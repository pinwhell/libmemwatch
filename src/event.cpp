#include "memwatch/event.hpp"
#include "memwatch/thr.hpp"
#include "memwatch/remote.hpp"
#include "memwatch/watch.hpp"
#include "memwatch/internal.hpp"
#include "memwatch/api.hpp"

#include <cerrno>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

/* Signals that must never be re-injected by a tracer: re-injecting them would
 * either loop forever or change the meaning of the stop. */
bool sig_is_never_delivered(int sig) {
  return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU ||
         (sig & 0x80) != 0;
}

const char *ev_name(ev_t e) {
  switch (e) {
    case ev_t::none:        return "none";
    case ev_t::target_exit: return "target_exit";
    case ev_t::thread_exit: return "thread_exit";
    case ev_t::clone:       return "clone";
    case ev_t::fault:       return "fault";
    case ev_t::step_trap:   return "step_trap";
    case ev_t::stray_trap:  return "stray_trap";
    case ev_t::group_stop:  return "group_stop";
    case ev_t::signal:      return "signal";
    case ev_t::unknown:     return "unknown";
  }
  return "?";
}

const char *state_name(mw_state_t s) {
  switch (s) {
    case mw_state_t::idle:      return "idle";
    case mw_state_t::entering:  return "entering";
    case mw_state_t::critical:  return "critical";
    case mw_state_t::rcall:     return "rcall";
    case mw_state_t::sstep:     return "sstep";
    case mw_state_t::rearming:  return "rearming";
    case mw_state_t::detaching: return "detaching";
  }
  return "?";
}

} /* namespace */

/* ------------------------------------------------------------- classifier */

ev_t mw_ev_classify(mw_ctx_t *ctx, pid_t tid, int status, int *out_sig,
                    pid_t *out_newtid) {
  *out_sig = 0;
  *out_newtid = 0;

  if (WIFEXITED(status) || WIFSIGNALED(status)) {
    return (tid == ctx->pid) ? ev_t::target_exit : ev_t::thread_exit;
  }
  if (!WIFSTOPPED(status)) {
    return ev_t::unknown;
  }

  {
    unsigned event = static_cast<unsigned>(status) >> 16;
    int sig = WSTOPSIG(status);
    *out_sig = sig;

    switch (event) {
      case PTRACE_EVENT_CLONE:
      case PTRACE_EVENT_FORK:
      case PTRACE_EVENT_VFORK: {
        unsigned long msg = 0;
        if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &msg) == -1) {
          mw_log_errno("PTRACE_GETEVENTMSG on clone event");
          return ev_t::unknown;
        }
        *out_newtid = static_cast<pid_t>(msg);
        return ev_t::clone;
      }
      case PTRACE_EVENT_EXIT:
        return ev_t::thread_exit;
      case PTRACE_EVENT_EXEC:
      case PTRACE_EVENT_SECCOMP:
      case PTRACE_EVENT_STOP:
        return ev_t::group_stop;
      case 0:
        break;
      default:
        return ev_t::unknown;
    }

    if (sig == SIGTRAP) {
      if (!ctx->in_rcall && ctx->st == mw_state_t::sstep &&
          ctx->fault_tid == tid) {
        return ev_t::step_trap;
      }
      return ev_t::stray_trap;
    }
    if (sig == SIGSEGV || sig == SIGBUS) {
      return ev_t::fault;
    }
    if (sig_is_never_delivered(sig)) {
      return ev_t::group_stop;
    }
    return ev_t::signal;
  }
}

/* ------------------------------------------------------------------ applier */

rc_t mw_ev_apply(mw_ctx_t *ctx, ev_t ev, pid_t tid, int status,
                 bool resume_now) {
  int sig = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
  thr_t *t = mw_thr_find(ctx, tid);

  if (t == nullptr && ctx->pid != 0 && ev != ev_t::target_exit) {
    /* A new thread can report its very first stop before the clone event of
     * its parent has been reaped (waitpid(-1) hands out whichever stop landed
     * first).  Recover the thread from /proc so the event is never dropped and
     * the stop is never mistaken for "thread not found". */
    (void)mw_thr_sync(ctx);
    t = mw_thr_find(ctx, tid);
  }

  switch (ev) {
    case ev_t::target_exit:
      ++ctx->stats.events;
      mw_log("target process %d exited (status=0x%x)", ctx->pid, status);
      /* memwatch owns the waitpid that observed the death, so the wait status
       * is recorded here: it is the only way the caller can still learn how the
       * target ended. */
      ctx->target_exited = true;
      ctx->exit_status = status;
      for (size_t i = 0; i < ctx->thrs.size(); ++i) {
        ctx->thrs[i].alive = false;
        ctx->thrs[i].running = false;
      }
      return rc_t::err_gone;

    case ev_t::thread_exit:
      ++ctx->stats.events;
      mw_thr_note_stopped(ctx, tid);
      mw_thr_mark_dead(ctx, tid);
      if (resume_now && t != nullptr) {
        (void)mw_thr_resume_one(ctx, tid, 0, false, nullptr);
      }
      return rc_t::ok;

    case ev_t::clone: {
      unsigned long msg = 0;
      ++ctx->stats.events;
      if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &msg) == -1) {
        mw_log_errno("PTRACE_GETEVENTMSG");
        return rc_t::err_unexpected;
      }
      if (mw_thr_add_cloned(ctx, static_cast<pid_t>(msg)) != rc_t::ok) {
        return rc_t::err_proc;
      }
      mw_thr_note_stopped(ctx, tid);
      /* The reporting thread must continue, but only when we are allowed to
       * let target code run again. */
      if (resume_now) {
        return mw_thr_resume_one(ctx, tid, 0, false, nullptr);
      }
      return rc_t::ok;
    }

    case ev_t::fault:
      ++ctx->stats.events;
      mw_thr_note_stopped(ctx, tid);
      if (!resume_now) {
        /* Collected while we were already in a critical section: the faulting
         * instruction is still pending, so suppress the signal and let it
         * re-fault against the current protections once we resume. */
        if (t != nullptr) {
          t->deliver_sig = 0;
          t->has_pend_si = false;
        }
        ++ctx->stats.signals_suppressed;
        return rc_t::ok;
      }
      return mw_ev_handle_fault(ctx, tid, sig);

    case ev_t::step_trap:
      /* Only ever reaped through the dedicated wait inside the fault
       * sequence; reaching it here means the state machine lost track. */
      ++ctx->stats.events;
      mw_thr_note_stopped(ctx, tid);
      mw_log("stray single-step trap reaped by the event loop");
      return rc_t::err_unexpected;

    case ev_t::stray_trap:
      ++ctx->stats.events;
      mw_thr_note_stopped(ctx, tid);
      if (ctx->st == mw_state_t::rcall || ctx->st == mw_state_t::sstep) {
        mw_log("stray SIGTRAP inside controlled scope (state=%s)",
               state_name(ctx->st));
        return rc_t::err_unexpected;
      }
      if (resume_now) {
        ++ctx->stats.signals_forwarded;
        return mw_thr_resume_one(ctx, tid, SIGTRAP, false, nullptr);
      }
      if (t != nullptr) {
        t->deliver_sig = 0;
        t->has_pend_si = false;
      }
      ++ctx->stats.signals_suppressed;
      return rc_t::ok;

    case ev_t::group_stop:
    case ev_t::signal:
    case ev_t::unknown: {
      ++ctx->stats.events;
      mw_thr_note_stopped(ctx, tid);
      if (t != nullptr && t->init_stop) {
        /* The very first stop of a freshly cloned tracee: consume it silently
         * so the new thread can be managed by the global stop discipline. */
        t->init_stop = false;
        t->deliver_sig = 0;
        t->has_pend_si = false;
        ++ctx->stats.signals_suppressed;
        if (resume_now) {
          /* It has to be started now: the thread that cloned it is already
           * running and will wait for it forever otherwise.  Safe because the
           * state machine is idle here, so nothing needs a zero-run state. */
          return mw_thr_resume_one(ctx, tid, 0, false, nullptr);
        }
        return rc_t::ok;
      }
      {
        int deliver = 0;
        if (ev == ev_t::signal && !sig_is_never_delivered(sig)) {
          deliver = sig;
        }
        if (resume_now) {
          if (deliver != 0) {
            ++ctx->stats.signals_forwarded;
          } else {
            ++ctx->stats.signals_suppressed;
          }
          return mw_thr_resume_one(ctx, tid, deliver, false, nullptr);
        }
        if (t != nullptr) {
          /* Park the signal: it is injected when we leave the critical
           * section, or suppressed so a faulting instruction re-faults. */
          t->deliver_sig = (ev == ev_t::fault) ? 0 : deliver;
          t->has_pend_si = false;
          if (t->deliver_sig != 0) {
            ++ctx->stats.signals_forwarded;
          } else {
            ++ctx->stats.signals_suppressed;
          }
        }
        return rc_t::ok;
      }
    }

    case ev_t::none:
      return rc_t::ok;
  }
  return rc_t::ok;
}

bool mw_ev_reap_nonblock(mw_ctx_t *ctx, pid_t *tid, int *status) {
  pid_t w;
  (void)ctx;
  errno = 0;
  w = waitpid(-1, status, MW_WAIT_NOWAIT);
  if (w > 0) {
    *tid = w;
    return true;
  }
  return false;
}

rc_t mw_ev_drain(mw_ctx_t *ctx) {
  pid_t tid = 0;
  int status = 0;
  int sig = 0;
  pid_t newtid = 0;
  unsigned guard = 0;
  while (mw_ev_reap_nonblock(ctx, &tid, &status)) {
    rc_t r;
    ev_t ev = mw_ev_classify(ctx, tid, status, &sig, &newtid);
    r = mw_ev_apply(ctx, ev, tid, status, false);
    if (r == rc_t::err_gone) {
      return r;
    }
    if (r != rc_t::ok) {
      return r;
    }
    if (++guard > 1000000U) {
      return rc_t::err_timeout;
    }
  }
  return rc_t::ok;
}

/* ------------------------------------------------------------ fault sequence */

namespace {

/* Hand the original signal back to the target and leave the critical section. */
rc_t forward_and_resume(mw_ctx_t *ctx, pid_t tid, int sig,
                        const siginfo_t *si) {
  thr_t *t = mw_thr_find_alive(ctx, tid);
  rc_t r;
  if (t != nullptr) {
    t->deliver_sig = sig;
    t->has_pend_si = (si != nullptr && sig != 0);
    if (t->has_pend_si) {
      t->pend_si = *si;
    }
    ++ctx->stats.faults_forwarded;
    mw_log("forwarding signal %d to thread %d untouched", sig, tid);
  }
  mw_fault_clear(ctx);
  r = mw_thr_resume_all(ctx, true);
  ctx->st = mw_state_t::idle;
  (void)mw_inv_check(ctx, "forward_and_resume");
  return r;
}

rc_t abort_and_resume(mw_ctx_t *ctx, rc_t err) {
  rc_t r;
  mw_fault_clear(ctx);
  ctx->st = mw_state_t::critical;
  (void)mw_inv_check(ctx, "abort_and_resume");
  r = mw_thr_resume_all(ctx, true);
  ctx->st = mw_state_t::idle;
  (void)mw_inv_check(ctx, "abort_and_resume/idle");
  if (err != rc_t::ok) {
    return err;
  }
  return (r != rc_t::ok) ? r : rc_t::ok;
}

} /* namespace */

rc_t mw_ev_handle_fault(mw_ctx_t *ctx, pid_t tid, int sig) {
  siginfo_t si;
  siginfo_t si2;
  mw_watch_t *w = nullptr;
  rc_t r;

  if (ctx->st != mw_state_t::idle) {
    mw_log("fault ignored: state is %s, not idle", state_name(ctx->st));
    return rc_t::err_state;
  }
  if (ctx->poisoned) {
    return rc_t::err_poisoned;
  }

  (void)memset(&si, 0, sizeof si);
  (void)memset(&si2, 0, sizeof si2);
  if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &si) == -1) {
    mw_log_errno("PTRACE_GETSIGINFO(%d)", tid);
    return abort_and_resume(ctx, rc_t::err_ptrace);
  }

  /* ---- entering: record the candidate, then force the global stop ---- */
  ctx->fault_tid = tid;
  ctx->fault_addr = reinterpret_cast<uintptr_t>(si.si_addr);
  ctx->have_fault = false;
  ctx->fault_watch = nullptr;
  ctx->st = mw_state_t::entering;
  r = mw_thr_stop_all(ctx);
  if (r != rc_t::ok) {
    mw_fault_clear(ctx);
    ctx->st = mw_state_t::idle;
    (void)mw_thr_resume_all(ctx, true);
    return (r == rc_t::err_gone) ? r : rc_t::ok;
  }
  ctx->st = mw_state_t::critical;
  r = mw_inv_check(ctx, "fault/after_global_stop");
  if (r != rc_t::ok) {
    return abort_and_resume(ctx, r);
  }

  /* ---- double validation, now with every target thread stopped ---- */
  if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &si2) == -1) {
    mw_log_errno("PTRACE_GETSIGINFO after global stop");
    return forward_and_resume(ctx, tid, sig, &si);
  }
  ctx->fault_addr = reinterpret_cast<uintptr_t>(si2.si_addr);

  if (si2.si_code != SEGV_MAPERR && si2.si_code != SEGV_ACCERR) {
    mw_log("fault si_code=%d is never claimed by memwatch", si2.si_code);
    return forward_and_resume(ctx, tid, sig, &si2);
  }
  w = mw_watch_covering_armed(ctx, ctx->fault_addr);
  if (w == nullptr) {
    mw_log("unrelated %s at 0x%lx -> forwarding", sig == SIGBUS ? "SIGBUS"
                                                                  : "SIGSEGV",
           static_cast<unsigned long>(ctx->fault_addr));
    return forward_and_resume(ctx, tid, sig, &si2);
  }
  {
    thr_t *t = mw_thr_find_alive(ctx, tid);
    if (t == nullptr || t->running) {
      mw_log("faulting thread %d is no longer held", tid);
      return forward_and_resume(ctx, tid, sig, &si2);
    }
  }

  ctx->have_fault = true;
  ctx->fault_watch = w;
  ctx->fault_tid = tid;
  ++ctx->stats.faults_owned;

  /* ---- user callback: zero target threads are executing here ---- */
  {
    mw_fault_t f;
    user_regs_struct regs;
    (void)memset(&f, 0, sizeof f);
    (void)memset(&regs, 0, sizeof regs);
    f.tid = tid;
    f.addr = ctx->fault_addr;
    f.p = pg_align_down(ctx->fault_addr, ctx->page_size);
    f.si_code = si2.si_code;
    f.watch = w;
    f.owned = true;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == 0) {
      f.rip = regs.rip;
    }
    mw_log("owned fault tid=%d addr=0x%lx -> callback", tid,
           static_cast<unsigned long>(f.addr));
    r = w->cb(ctx, w, &f);
    if (r != rc_t::ok) {
      mw_log("watch callback returned %s", mw_strerror(r));
    }
  }

  /* ---- ownership release before removing PROT_NONE ---- */
  r = mw_watch_disarm(ctx, w);
  if (r != rc_t::ok) {
    mw_poison(ctx, r, "fault/disarm");
    return abort_and_resume(ctx, r);
  }

  /* ---- single step exactly the faulting thread ---- */
  {
    user_regs_struct pre;
    int status = 0;
    (void)memset(&pre, 0, sizeof pre);
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &pre) == -1) {
      mw_log_errno("PTRACE_GETREGS before single step");
      (void)mw_watch_arm(ctx, w);
      return abort_and_resume(ctx, rc_t::err_ptrace);
    }
    ctx->st = mw_state_t::sstep;
    if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) == -1) {
      mw_log_errno("PTRACE_SINGLESTEP(%d)", tid);
      ctx->st = mw_state_t::rearming;
      (void)mw_watch_arm(ctx, w);
      return abort_and_resume(ctx, rc_t::err_ptrace);
    }
    mw_thr_note_running(ctx, tid);
    r = mw_inv_check(ctx, "sstep/armed");
    {
      rc_t inv_bad = r;
      /* Even when the state machine tripped, the single step is already in
       * flight: its trap must be reaped before anything else touches the
       * target, otherwise the tracer would lose the stop it is waiting for. */
      r = mw_thr_wait(ctx, tid, &status);
      mw_thr_note_stopped(ctx, tid);
      ctx->st = mw_state_t::rearming;
      if (inv_bad != rc_t::ok) {
        (void)mw_watch_arm(ctx, w);
        return abort_and_resume(ctx, inv_bad);
      }
    }
    if (r != rc_t::ok) {
      mw_log("faulting thread %d vanished during single step", tid);
      (void)mw_watch_arm(ctx, w);
      return abort_and_resume(ctx, (r == rc_t::err_gone) ? r
                                                        : rc_t::err_ptrace);
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
        (static_cast<unsigned>(status) >> 16) != 0) {
      mw_log("single step produced status=0x%x (expected SIGTRAP)", status);
      (void)mw_watch_arm(ctx, w);
      /* Give the unexpected signal back to the target instead of eating it. */
      {
        thr_t *t = mw_thr_find_alive(ctx, tid);
        if (t != nullptr) {
          int s2 = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
          t->deliver_sig = (s2 == SIGSEGV || s2 == SIGBUS || s2 == SIGTRAP ||
                            s2 == SIGILL || s2 == SIGFPE || s2 == SIGABRT)
                               ? s2
                               : 0;
          t->has_pend_si = false;
        }
      }
      return abort_and_resume(ctx, rc_t::err_unexpected);
    }
    ++ctx->stats.ssteps;
    {
      user_regs_struct post;
      (void)memset(&post, 0, sizeof post);
      if (ptrace(PTRACE_GETREGS, tid, nullptr, &post) == 0) {
        if (post.rip == pre.rip) {
          mw_log("single step did not advance RIP (0x%llx)",
                 static_cast<unsigned long long>(post.rip));
        }
      } else {
        mw_log_errno("PTRACE_GETREGS after single step");
      }
    }
  }
  r = mw_inv_check(ctx, "rearming/after_step");
  if (r != rc_t::ok) {
    (void)mw_watch_arm(ctx, w);
    return abort_and_resume(ctx, r);
  }

  /* ---- re-arm: PROT_NONE first, then armed = true ---- */
  r = mw_watch_arm(ctx, w);
  if (r != rc_t::ok) {
    mw_poison(ctx, r, "fault/rearm");
    return abort_and_resume(ctx, r);
  }

  mw_fault_clear(ctx);
  ctx->st = mw_state_t::critical;
  r = mw_inv_check(ctx, "fault/before_resume");
  if (r != rc_t::ok) {
    return abort_and_resume(ctx, r);
  }
  r = mw_thr_resume_all(ctx, true);
  ctx->st = mw_state_t::idle;
  (void)mw_inv_check(ctx, "fault/after_resume");
  return r;
}

/* ---------------------------------------------------------------- public API */

rc_t mw_poll(mw_ctx_t *ctx, int timeout_ms) {
  pid_t tid = 0;
  int status = 0;
  int sig = 0;
  pid_t newtid = 0;
  rc_t r;
  ev_t ev;

  if (ctx == nullptr) {
    return rc_t::err_invalid;
  }
  if (!ctx->attached) {
    return rc_t::err_state;
  }
  if (ctx->poisoned) {
    return rc_t::err_poisoned;
  }
  if (ctx->st != mw_state_t::idle) {
    mw_log("mw_poll refused in state %s", state_name(ctx->st));
    return rc_t::err_state;
  }
  ++ctx->stats.polls;

  r = mw_thr_wait_any(ctx, &tid, &status, timeout_ms < 0, timeout_ms);
  if (r != rc_t::ok) {
    return r;
  }
  ev = mw_ev_classify(ctx, tid, status, &sig, &newtid);
  if (ev == ev_t::none) {
    return rc_t::ok;
  }
  mw_log("event tid=%d %s sig=%d state=%s", tid, ev_name(ev), sig,
         state_name(ctx->st));
  return mw_ev_apply(ctx, ev, tid, status, true);
}

rc_t mw_run(mw_ctx_t *ctx) {
  for (;;) {
    rc_t r = mw_poll(ctx, -1);
    if (r == rc_t::ok || r == rc_t::err_timeout) {
      continue;
    }
    return r;
  }
}

rc_t mw_get_fault(mw_ctx_t *ctx, mw_fault_t *out) {
  if (ctx == nullptr || out == nullptr) {
    return rc_t::err_invalid;
  }
  if (!ctx->have_fault || ctx->fault_watch == nullptr) {
    return rc_t::err_not_found;
  }
  (void)memset(out, 0, sizeof *out);
  out->tid = ctx->fault_tid;
  out->addr = ctx->fault_addr;
  out->p = pg_align_down(ctx->fault_addr, ctx->page_size);
  out->watch = ctx->fault_watch;
  out->owned = true;
  return rc_t::ok;
}
