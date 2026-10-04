#include "memwatch/thr.hpp"
#include "memwatch/event.hpp"
#include "memwatch/internal.hpp"
#include "memwatch/api.hpp"

#include <cerrno>
#include <cstring>
#include <ctime>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------- lookup/counts */

thr_t *mw_thr_find(mw_ctx_t *ctx, pid_t tid) {
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (ctx->thrs[i].tid == tid) {
      return &ctx->thrs[i];
    }
  }
  return nullptr;
}

thr_t *mw_thr_find_alive(mw_ctx_t *ctx, pid_t tid) {
  thr_t *t = mw_thr_find(ctx, tid);
  return (t != nullptr && t->alive) ? t : nullptr;
}

size_t mw_thr_count_running(const mw_ctx_t *ctx) {
  size_t n = 0;
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (ctx->thrs[i].alive && ctx->thrs[i].running) {
      ++n;
    }
  }
  return n;
}

size_t mw_thr_count_alive(const mw_ctx_t *ctx) {
  size_t n = 0;
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (ctx->thrs[i].alive) {
      ++n;
    }
  }
  return n;
}

size_t mw_thr_count_stopped(const mw_ctx_t *ctx) {
  size_t n = 0;
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (ctx->thrs[i].alive && !ctx->thrs[i].running) {
      ++n;
    }
  }
  return n;
}

void mw_thr_note_running(mw_ctx_t *ctx, pid_t tid) {
  thr_t *t = mw_thr_find_alive(ctx, tid);
  if (t != nullptr) {
    t->running = true;
    t->init_stop = false;
  }
}

void mw_thr_note_stopped(mw_ctx_t *ctx, pid_t tid) {
  thr_t *t = mw_thr_find_alive(ctx, tid);
  if (t != nullptr) {
    t->running = false;
  }
}

void mw_thr_mark_dead(mw_ctx_t *ctx, pid_t tid) {
  thr_t *t = mw_thr_find(ctx, tid);
  if (t != nullptr) {
    t->alive = false;
    t->running = false;
    t->deliver_sig = 0;
    t->has_pend_si = false;
    ++ctx->stats.thread_exits;
  }
}

/* ---------------------------------------------------------------- discovery */

rc_t mw_thr_add_cloned(mw_ctx_t *ctx, pid_t tid) {
  if (tid <= 0) {
    return rc_t::err_invalid;
  }
  if (mw_thr_find(ctx, tid) != nullptr) {
    return rc_t::ok;
  }
  thr_t t;
  (void)memset(&t, 0, sizeof t);
  t.tid = tid;
  t.alive = true;
  /* A freshly attached tracee cannot execute user code before the tracer
   * continues it, and its initial stop has not been reaped yet. */
  t.running = false;
  t.init_stop = true;
  t.deliver_sig = 0;
  t.has_pend_si = false;
  ctx->thrs.push_back(t);
  ++ctx->stats.clone_events;
  mw_log("thread %d registered (clone event)", tid);
  return rc_t::ok;
}

rc_t mw_thr_sync_seized(mw_ctx_t *ctx) {
  std::vector<pid_t> tasks;
  rc_t r = mw_list_tasks(ctx->pid, &tasks);
  if (r != rc_t::ok) {
    return r;
  }
  for (size_t i = 0; i < tasks.size(); ++i) {
    thr_t t;
    if (mw_thr_find(ctx, tasks[i]) != nullptr) {
      continue;
    }
    (void)memset(&t, 0, sizeof t);
    t.tid = tasks[i];
    t.alive = true;
    /* PTRACE_SEIZE leaves the tracee running: these threads are executing user
     * code right now and the first global stop has to interrupt all of them. */
    t.running = true;
    t.init_stop = false;
    t.deliver_sig = 0;
    t.has_pend_si = false;
    ctx->thrs.push_back(t);
    mw_log("thread %d registered (seized baseline, running)", tasks[i]);
  }
  if (ctx->thrs.empty()) {
    return rc_t::err_gone;
  }
  return rc_t::ok;
}

rc_t mw_thr_sync(mw_ctx_t *ctx) {
  std::vector<pid_t> tasks;
  rc_t r = mw_list_tasks(ctx->pid, &tasks);
  if (r != rc_t::ok) {
    return r;
  }
  for (size_t i = 0; i < tasks.size(); ++i) {
    if (mw_thr_find(ctx, tasks[i]) == nullptr) {
      /* Recovered without a PTRACE_EVENT_CLONE: ptrace attaches it
       * automatically and it starts stopped, so running stays false. */
      r = mw_thr_add_cloned(ctx, tasks[i]);
      if (r != rc_t::ok) {
        return r;
      }
    }
  }
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (!ctx->thrs[i].alive) {
      continue;
    }
    if (!mw_task_alive(ctx->pid, ctx->thrs[i].tid)) {
      mw_thr_mark_dead(ctx, ctx->thrs[i].tid);
    }
  }
  /* Compact the dead entries out so that borrow selection never sees them. */
  std::vector<thr_t> live;
  live.reserve(ctx->thrs.size());
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (ctx->thrs[i].alive) {
      live.push_back(ctx->thrs[i]);
    }
  }
  ctx->thrs.swap(live);
  if (ctx->thrs.empty()) {
    return rc_t::err_gone;
  }
  return rc_t::ok;
}

/* --------------------------------------------------------------------- wait */

rc_t mw_thr_wait(mw_ctx_t *ctx, pid_t tid, int *status) {
  pid_t w;
  (void)ctx;
  for (;;) {
    errno = 0;
    w = waitpid(tid, status, MW_WAIT_FLAGS);
    if (w == tid) {
      return rc_t::ok;
    }
    if (w == -1 && errno == EINTR) {
      continue;
    }
    if (w == -1 && errno == ECHILD) {
      return rc_t::err_not_found;
    }
    if (w == -1) {
      mw_log_errno("waitpid(%d)", tid);
      return rc_t::err_ptrace;
    }
    return rc_t::err_unexpected; /* waitpid cannot return another pid here */
  }
}

rc_t mw_thr_wait_any(mw_ctx_t *ctx, pid_t *tid, int *status, bool blocking,
                     int timeout_ms) {
  struct timespec deadline;
  bool have_deadline = false;
  (void)ctx;
  if (!blocking && timeout_ms >= 0) {
    (void)clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += static_cast<long>(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
      deadline.tv_nsec -= 1000000000L;
      deadline.tv_sec += 1;
    }
    have_deadline = true;
  }
  for (;;) {
    pid_t w;
    errno = 0;
    w = waitpid(-1, status, blocking ? MW_WAIT_FLAGS : MW_WAIT_NOWAIT);
    if (w > 0) {
      *tid = w;
      return rc_t::ok;
    }
    if (w == -1) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == ECHILD) {
        return rc_t::err_gone;
      }
      mw_log_errno("waitpid(-1)");
      return rc_t::err_ptrace;
    }
    /* w == 0: nothing pending. */
    if (!have_deadline) {
      return rc_t::err_timeout;
    }
    {
      struct timespec now;
      (void)clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec > deadline.tv_sec ||
          (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
        return rc_t::err_timeout;
      }
    }
    {
      struct timespec nap;
      nap.tv_sec = 0;
      nap.tv_nsec = 200000L; /* 200us */
      (void)nanosleep(&nap, nullptr);
    }
  }
}

/* ---------------------------------------------------------------- global stop */

static rc_t thr_interrupt(pid_t tid) {
  for (;;) {
    if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == -1) {
      if (errno == ESRCH) {
        return rc_t::err_not_found;
      }
      if (errno == EINTR) {
        continue;
      }
      return rc_t::err_ptrace;
    }
    return rc_t::ok;
  }
}

static void nap_short(void) {
  struct timespec nap;
  nap.tv_sec = 0;
  nap.tv_nsec = 200000L; /* 200us */
  (void)nanosleep(&nap, nullptr);
}

static bool past_deadline(const struct timespec *deadline) {
  struct timespec now;
  (void)clock_gettime(CLOCK_MONOTONIC, &now);
  if (now.tv_sec != deadline->tv_sec) {
    return now.tv_sec > deadline->tv_sec;
  }
  return now.tv_nsec >= deadline->tv_nsec;
}

rc_t mw_thr_stop_all(mw_ctx_t *ctx) {
  struct timespec deadline;

  if (ctx->st == mw_state_t::idle || ctx->st == mw_state_t::entering ||
      ctx->st == mw_state_t::critical || ctx->st == mw_state_t::rearming ||
      ctx->st == mw_state_t::detaching) {
    /* fine: entering a stop from any zero-run state */
  } else {
    return rc_t::err_state;
  }

  (void)clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_nsec += 50L * 1000000L; /* 50ms to publish the stops we asked for */
  if (deadline.tv_nsec >= 1000000000L) {
    deadline.tv_nsec -= 1000000000L;
    deadline.tv_sec += 1;
  }

  for (unsigned round = 0; round < MW_STOP_MAX_ROUNDS; ++round) {
    bool any_running = false;
    rc_t r;

    r = mw_thr_sync(ctx);
    if (r != rc_t::ok) {
      return r;
    }

    for (size_t i = 0; i < ctx->thrs.size(); ++i) {
      thr_t *t = &ctx->thrs[i];
      if (!t->alive || !t->running) {
        continue;
      }
      r = thr_interrupt(t->tid);
      if (r == rc_t::err_not_found) {
        mw_thr_mark_dead(ctx, t->tid);
        continue;
      }
      if (r != rc_t::ok) {
        return r;
      }
      any_running = true;
    }

    /* Reap everything that became available, including events from threads we
     * did not interrupt (a second thread may have faulted on a watched page
     * while we were idle).  Those threads are left stopped: their faulting
     * instruction will re-fault after the global resume.
     *
     * The loop below is what makes "every thread is stopped" a fact rather
     * than a hope: a thread is only stopped once its stop has actually been
     * reaped, so the interrupts are waited for (briefly) instead of being
     * fired and forgotten. */
    for (;;) {
      r = mw_ev_drain(ctx);
      if (r == rc_t::err_gone) {
        return r;
      }
      if (r != rc_t::ok) {
        return r;
      }
      if (mw_thr_count_running(ctx) == 0) {
        break;
      }
      if (past_deadline(&deadline)) {
        break;
      }
      nap_short();
    }

    if (mw_thr_count_running(ctx) != 0) {
      continue; /* retry: another round interrupts whoever is still moving */
    }
    if (!any_running) {
      break;
    }
  }

  if (mw_thr_count_running(ctx) != 0) {
    mw_log("global stop did not converge (%zu threads still running)",
           mw_thr_count_running(ctx));
    return rc_t::err_timeout;
  }
  return mw_inv_check(ctx, "stop_all");
}

rc_t mw_thr_ensure_all_stopped(mw_ctx_t *ctx) {
  rc_t r;
  if (mw_thr_count_running(ctx) == 0) {
    return mw_inv_check(ctx, "ensure_all_stopped/fast");
  }
  r = mw_thr_stop_all(ctx);
  if (r != rc_t::ok) {
    return r;
  }
  return mw_inv_check(ctx, "ensure_all_stopped");
}

/* -------------------------------------------------------------- global resume */

rc_t mw_thr_resume_one(mw_ctx_t *ctx, pid_t tid, int sig, bool has_si,
                       const siginfo_t *si) {
  thr_t *t = mw_thr_find_alive(ctx, tid);
  if (t == nullptr) {
    return rc_t::err_not_found;
  }
  if (t->running) {
    return rc_t::ok; /* already running: nothing to do */
  }
  if (has_si && sig != 0) {
    if (ptrace(PTRACE_SETSIGINFO, tid, nullptr,
               const_cast<siginfo_t *>(si)) == -1) {
      if (errno != EINVAL && errno != ESRCH) {
        mw_log_errno("PTRACE_SETSIGINFO(%d)", tid);
      }
    }
  }
  if (ptrace(PTRACE_CONT, tid, nullptr,
             reinterpret_cast<void *>(static_cast<uintptr_t>(sig))) == -1) {
    if (errno == ESRCH) {
      mw_thr_mark_dead(ctx, tid);
      return rc_t::err_not_found;
    }
    if (errno == EINTR) {
      return rc_t::ok; /* the continue was accepted */
    }
    mw_log_errno("PTRACE_CONT(%d)", tid);
    return rc_t::err_ptrace;
  }
  t->running = true;
  t->init_stop = false;
  t->deliver_sig = 0;
  t->has_pend_si = false;
  return rc_t::ok;
}

rc_t mw_thr_resume_all(mw_ctx_t *ctx, bool deliver) {
  rc_t first_err = rc_t::ok;
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    thr_t *t = &ctx->thrs[i];
    rc_t r;
    if (!t->alive || t->running) {
      continue;
    }
    r = mw_thr_resume_one(ctx, t->tid, deliver ? t->deliver_sig : 0,
                          deliver && t->has_pend_si, &t->pend_si);
    if (r == rc_t::err_not_found) {
      /* The thread vanished between the liveness check and PTRACE_CONT.  That
       * is bookkeeping, not a failure of the global resume. */
      continue;
    }
    if (r != rc_t::ok && first_err == rc_t::ok) {
      first_err = r;
    }
  }
  if (mw_thr_count_running(ctx) == 0 && mw_thr_count_alive(ctx) > 0 &&
      first_err == rc_t::ok) {
    first_err = rc_t::err_ptrace;
  }
  return first_err;
}
