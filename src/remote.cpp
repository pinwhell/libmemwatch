#include "memwatch/remote.hpp"
#include "memwatch/thr.hpp"
#include "memwatch/internal.hpp"
#include "memwatch/api.hpp"

#include <cerrno>
#include <cstring>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

namespace {

/* ---------------------------------------------------------------- encoding */

struct stub_t {
  unsigned char b[128];
  size_t        n;
  unsigned char pristine[128]; /* page content before we wrote anything */
  size_t        pristine_n;
};

inline void emit_movabs(unsigned char *out, unsigned char rex, unsigned char op,
                        unsigned long long v) {
  out[0] = rex;
  out[1] = op;
  (void)memcpy(&out[2], &v, sizeof v);
}

void build_stub(stub_t *s, unsigned long nr, unsigned long a0, unsigned long a1,
                unsigned long a2, unsigned long a3, unsigned long a4,
                unsigned long a5) {
  s->n = 0;
  emit_movabs(&s->b[s->n], 0x48, 0xB8, nr);  s->n += 10;
  emit_movabs(&s->b[s->n], 0x48, 0xBF, a0);  s->n += 10;
  emit_movabs(&s->b[s->n], 0x48, 0xBE, a1);  s->n += 10;
  emit_movabs(&s->b[s->n], 0x48, 0xBA, a2);  s->n += 10;
  emit_movabs(&s->b[s->n], 0x49, 0xBA, a3);  s->n += 10;
  emit_movabs(&s->b[s->n], 0x49, 0xB8, a4);  s->n += 10;
  emit_movabs(&s->b[s->n], 0x49, 0xB9, a5);  s->n += 10;
  s->b[s->n++] = 0x0F;
  s->b[s->n++] = 0x05; /* syscall */
  s->b[s->n++] = 0xCC; /* int3 -> ptrace SIGTRAP, the controlled exit */
}

bool state_allows_remote(mw_state_t s) {
  return s == mw_state_t::critical || s == mw_state_t::rearming ||
         s == mw_state_t::detaching || s == mw_state_t::entering;
}

/* A group-stop can still be in flight when a borrow begins: the global stop
 * fires PTRACE_INTERRUPT at every running thread, and the kernel may publish
 * one of those stops just after that round's drain observed nothing.  Such a
 * stop is not a signal for the target and not an event for the callback, so the
 * borrow must not treat it as an anomaly -- it continues the thread and waits
 * for the trap it actually asked for.  Anything that is not a group-stop is a
 * genuine anomaly and still aborts the call. */
bool is_group_stop(int status) {
  if (!WIFSTOPPED(status)) {
    return false;
  }
  unsigned event = static_cast<unsigned>(status >> 16) & 0xffffU;
  int sig = WSTOPSIG(status);
  return (event == static_cast<unsigned>(PTRACE_EVENT_STOP) && sig == SIGTRAP) ||
         (event == 0 && sig == SIGSTOP);
}

bool is_controlled_trap(int status) {
  return WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
         (status >> 16) == 0;
}

/* Pick exactly one alive, stopped thread.  A running thread is never eligible:
 * that is what keeps "exactly one target thread executes" true by selection
 * rather than by hope. */
rc_t pick_borrow(mw_ctx_t *ctx, pid_t *out) {
  pid_t prefer = ctx->fault_tid;
  if (prefer != 0) {
    thr_t *t = mw_thr_find_alive(ctx, prefer);
    if (t != nullptr && !t->running) {
      *out = prefer;
      return rc_t::ok;
    }
  }
  if (ctx->borrow_tid != 0) {
    thr_t *t = mw_thr_find_alive(ctx, ctx->borrow_tid);
    if (t != nullptr && !t->running) {
      *out = ctx->borrow_tid;
      return rc_t::ok;
    }
  }
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (ctx->thrs[i].alive && !ctx->thrs[i].running) {
      *out = ctx->thrs[i].tid;
      return rc_t::ok;
    }
  }
  return rc_t::err_nothread;
}

/* Undo everything a borrow touched and leave the machine coherent.
 *
 * The borrowed thread MUST be left stopped.  Every call site reaches unwind
 * either before the resume was ever issued, or after the resulting stop has
 * already been reaped, so "restore the registers and stay stopped" is the only
 * answer that keeps the state machine's zero-run states true.  Resuming here
 * would let a target thread run while other threads believe it is stopped. */
void unwind(mw_ctx_t *ctx, pid_t tid, const user_regs_struct *snap,
            mw_state_t prev_state) {
  if (ptrace(PTRACE_SETREGS, tid, nullptr,
             const_cast<user_regs_struct *>(snap)) == -1) {
    if (errno == ESRCH) {
      mw_thr_mark_dead(ctx, tid);
    } else {
      mw_log_errno("remote call: restoring registers of %d", tid);
      mw_poison(ctx, rc_t::err_ptrace, "remote-unwind-setregs");
    }
  }
  ctx->in_rcall = false;
  ctx->borrow_tid = 0;
  ctx->st = prev_state;
  (void)mw_inv_check(ctx, "remote/unwind");
}

/* Remote syscall executed by single-stepping a bare `syscall` instruction that
 * already exists inside the target.  Writes nothing into the target memory, so
 * it is safe to use before a code cave exists. */
rc_t call_via_gadget(mw_ctx_t *ctx, uintptr_t gadget, unsigned long nr,
                     unsigned long a0, unsigned long a1, unsigned long a2,
                     unsigned long a3, unsigned long a4, unsigned long a5,
                     long *ret) {
  user_regs_struct snap;
  user_regs_struct run;
  pid_t tid = 0;
  int status = 0;
  rc_t r;
  mw_state_t prev = ctx->st;

  r = pick_borrow(ctx, &tid);
  if (r != rc_t::ok) {
    return r;
  }
  if (ptrace(PTRACE_GETREGS, tid, nullptr, &snap) == -1) {
    mw_log_errno("gadget call: PTRACE_GETREGS(%d)", tid);
    return rc_t::err_ptrace;
  }
  run = snap;
  run.rip = gadget;
  run.rax = static_cast<unsigned long long>(nr);
  run.rdi = static_cast<unsigned long long>(a0);
  run.rsi = static_cast<unsigned long long>(a1);
  run.rdx = static_cast<unsigned long long>(a2);
  run.r10 = static_cast<unsigned long long>(a3);
  run.r8 = static_cast<unsigned long long>(a4);
  run.r9 = static_cast<unsigned long long>(a5);
  run.orig_rax = static_cast<unsigned long long>(-1);

  if (ptrace(PTRACE_SETREGS, tid, nullptr, &run) == -1) {
    mw_log_errno("gadget call: PTRACE_SETREGS(%d)", tid);
    return rc_t::err_ptrace;
  }

  ctx->borrow_regs_snap = snap;
  ctx->in_rcall = true;
  ctx->borrow_tid = tid;
  ctx->st = mw_state_t::rcall;
  ++ctx->stats.remote_calls;

  if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) == -1) {
    mw_log_errno("gadget call: PTRACE_SINGLESTEP(%d)", tid);
    (void)unwind(ctx, tid, &snap, prev);
    return rc_t::err_ptrace;
  }
  mw_thr_note_running(ctx, tid);

  for (unsigned attempt = 0;; ++attempt) {
    r = mw_thr_wait(ctx, tid, &status);
    if (r != rc_t::ok) {
      mw_thr_mark_dead(ctx, tid);
      ctx->in_rcall = false;
      ctx->borrow_tid = 0;
      ctx->st = prev;
      return r;
    }
    mw_thr_note_stopped(ctx, tid);

    if (is_controlled_trap(status)) {
      break;
    }
    if (attempt < MW_BORROW_MAX_SPURIOUS_STOPS && is_group_stop(status)) {
      mw_log("gadget call: in-flight group stop status=0x%x, continuing",
             status);
      if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) == -1) {
        mw_log_errno("gadget call: PTRACE_SINGLESTEP after group stop(%d)", tid);
        unwind(ctx, tid, &snap, prev);
        return rc_t::err_ptrace;
      }
      mw_thr_note_running(ctx, tid);
      continue;
    }
    mw_log("gadget call: unexpected stop status=0x%x", status);
    unwind(ctx, tid, &snap, prev);
    return rc_t::err_unexpected;
  }
  if (ptrace(PTRACE_GETREGS, tid, nullptr, &run) == -1) {
    mw_log_errno("gadget call: PTRACE_GETREGS after step");
    unwind(ctx, tid, &snap, prev);
    return rc_t::err_ptrace;
  }
  if (ret != nullptr) {
    *ret = static_cast<long>(run.rax);
  }
  if (ptrace(PTRACE_SETREGS, tid, nullptr, &snap) == -1) {
    mw_log_errno("gadget call: PTRACE_SETREGS restore(%d)", tid);
    mw_poison(ctx, rc_t::err_ptrace, "gadget-restore");
    ctx->in_rcall = false;
    ctx->borrow_tid = 0;
    ctx->st = prev;
    return rc_t::err_ptrace;
  }
  ctx->in_rcall = false;
  ctx->borrow_tid = 0;
  ctx->st = prev;
  (void)mw_inv_check(ctx, "call_via_gadget");
  return rc_t::ok;
}

/* Remote syscall executed by writing a complete, architecture-correct stub into
 * memwatch's private code cave inside the target and running it with
 * PTRACE_CONT.  The expected stop is the SIGTRAP produced by the stub's int3. */
rc_t call_via_stub(mw_ctx_t *ctx, unsigned long nr, unsigned long a0,
                   unsigned long a1, unsigned long a2, unsigned long a3,
                   unsigned long a4, unsigned long a5, long *ret) {
  user_regs_struct snap;
  user_regs_struct run;
  stub_t s;
  pid_t tid = 0;
  int status = 0;
  rc_t r;
  mw_state_t prev = ctx->st;

  (void)memset(&s, 0, sizeof s);
  build_stub(&s, nr, a0, a1, a2, a3, a4, a5);
  s.pristine_n = s.n;
  if (mw_vm_read(ctx->pid, ctx->stub_page, s.pristine, s.n) !=
      static_cast<ssize_t>(s.n)) {
    mw_log("stub: cannot read code cave at 0x%lx", ctx->stub_page);
    return rc_t::err_stub_write;
  }

  r = pick_borrow(ctx, &tid);
  if (r != rc_t::ok) {
    return r;
  }
  if (ptrace(PTRACE_GETREGS, tid, nullptr, &snap) == -1) {
    mw_log_errno("remote call: PTRACE_GETREGS(%d)", tid);
    return rc_t::err_ptrace;
  }
  if (mw_vm_write(ctx->pid, ctx->stub_page, s.b, s.n) !=
      static_cast<ssize_t>(s.n)) {
    mw_log_errno("remote call: writing stub at 0x%lx", ctx->stub_page);
    return rc_t::err_stub_write;
  }
  run = snap;
  run.rip = ctx->stub_page;
  run.rax = static_cast<unsigned long long>(nr);
  run.rdi = static_cast<unsigned long long>(a0);
  run.rsi = static_cast<unsigned long long>(a1);
  run.rdx = static_cast<unsigned long long>(a2);
  run.r10 = static_cast<unsigned long long>(a3);
  run.r8 = static_cast<unsigned long long>(a4);
  run.r9 = static_cast<unsigned long long>(a5);
  run.orig_rax = static_cast<unsigned long long>(-1);
  if (ptrace(PTRACE_SETREGS, tid, nullptr, &run) == -1) {
    mw_log_errno("remote call: PTRACE_SETREGS(%d)", tid);
    (void)mw_vm_write(ctx->pid, ctx->stub_page, s.pristine, s.pristine_n);
    return rc_t::err_ptrace;
  }

  ctx->borrow_regs_snap = snap;
  ctx->in_rcall = true;
  ctx->borrow_tid = tid;
  ctx->st = mw_state_t::rcall;
  ++ctx->stats.remote_calls;

  /* Exactly one target thread is allowed to run from here until the int3. */
  if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
    mw_log_errno("remote call: PTRACE_CONT(%d)", tid);
    (void)mw_vm_write(ctx->pid, ctx->stub_page, s.pristine, s.pristine_n);
    unwind(ctx, tid, &snap, prev);
    return rc_t::err_ptrace;
  }
  mw_thr_note_running(ctx, tid);

  for (unsigned attempt = 0;; ++attempt) {
    r = mw_thr_wait(ctx, tid, &status);
    if (r != rc_t::ok) {
      /* The borrowed thread vanished: nothing to restore, but the stub bytes
       * must be put back so the code cave is not left holding live code. */
      (void)mw_vm_write(ctx->pid, ctx->stub_page, s.pristine, s.pristine_n);
      mw_thr_mark_dead(ctx, tid);
      ctx->in_rcall = false;
      ctx->borrow_tid = 0;
      ctx->st = prev;
      return r;
    }
    mw_thr_note_stopped(ctx, tid);

    if (is_controlled_trap(status)) {
      break;
    }
    if (attempt < MW_BORROW_MAX_SPURIOUS_STOPS && is_group_stop(status)) {
      /* The stub never started (or finished) yet: the thread is still parked on
       * its first instruction, so continuing is safe and re-entering the stub
       * from the top is safe too. */
      mw_log("remote call: in-flight group stop status=0x%x, continuing",
             status);
      if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        mw_log_errno("remote call: PTRACE_CONT after group stop(%d)", tid);
        (void)mw_vm_write(ctx->pid, ctx->stub_page, s.pristine, s.pristine_n);
        unwind(ctx, tid, &snap, prev);
        return rc_t::err_ptrace;
      }
      mw_thr_note_running(ctx, tid);
      continue;
    }

    mw_log("remote call: unexpected stop status=0x%x (expected SIGTRAP)",
           status);
    (void)mw_vm_write(ctx->pid, ctx->stub_page, s.pristine, s.pristine_n);
    unwind(ctx, tid, &snap, prev);
    return rc_t::err_unexpected;
  }

  if (ptrace(PTRACE_GETREGS, tid, nullptr, &run) == -1) {
    mw_log_errno("remote call: PTRACE_GETREGS after trap");
    (void)mw_vm_write(ctx->pid, ctx->stub_page, s.pristine, s.pristine_n);
    unwind(ctx, tid, &snap, prev);
    return rc_t::err_ptrace;
  }
  if (ret != nullptr) {
    *ret = static_cast<long>(run.rax);
  }
  /* Restore the complete original register image, then the code cave bytes. */
  if (ptrace(PTRACE_SETREGS, tid, nullptr, &snap) == -1) {
    mw_log_errno("remote call: PTRACE_SETREGS restore(%d)", tid);
    mw_poison(ctx, rc_t::err_ptrace, "remote-restore");
  }
  if (mw_vm_write(ctx->pid, ctx->stub_page, s.pristine, s.pristine_n) !=
      static_cast<ssize_t>(s.pristine_n)) {
    mw_log("stub: could not restore code cave bytes");
    mw_poison(ctx, rc_t::err_stub_write, "stub-restore");
  }
  ctx->in_rcall = false;
  ctx->borrow_tid = 0;
  ctx->st = prev;
  (void)mw_inv_check(ctx, "call_via_stub");
  return rc_t::ok;
}

/* Locate `0f 05` (syscall) inside an executable mapping of the target. */
rc_t gadget_scan(mw_ctx_t *ctx, uintptr_t *out) {
  std::vector<mw_map_t> maps;
  rc_t r = mw_read_maps(ctx->pid, &maps);
  if (r != rc_t::ok) {
    return r;
  }
  for (size_t i = 0; i < maps.size(); ++i) {
    const mw_map_t &m = maps[i];
    std::vector<unsigned char> buf;
    size_t len;
    ssize_t got;
    if ((m.prot & PROT_EXEC) == 0) {
      continue;
    }
    len = static_cast<size_t>(m.hi - m.lo);
    if (len == 0 || len > (4U * 1024U * 1024U)) {
      continue;
    }
    buf.resize(len);
    got = mw_vm_read(ctx->pid, m.lo, buf.data(), len);
    if (got != static_cast<ssize_t>(len)) {
      continue;
    }
    for (size_t k = 0; k + 1 < len; ++k) {
      if (buf[k] == 0x0F && buf[k + 1] == 0x05) {
        *out = m.lo + k;
        mw_log("found syscall gadget at 0x%lx in %s", *out, m.path.c_str());
        return rc_t::ok;
      }
    }
  }
  return rc_t::err_nogadget;
}

bool syscall_failed(long r) { return r < 0 && r >= -4095; }

} /* namespace */

/* ------------------------------------------------------------------ public */

rc_t mw_remote_init(mw_ctx_t *ctx) {
  long ret = 0;
  rc_t r;
  if (ctx->stub_ready) {
    return rc_t::ok;
  }
  if (!ctx->gadget_ready) {
    uintptr_t g = 0;
    r = gadget_scan(ctx, &g);
    if (r != rc_t::ok) {
      return r;
    }
    ctx->gadget = g;
    ctx->gadget_ready = true;
  }
  r = call_via_gadget(ctx, ctx->gadget,
                      static_cast<unsigned long>(__NR_mmap), 0,
                      static_cast<unsigned long>(ctx->page_size),
                      static_cast<unsigned long>(PROT_READ | PROT_WRITE |
                                                 PROT_EXEC),
                      static_cast<unsigned long>(MAP_PRIVATE | MAP_ANONYMOUS),
                      static_cast<unsigned long>(-1), 0, &ret);
  if (r != rc_t::ok) {
    return r;
  }
  if (syscall_failed(ret) || ret == 0) {
    mw_log("bootstrap mmap failed: rax=%ld", ret);
    ++ctx->stats.remote_sys_fail;
    return rc_t::err_syscall;
  }
  ctx->stub_page = static_cast<uintptr_t>(ret);
  ctx->stub_ready = true;
  mw_log("remote-call code cave ready at 0x%lx", ctx->stub_page);
  return rc_t::ok;
}

rc_t mw_remote_fini(mw_ctx_t *ctx) {
  long ret = 0;
  rc_t r;
  bool had_stub;
  if (!ctx->stub_ready) {
    return rc_t::ok;
  }
  had_stub = ctx->stub_ready;
  /* The code cave cannot unmap itself: the syscall would return into the very
   * page it just removed and die with SIGSEGV instead of reaching the int3.
   * Run this last remote call from the syscall gadget instead, which lives in
   * an existing executable mapping. */
  ctx->stub_ready = false;
  r = mw_remote_syscall(ctx, static_cast<unsigned long>(__NR_munmap),
                        ctx->stub_page,
                        static_cast<unsigned long>(ctx->page_size), 0, 0, 0, 0,
                        &ret);
  if (r != rc_t::ok) {
    ctx->stub_ready = had_stub;
    return r;
  }
  if (syscall_failed(ret)) {
    ++ctx->stats.remote_sys_fail;
    mw_log("munmap of code cave failed: %ld", ret);
    return rc_t::err_syscall;
  }
  ctx->stub_page = 0;
  ctx->stub_ready = false;
  return rc_t::ok;
}

rc_t mw_remote_syscall(mw_ctx_t *ctx, unsigned long nr, unsigned long a0,
                       unsigned long a1, unsigned long a2, unsigned long a3,
                       unsigned long a4, unsigned long a5, long *ret) {
  long r_ret = 0;
  rc_t r;

  if (!state_allows_remote(ctx->st)) {
    mw_log("remote syscall refused in state (borrow active or idle)");
    return rc_t::err_state;
  }
  if (ctx->in_rcall || ctx->borrow_tid != 0) {
    return rc_t::err_state;
  }
  if (ctx->poisoned) {
    return rc_t::err_poisoned;
  }
  /* Without either mechanism there is nothing to execute remotely: refuse
   * instead of jumping the borrowed thread to address 0. */
  if (!ctx->stub_ready && !ctx->gadget_ready) {
    mw_log("remote syscall refused: no code cave and no syscall gadget");
    return rc_t::err_nogadget;
  }
  if (!ctx->stub_ready && ctx->gadget == 0) {
    mw_log("remote syscall refused: syscall gadget address is unset");
    return rc_t::err_nogadget;
  }
  r = mw_thr_ensure_all_stopped(ctx);
  if (r != rc_t::ok) {
    return r;
  }
  if (ctx->st != mw_state_t::critical && ctx->st != mw_state_t::rearming &&
      ctx->st != mw_state_t::detaching) {
    ctx->st = mw_state_t::critical;
  }

  if (ctx->stub_ready) {
    r = call_via_stub(ctx, nr, a0, a1, a2, a3, a4, a5, &r_ret);
  } else {
    r = call_via_gadget(ctx, ctx->gadget, nr, a0, a1, a2, a3, a4, a5, &r_ret);
  }
  if (r != rc_t::ok) {
    return r;
  }
  if (ret != nullptr) {
    *ret = r_ret;
  }
  if (syscall_failed(r_ret)) {
    ++ctx->stats.remote_sys_fail;
    mw_log("remote syscall %lu failed: errno=%ld", nr, -r_ret);
    return rc_t::err_syscall;
  }
  r = mw_thr_ensure_all_stopped(ctx);
  if (r != rc_t::ok) {
    return r;
  }
  return rc_t::ok;
}

rc_t mw_remote_mprotect(mw_ctx_t *ctx, uintptr_t addr, size_t len, int prot) {
  long ret = 0;
  rc_t r;
  if (addr % ctx->page_size != 0 || len % ctx->page_size != 0 ||
      len == 0) {
    mw_log("remote mprotect: unaligned range 0x%lx+%zu", addr, len);
    return rc_t::err_invalid;
  }
  r = mw_remote_syscall(ctx, static_cast<unsigned long>(__NR_mprotect), addr,
                        static_cast<unsigned long>(len),
                        static_cast<unsigned long>(prot), 0, 0, 0, &ret);
  if (r != rc_t::ok) {
    return (r == rc_t::err_syscall) ? rc_t::err_mprotect : r;
  }
  return rc_t::ok;
}
