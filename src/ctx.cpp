#include "memwatch/api.hpp"
#include "memwatch/internal.hpp"
#include "memwatch/thr.hpp"
#include "memwatch/remote.hpp"
#include "memwatch/watch.hpp"
#include "memwatch/event.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <new>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

rc_t mw_ctx_init(mw_ctx_t **out) {
  mw_ctx_t *ctx;
  long ps;
  if (out == nullptr) {
    return rc_t::err_invalid;
  }
  *out = nullptr;
  ctx = new (std::nothrow) mw_ctx_t();
  if (ctx == nullptr) {
    return rc_t::err_proc;
  }
  (void)memset(static_cast<void *>(&ctx->borrow_regs_snap), 0,
               sizeof ctx->borrow_regs_snap);
  ps = sysconf(_SC_PAGESIZE);
  ctx->page_size = (ps > 0) ? static_cast<size_t>(ps) : 4096U;
  ctx->pid = 0;
  ctx->attached = false;
  ctx->st = mw_state_t::idle;
  ctx->have_fault = false;
  ctx->fault_tid = 0;
  ctx->fault_addr = 0;
  ctx->fault_watch = nullptr;
  ctx->in_rcall = false;
  ctx->borrow_tid = 0;
  ctx->stub_page = 0;
  ctx->stub_ready = false;
  ctx->gadget = 0;
  ctx->gadget_ready = false;
  ctx->poisoned = false;
  ctx->poison_rc = rc_t::ok;
  ctx->target_exited = false;
  ctx->exit_status = 0;
  (void)memset(&ctx->stats, 0, sizeof ctx->stats);
  *out = ctx;
  return rc_t::ok;
}

rc_t mw_ctx_free(mw_ctx_t *ctx) {
  if (ctx == nullptr) {
    return rc_t::err_invalid;
  }
  if (ctx->attached) {
    (void)mw_detach(ctx);
  }
  delete ctx;
  return rc_t::ok;
}

rc_t mw_attach(mw_ctx_t *ctx, pid_t pid) {
  rc_t r;

  if (ctx == nullptr || pid <= 0) {
    return rc_t::err_invalid;
  }
  if (ctx->attached) {
    return rc_t::err_already;
  }
  if (ctx->st != mw_state_t::idle) {
    return rc_t::err_state;
  }

  if (ptrace(PTRACE_SEIZE, pid, nullptr,
             reinterpret_cast<void *>(static_cast<uintptr_t>(MW_PTRACE_OPTS))) ==
      -1) {
    if (errno == ESRCH) {
      return rc_t::err_not_found;
    }
    mw_log_errno("PTRACE_SEIZE(%d)", pid);
    return rc_t::err_attach;
  }
  ctx->pid = pid;
  ctx->attached = true;

  /* Deterministic baseline: stop everything, then look around. */
  ctx->st = mw_state_t::entering;
  r = mw_thr_sync_seized(ctx);
  if (r != rc_t::ok) {
    ctx->attached = false;
    ctx->st = mw_state_t::idle;
    return r;
  }
  r = mw_thr_stop_all(ctx);
  if (r != rc_t::ok) {
    ctx->attached = false;
    ctx->st = mw_state_t::idle;
    return r;
  }
  ctx->st = mw_state_t::critical;

  /* ptrace options are per-tracee: SEIZE only set them for the thread we named,
   * and they are inherited only by threads created from now on. */
  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (!ctx->thrs[i].alive) {
      continue;
    }
    if (ptrace(PTRACE_SETOPTIONS, ctx->thrs[i].tid, nullptr,
               reinterpret_cast<void *>(
                   static_cast<uintptr_t>(MW_PTRACE_OPTS))) == -1) {
      if (errno == ESRCH) {
        mw_thr_mark_dead(ctx, ctx->thrs[i].tid);
        continue;
      }
      mw_log_errno("PTRACE_SETOPTIONS(%d)", ctx->thrs[i].tid);
      r = rc_t::err_ptrace;
    }
  }
  if (r != rc_t::ok) {
    (void)mw_thr_resume_all(ctx, true);
    ctx->st = mw_state_t::idle;
    return r;
  }

  /* Bootstrap the private remote-call code cave while the target is stopped. */
  r = mw_remote_init(ctx);
  if (r != rc_t::ok) {
    mw_log("remote calls unavailable: %s (watch_add will refuse)",
           mw_strerror(r));
    if (r == rc_t::err_gone || r == rc_t::err_invariant) {
      (void)mw_thr_resume_all(ctx, true);
      ctx->st = mw_state_t::idle;
      return r;
    }
  }

  r = mw_thr_resume_all(ctx, true);
  ctx->st = mw_state_t::idle;
  if (r != rc_t::ok) {
    return r;
  }
  mw_log("attached to %d (%zu threads)", pid, mw_thr_count_alive(ctx));
  return rc_t::ok;
}

rc_t mw_detach(mw_ctx_t *ctx) {
  rc_t first = rc_t::ok;
  rc_t r;

  if (ctx == nullptr) {
    return rc_t::err_invalid;
  }
  if (!ctx->attached) {
    return rc_t::err_state;
  }
  if (ctx->st != mw_state_t::idle) {
    return rc_t::err_state;
  }

  ctx->st = mw_state_t::detaching;
  r = mw_thr_stop_all(ctx);
  if (r == rc_t::err_gone) {
    ctx->thrs.clear();
    ctx->attached = false;
    ctx->st = mw_state_t::idle;
    return rc_t::err_gone;
  }
  if (r != rc_t::ok) {
    ctx->st = mw_state_t::idle;
    return r;
  }
  (void)mw_inv_check(ctx, "detach/stopped");

  r = mw_watch_restore_all(ctx);
  if (r != rc_t::ok) {
    first = r;
  }
  if (ctx->st != mw_state_t::detaching) {
    ctx->st = mw_state_t::detaching;
  }
  if (mw_remote_fini(ctx) != rc_t::ok && first == rc_t::ok) {
    first = rc_t::err_syscall;
  }

  for (size_t i = 0; i < ctx->thrs.size(); ++i) {
    if (!ctx->thrs[i].alive) {
      continue;
    }
    if (ptrace(PTRACE_DETACH, ctx->thrs[i].tid, nullptr, nullptr) == -1) {
      if (errno == ESRCH) {
        mw_thr_mark_dead(ctx, ctx->thrs[i].tid);
        continue;
      }
      mw_log_errno("PTRACE_DETACH(%d)", ctx->thrs[i].tid);
      if (first == rc_t::ok) {
        first = rc_t::err_ptrace;
      }
    }
    ctx->thrs[i].running = false;
  }

  ctx->thrs.clear();
  ctx->ws.clear();
  ctx->attached = false;
  ctx->stub_ready = false;
  ctx->stub_page = 0;
  ctx->gadget_ready = false;
  ctx->gadget = 0;
  mw_fault_clear(ctx);
  ctx->in_rcall = false;
  ctx->borrow_tid = 0;
  ctx->st = mw_state_t::idle;
  mw_log("detached");
  return first;
}
