/* libmemwatch - public API. */
#ifndef MEMWATCH_API_HPP
#define MEMWATCH_API_HPP

#include "memwatch/types.hpp"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mw_logfn_t)(const char *msg);

/* ---------------------------------------------------------------- lifecycle */

rc_t mw_ctx_init(mw_ctx_t **out);
rc_t mw_ctx_free(mw_ctx_t *ctx);

/* Attach with PTRACE_SEIZE, install ptrace options on every existing thread,
 * establish a deterministic baseline (all threads stopped, then resumed). */
rc_t mw_attach(mw_ctx_t *ctx, pid_t pid);

/* Restore every watched page, release the remote-call stub page and
 * PTRACE_DETACH every alive thread.  Returns err_gone if the target is gone. */
rc_t mw_detach(mw_ctx_t *ctx);

/* ------------------------------------------------------------------- watches */

/* Watch [base, base+size).  Pages must be mapped in the target and must not
 * overlap any existing watch.  The watch is only reported as armed once
 * PROT_NONE is really installed. */
rc_t mw_watch_add(mw_ctx_t *ctx, uintptr_t base, size_t size, mw_cb_t cb,
                  void *ud);
rc_t mw_watch_del(mw_ctx_t *ctx, uintptr_t base, size_t size);
rc_t mw_watch_del_all(mw_ctx_t *ctx);

/* ---------------------------------------------------------------- event loop */

/* Wait for one target event and drive it to completion.
 * Returns err_timeout when nothing happened within timeout_ms (<0 = forever). */
rc_t mw_poll(mw_ctx_t *ctx, int timeout_ms);

/* mw_poll in a loop.  Returns the first non-ok/err_timeout code. */
rc_t mw_run(mw_ctx_t *ctx);

/* ---------------------------------------------------------------- inspection */

const char *mw_strerror(rc_t r);
rc_t         mw_get_stats(const mw_ctx_t *ctx, mw_stats_t *out);
size_t       mw_threads_alive(const mw_ctx_t *ctx);
size_t       mw_threads_running(const mw_ctx_t *ctx);
mw_state_t   mw_get_state(const mw_ctx_t *ctx);
rc_t         mw_get_fault(mw_ctx_t *ctx, mw_fault_t *out);

/* The tracer is the target's parent, so memwatch is the only component that can
 * waitpid() the target's death - a caller's own waitpid() would fail with
 * ECHILD once mw_poll()/mw_detach() has reported rc_t::err_gone.  This returns
 * the wait status the kernel reported (WIFEXITED/WEXITSTATUS or
 * WIFSIGNALED/WTERMSIG), or false while the target is still alive. */
bool         mw_target_exit(const mw_ctx_t *ctx, int *wait_status);

/* Memory access into the stopped target, used from watch callbacks. */
ssize_t mw_read_mem(mw_ctx_t *ctx, uintptr_t addr, void *buf, size_t len);
ssize_t mw_write_mem(mw_ctx_t *ctx, uintptr_t addr, const void *buf, size_t len);

/* Diagnostics. */
void mw_log_set(mw_logfn_t fn);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MEMWATCH_API_HPP */
