/* libmemwatch - thread controller.
 *
 * Postcondition of thr_stop_all()/thr_ensure_all_stopped() returning ok:
 *   every alive target thread has thr_t::running == false,
 * which means no target thread can be executing user code.
 */
#ifndef MEMWATCH_THR_HPP
#define MEMWATCH_THR_HPP

#include "memwatch/types.hpp"

thr_t *mw_thr_find(mw_ctx_t *ctx, pid_t tid);
thr_t *mw_thr_find_alive(mw_ctx_t *ctx, pid_t tid);
size_t mw_thr_count_running(const mw_ctx_t *ctx);
size_t mw_thr_count_alive(const mw_ctx_t *ctx);
size_t mw_thr_count_stopped(const mw_ctx_t *ctx);

/* Reconcile the tracked list with /proc/<pid>/task and with ptrace events.
 * Never changes the execution state of any thread; newly discovered threads are
 * recorded as stopped because a fresh ptrace tracee cannot run user code before
 * the tracer continues it. */
rc_t mw_thr_sync(mw_ctx_t *ctx);

/* Initial inventory right after PTRACE_SEIZE.  SEIZE does not stop the tracee,
 * so every pre-existing thread is executing user code and must be recorded as
 * running: otherwise the first global stop would believe in a false "all
 * threads stopped" and single-step a borrow while the rest keep running. */
rc_t mw_thr_sync_seized(mw_ctx_t *ctx);

/* Register a thread reported by PTRACE_EVENT_CLONE (or discovered). */
rc_t mw_thr_add_cloned(mw_ctx_t *ctx, pid_t tid);
void mw_thr_mark_dead(mw_ctx_t *ctx, pid_t tid);

/* Global stop.  Idempotent. */
rc_t mw_thr_stop_all(mw_ctx_t *ctx);
rc_t mw_thr_ensure_all_stopped(mw_ctx_t *ctx);

/* Global resume.  Every alive, non-running thread is continued; deliver
 * selects whether the per-thread pending signal is injected or suppressed. */
rc_t mw_thr_resume_all(mw_ctx_t *ctx, bool deliver);

/* Resume exactly one thread (used by the idle-state event handler). */
rc_t mw_thr_resume_one(mw_ctx_t *ctx, pid_t tid, int sig, bool has_si,
                       const siginfo_t *si);

/* Wait for a specific thread, retrying on EINTR. */
rc_t mw_thr_wait(mw_ctx_t *ctx, pid_t tid, int *status);
rc_t mw_thr_wait_any(mw_ctx_t *ctx, pid_t *tid, int *status, bool blocking,
                     int timeout_ms);

void mw_thr_note_running(mw_ctx_t *ctx, pid_t tid);
void mw_thr_note_stopped(mw_ctx_t *ctx, pid_t tid);

#endif /* MEMWATCH_THR_HPP */
