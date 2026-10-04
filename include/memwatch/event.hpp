/* libmemwatch - fault engine (event loop + state machine). */
#ifndef MEMWATCH_EVENT_HPP
#define MEMWATCH_EVENT_HPP

#include "memwatch/types.hpp"

enum class ev_t : int {
  none,        /* nothing happened */
  target_exit, /* the whole target process is gone */
  thread_exit,
  clone,
  fault,       /* SIGSEGV / SIGBUS candidate */
  step_trap,   /* the SIGTRAP we asked for with PTRACE_SINGLESTEP */
  stray_trap,  /* SIGTRAP we did not ask for */
  group_stop,  /* SIGSTOP & friends */
  signal,      /* any other signal: must be forwarded */
  unknown,
};

/* Classify a reaped wait status.  *out_sig / *out_newtid receive the signal
 * number and the clone event message respectively. */
ev_t mw_ev_classify(mw_ctx_t *ctx, pid_t tid, int status, int *out_sig,
                    pid_t *out_newtid);

/* Apply a classified event to the thread table and (when resume_now is true)
 * continue the thread.  During a critical section resume_now must be false so
 * that no thread escapes the stop discipline. */
rc_t mw_ev_apply(mw_ctx_t *ctx, ev_t ev, pid_t tid, int status, bool resume_now);

/* Reap without classifying; returns false when nothing was pending. */
bool mw_ev_reap_nonblock(mw_ctx_t *ctx, pid_t *tid, int *status);

/* Drain every pending, non-blocking event (no state-machine transitions). */
rc_t mw_ev_drain(mw_ctx_t *ctx);

/* The whole fault sequence: entering -> critical -> callback -> disarm ->
 * rcall -> sstep -> rearming -> arm -> cleanup -> resume -> idle. */
rc_t mw_ev_handle_fault(mw_ctx_t *ctx, pid_t tid, int sig);

#endif /* MEMWATCH_EVENT_HPP */
