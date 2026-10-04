/* libmemwatch - remote call engine.
 *
 * Borrows exactly one alive, stopped target thread, makes it execute a minimal
 * architecture-correct syscall stub and restores its complete register state.
 * No other target thread runs at any point of the call.
 */
#ifndef MEMWATCH_REMOTE_HPP
#define MEMWATCH_REMOTE_HPP

#include "memwatch/types.hpp"

/* Locate a `syscall` (0f 05) instruction inside an executable mapping of the
 * target and use it to create a private RWX stub page inside the target.
 * Precondition: all target threads stopped, ctx->st in the critical set. */
rc_t mw_remote_init(mw_ctx_t *ctx);

/* Release the private stub page (remote munmap).  All threads must be stopped.
 * Idempotent: ok when no stub page exists. */
rc_t mw_remote_fini(mw_ctx_t *ctx);

/* Remote mprotect.  Preconditions: every alive thread stopped, no active
 * borrow.  On success all threads are still stopped and every register of the
 * borrowed thread is bit-identical to what it was before the call.
 * On failure the borrow is unwound the same way and the state machine stays
 * coherent. */
rc_t mw_remote_mprotect(mw_ctx_t *ctx, uintptr_t addr, size_t len, int prot);

/* Generic remote syscall (used for the bootstrap mmap). */
rc_t mw_remote_syscall(mw_ctx_t *ctx, unsigned long nr, unsigned long a0,
                       unsigned long a1, unsigned long a2, unsigned long a3,
                       unsigned long a4, unsigned long a5, long *ret);

#endif /* MEMWATCH_REMOTE_HPP */
