/* libmemwatch - internal helpers shared by the implementation files. */
#ifndef MEMWATCH_INTERNAL_HPP
#define MEMWATCH_INTERNAL_HPP

#include "memwatch/types.hpp"

#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

#include <dirent.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

#if !defined(__x86_64__)
#error "libmemwatch currently supports x86_64 only"
#endif

/* Wait for any tracee of this tracer process, never for unrelated children. */
#define MW_WAIT_FLAGS (__WALL | __WNOTHREAD)
#define MW_WAIT_NOWAIT (MW_WAIT_FLAGS | WNOHANG)

/* ptrace options installed on every tracked thread. */
#define MW_PTRACE_OPTS                                                      \
  (PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL |          \
   PTRACE_O_TRACESYSGOOD)

/* Hard cap on the global-stop retry loop; a target that clones forever must not
 * hang the tracer. */
#define MW_STOP_MAX_ROUNDS 4096

/* A group-stop published by an interrupt that was issued just before a borrow
 * may still be queued when that borrow starts.  The borrow continues the thread
 * and waits again rather than failing; this bounds the retries. */
#define MW_BORROW_MAX_SPURIOUS_STOPS 8

#ifdef __GNUC__
#define MW_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define MW_PRINTF(a, b)
#endif

struct mw_map_t {
  uintptr_t lo;
  uintptr_t hi;
  int       prot;  /* PROT_* flags */
  char      perms[5];
  std::string path;
};

/* ------------------------------------------------------------------- logging */
void mw_log(const char *fmt, ...) MW_PRINTF(1, 2);
void mw_log_errno(const char *fmt, ...) MW_PRINTF(1, 2);

/* ------------------------------------------------------------------- procfs */
rc_t    mw_read_maps(pid_t pid, std::vector<mw_map_t> *out);
int     mw_perms_to_prot(const char perms[4]);
rc_t    mw_list_tasks(pid_t pid, std::vector<pid_t> *out);
bool    mw_task_alive(pid_t pid, pid_t tid);
char    mw_task_state(pid_t pid, pid_t tid); /* 'R','t','Z','S', 0 if unknown */

/* ------------------------------------------------------------------- memory */
ssize_t mw_vm_read(pid_t pid, uintptr_t addr, void *buf, size_t len);
ssize_t mw_vm_write(pid_t pid, uintptr_t addr, const void *buf, size_t len);

/* ------------------------------------------------------------------- ptrace */
long mw_ptrace_enter(void);

/* --------------------------------------------------------------- invariants */
rc_t mw_inv_check(mw_ctx_t *ctx, const char *where);
void mw_poison(mw_ctx_t *ctx, rc_t why, const char *where);
void mw_fault_clear(mw_ctx_t *ctx);
size_t mw_page_count(uintptr_t base, size_t size, size_t page_size);

#endif /* MEMWATCH_INTERNAL_HPP */
