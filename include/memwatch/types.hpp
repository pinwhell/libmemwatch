/* libmemwatch - core types.
 *
 * Architecture (do not redesign):
 *   ptrace + PROT_NONE + SIGSEGV
 *   -> global thread stop
 *   -> double validation
 *   -> callback while all target threads are stopped
 *   -> armed=false ownership transition
 *   -> remote mprotect using exactly one borrowed stopped target thread
 *   -> restore all registers
 *   -> PTRACE_SINGLESTEP of exactly the faulting thread
 *   -> SIGTRAP
 *   -> global stop
 *   -> remote mprotect(PROT_NONE)
 *   -> armed=true
 *   -> resume target
 */
#ifndef MEMWATCH_TYPES_HPP
#define MEMWATCH_TYPES_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>

struct mw_ctx_t;
struct mw_watch_t;
struct mw_fault_t;

/* Return codes. Extended from the design (added: err_nogadget, err_invariant,
 * err_gone, err_range) so that no failure can be silently reported as success. */
enum class rc_t : int {
  ok = 0,
  action_skip,     /* watch callback requested MW_ACTION_SKIP */
  action_disarm,   /* watch callback requested MW_ACTION_DISARM */
  action_kill,     /* watch callback requested MW_ACTION_KILL */
  err_attach,      /* PTRACE_SEIZE / PTRACE_ATTACH failed */
  err_ptrace,      /* a ptrace() or waitpid() call failed unexpectedly */
  err_mprotect,    /* the remote mprotect syscall returned -1/errno */
  err_proc,        /* procfs read / allocation failure */
  err_invalid,     /* caller passed an invalid argument */
  err_not_found,   /* no such watch / thread / event */
  err_already,     /* duplicate or overlapping watch */
  err_state,       /* illegal state-machine transition */
  err_unexpected,  /* unexpected signal inside a controlled scope */
  err_timeout,     /* deadline exceeded */
  err_syscall,     /* remote syscall returned an error */
  err_stub_write,  /* could not write/restore the remote-call stub bytes */
  err_nothread,    /* no stopped, alive thread available to borrow */
  err_nogadget,    /* no way to inject a syscall into the target */
  err_invariant,   /* internal invariant violated */
  err_gone,        /* target process exited */
  err_range,       /* overflowed or unmappable address range */
  err_poisoned,    /* context is poisoned; only mw_detach is legal */
};

enum mw_action_t : int {
  MW_ACTION_REPLAY = 0, /* unprotect, single-step insn, re-arm PROT_NONE, resume */
  MW_ACTION_SKIP   = 1, /* user handled access/bumped RIP: keep PROT_NONE, resume */
  MW_ACTION_DISARM = 2, /* permanently remove watchpoint, restore memory, resume */
  MW_ACTION_KILL   = 3, /* terminate target process */
};

enum class mw_state_t : int {
  idle,       /* target runs freely */
  entering,   /* candidate fault seen, forcing the global stop */
  critical,   /* every alive target thread is stopped, no rcall/sstep active */
  rcall,      /* remote call in progress: only borrow_tid runs */
  sstep,      /* PTRACE_SINGLESTEP in progress on fault_tid only */
  rearming,   /* post-single-step, re-arming with PROT_NONE */
  detaching,  /* restoring protections and detaching */
};

struct rng_t {
  uintptr_t base;
  size_t    size;
};

struct pg_t {
  uintptr_t addr; /* page aligned */
};

/* One tracked thread of the target.
 *
 * running == true means: we issued PTRACE_CONT/PTRACE_SINGLESTEP for this tid
 * and have NOT yet reaped the resulting ptrace stop. That is the only meaning
 * of "may be executing user code", which is what makes the global stop
 * provable: zero running threads => zero user instructions executing.
 */
struct thr_t {
  pid_t tid;
  bool  alive;
  bool  running;
  bool  init_stop;    /* initial clone stop not yet reaped */
  int   deliver_sig;  /* signal injected on the next resume (0 = suppress) */
  bool  has_pend_si;  /* deliver_sig must carry this siginfo */
  siginfo_t pend_si;
};

typedef rc_t (*mw_cb_t)(mw_ctx_t *ctx, mw_watch_t *w, mw_fault_t *f);

struct mw_watch_t {
  rng_t    r;      /* range exactly as requested by the user */
  pg_t     p0;     /* first page of the watched range */
  size_t   pcount; /* number of pages covered by r */
  bool     armed;  /* ownership guard: true <=> pages are PROT_NONE right now */
  std::vector<int> prot; /* original protection of each page (PROT_* flags) */
  mw_cb_t  cb;
  void    *ud;
};

struct mw_fault_t {
  pid_t     tid;
  uintptr_t addr;     /* si_addr, exact faulting address */
  pg_t      p;        /* page aligned addr */
  int       si_code;  /* SEGV_MAPERR / SEGV_ACCERR */
  unsigned long long rip; /* faulting instruction of the faulting thread */
  mw_watch_t *watch;  /* owning watch, non-null only when owned */
  bool      owned;    /* true when the fault belongs to memwatch */
};

struct mw_stats_t {
  uint64_t polls;
  uint64_t events;
  uint64_t faults_owned;
  uint64_t faults_forwarded;
  uint64_t remote_calls;
  uint64_t remote_sys_fail;
  uint64_t ssteps;
  uint64_t clone_events;
  uint64_t thread_exits;
  uint64_t signals_forwarded;
  uint64_t signals_suppressed;
  uint64_t inv_checks;
  uint64_t inv_violations;
  uint64_t cleanup_failures;
};

struct mw_ctx_t {
  pid_t       pid;
  bool        attached;
  size_t      page_size;

  std::vector<thr_t> thrs;

  std::vector<mw_watch_t> ws;

  mw_state_t  st;

  /* pending fault bookkeeping */
  bool        have_fault;
  pid_t       fault_tid;
  uintptr_t   fault_addr;
  mw_watch_t *fault_watch;

  /* remote-call borrow bookkeeping */
  bool        in_rcall;
  pid_t       borrow_tid;
  user_regs_struct borrow_regs_snap;

  /* remote-call executable area owned by memwatch inside the target */
  uintptr_t   stub_page;    /* page base, PROT_READ|WRITE|EXEC, in target */
  bool        stub_ready;
  uintptr_t   gadget;       /* `syscall` (0f 05) gadget used to bootstrap */
  bool        gadget_ready;

  bool        poisoned;
  rc_t        poison_rc;

  /* memwatch reaps the target's death itself (it has to, to report
   * rc_t::err_gone), so the wait status the kernel handed over is kept here
   * instead of being lost. */
  bool        target_exited;
  int         exit_status;

  /* Persistent last fault record for mw_get_fault inspection */
  bool        has_last_fault;
  mw_fault_t  last_fault;

  mw_stats_t  stats;
};

inline pg_t pg_align_down(uintptr_t addr, size_t page_size) {
  pg_t p;
  p.addr = addr & ~static_cast<uintptr_t>(page_size - 1U);
  return p;
}

inline bool rng_covers(const rng_t &r, uintptr_t addr) {
  return addr >= r.base && addr - r.base < r.size;
}

#endif /* MEMWATCH_TYPES_HPP */
