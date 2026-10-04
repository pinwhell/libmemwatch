/* libmemwatch test suite.
 *
 * Every case forks a target child, attaches with ptrace as the parent, arms
 * watches, and then checks the result against the kernel's own view of the
 * world rather than against memwatch's bookkeeping:
 *
 *   - one event per access, per page, summed over every thread
 *   - the target's own data survives (checksums computed after the borrowed
 *     thread had its registers overwritten and restored)
 *   - no target thread is observed running (/proc) while memwatch is in a
 *     critical section, and memwatch's own view agrees
 *   - the watched page really is PROT_NONE while armed and really is restored
 *   - signals that do not belong to memwatch reach the target handler
 */
#include "harness.hpp"

#include <cerrno>
#include <csignal>
#include <csetjmp>
#include <cstdlib>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAT 0x5A5A5A5A5A5A5A5AULL

namespace {

volatile uint64_t *tp(unsigned page) {
  return reinterpret_cast<volatile uint64_t *>(
      static_cast<uintptr_t>(TGT_BASE) + (page * TGT_PAGE_SIZE));
}

uint64_t sum_to(uint32_t n) { return static_cast<uint64_t>(n) * (n + 1U) / 2U; }

/* ---------------------------------------------------------------- targets */

struct warg_t {
  ctl_t   *c;
  unsigned id;
  unsigned pages;
  uint32_t n;
};

void *worker(void *arg) {
  warg_t *a = static_cast<warg_t *>(arg);
  uint64_t acc = 0;
  for (uint32_t i = 1; i <= a->n; ++i) {
    unsigned page = (a->pages > 1U) ? ((i - 1U) % a->pages) : 0U;
    *tp(page) = i;
    acc += i;
    __atomic_add_fetch(&a->c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&a->c->page_iters[page], 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&a->c->sums[a->id], acc, __ATOMIC_SEQ_CST);
  return nullptr;
}

/* A: one thread, repeated writes to one watched page. */
void tgt_a(ctl_t *c) {
  uint64_t acc = 0;
  child_prepare(c, 1);
  wait_go(c);
  for (uint32_t i = 1; i <= 300U; ++i) {
    *tp(0) = i;
    acc += i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&c->sums[0], acc, __ATOMIC_SEQ_CST);
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* B: one thread, repeated reads.  The page is pre-filled before the tracer may
 * attach, so the expected value is known exactly. */
void tgt_b(ctl_t *c) {
  uint64_t acc = 0;
  child_map(c, 1);
  *tp(0) = PAT;
  child_ready(c);
  wait_go(c);
  for (uint32_t i = 0; i < 300U; ++i) {
    acc += *tp(0);
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&c->sums[0], acc, __ATOMIC_SEQ_CST);
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* C: four threads hammering the same watched page. */
void tgt_c(ctl_t *c) {
  pthread_t th[4];
  warg_t a[4];
  child_prepare(c, 1);
  __atomic_store_n(&c->nthreads, 4U, __ATOMIC_SEQ_CST);
  for (unsigned k = 0; k < 4U; ++k) {
    a[k].c = c;
    a[k].id = k;
    a[k].pages = 1U;
    a[k].n = 150U;
  }
  wait_go(c);
  for (unsigned k = 0; k < 4U; ++k) {
    if (pthread_create(&th[k], nullptr, worker, &a[k]) != 0) {
      _exit(96);
    }
  }
  for (unsigned k = 0; k < 4U; ++k) {
    (void)pthread_join(th[k], nullptr);
  }
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* C': the stress shape: six threads, two watched pages. */
void tgt_c_stress(ctl_t *c) {
  pthread_t th[6];
  warg_t a[6];
  child_prepare(c, 2);
  __atomic_store_n(&c->nthreads, 6U, __ATOMIC_SEQ_CST);
  for (unsigned k = 0; k < 6U; ++k) {
    a[k].c = c;
    a[k].id = k;
    a[k].pages = 2U;
    a[k].n = 120U;
  }
  wait_go(c);
  for (unsigned k = 0; k < 6U; ++k) {
    if (pthread_create(&th[k], nullptr, worker, &a[k]) != 0) {
      _exit(96);
    }
  }
  for (unsigned k = 0; k < 6U; ++k) {
    (void)pthread_join(th[k], nullptr);
  }
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* D: three watched pages, round robin. */
void tgt_d(ctl_t *c) {
  uint64_t acc = 0;
  child_prepare(c, 3);
  wait_go(c);
  for (uint32_t i = 1; i <= 300U; ++i) {
    unsigned page = (i - 1U) % 3U;
    *tp(page) = i;
    acc += i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[page], 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&c->sums[0], acc, __ATOMIC_SEQ_CST);
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* E: threads are created while the watch is armed. */
void tgt_e(ctl_t *c) {
  pthread_t th[4];
  warg_t a[4];
  uint64_t acc = 0;
  child_prepare(c, 1);
  __atomic_store_n(&c->nthreads, 5U, __ATOMIC_SEQ_CST);
  for (unsigned k = 0; k < 4U; ++k) {
    a[k].c = c;
    a[k].id = k + 1U;
    a[k].pages = 1U;
    a[k].n = 60U;
  }
  wait_go(c);
  for (unsigned k = 0; k < 4U; ++k) {
    if (pthread_create(&th[k], nullptr, worker, &a[k]) != 0) {
      _exit(96);
    }
    for (uint32_t j = 0; j < 30U; ++j) {
      *tp(0) = j;
      acc += j;
      __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
      __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
    }
    (void)pthread_join(th[k], nullptr);
  }
  __atomic_store_n(&c->sums[0], acc, __ATOMIC_SEQ_CST);
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* F: short-lived threads come and go while the watch is armed. */
void tgt_f(ctl_t *c) {
  child_prepare(c, 1);
  __atomic_store_n(&c->nthreads, 9U, __ATOMIC_SEQ_CST);
  wait_go(c);
  for (unsigned k = 0; k < 8U; ++k) {
    pthread_t th;
    warg_t a;
    a.c = c;
    a.id = k;
    a.pages = 1U;
    a.n = 25U;
    if (pthread_create(&th, nullptr, worker, &a) == 0) {
      for (uint32_t j = 0; j < 10U; ++j) {
        *tp(0) = j;
        __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
        __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
      }
      (void)pthread_join(th, nullptr);
    }
  }
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* G: an unrelated SIGSEGV must reach the target's handler untouched.
 *
 * The jump buffer, the arming flag and the handler all live in this
 * translation unit together with the sigsetjmp() call site: a setjmp buffer
 * whose setjmp/longjmp pair is split across translation units gives the
 * compiler no returns_twice information about the frames in between, and the
 * non-local return then resumes with a stack frame that no longer exists. */
static sigjmp_buf g_g_jmp;
static volatile sig_atomic_t g_g_armed = 0;

static void g_segv_handler(int sig, siginfo_t *si, void *uc) {
  ctl_t *c = g_child_ctl;
  (void)sig;
  (void)uc;
  if (c != nullptr) {
    __atomic_add_fetch(&c->segv_seen, 1U, __ATOMIC_SEQ_CST);
    __atomic_store_n(&c->segv_addr,
                     static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
                         si != nullptr ? si->si_addr : nullptr)),
                     __ATOMIC_SEQ_CST);
    if (g_g_armed != 0) {
      g_g_armed = 0;
      siglongjmp(g_g_jmp, 1);
    }
  }
}

static void g_install_handler(void) {
  struct sigaction sa;
  (void)memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = g_segv_handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  (void)sigemptyset(&sa.sa_mask);
  if (sigaction(SIGSEGV, &sa, nullptr) == -1) {
    _exit(97);
  }
}

void tgt_g(ctl_t *c) {
  child_prepare(c, 1);
  g_install_handler();
  wait_go(c);
  for (uint32_t i = 1; i <= 100U; ++i) {
    *tp(0) = i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  if (sigsetjmp(g_g_jmp, 1) == 0) {
    g_g_armed = 1;
    /* The faulting address is computed at run time so that the compiler cannot
     * fold it into a compile-time null dereference and reject the build. */
    {
      uintptr_t bad = static_cast<uintptr_t>(
                          __atomic_load_n(&c->unused, __ATOMIC_SEQ_CST)) +
                      1U;
      *reinterpret_cast<volatile int *>(bad) = 1;
    }
    __atomic_add_fetch(&c->corrupt, 1U, __ATOMIC_SEQ_CST);
  }
  for (uint32_t i = 1; i <= 100U; ++i) {
    *tp(0) = i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* H: many repeated faults on a single thread. */
void tgt_h(ctl_t *c) {
  uint64_t acc = 0;
  child_prepare(c, 1);
  wait_go(c);
  for (uint32_t i = 1; i <= 2000U; ++i) {
    *tp(0) = i;
    acc += i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&c->sums[0], acc, __ATOMIC_SEQ_CST);
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* I/J: driven from the outside, never finishes on its own.
 *
 * Three mapped pages: cases I and J arm multi-page watches, so the mapping has
 * to be there before memwatch is asked to capture its protection. */
void tgt_loop(ctl_t *c) {
  uint64_t i = 0;
  child_prepare(c, 3);
  wait_go(c);
  while (__atomic_load_n(&c->quit, __ATOMIC_SEQ_CST) == 0U) {
    ++i;
    *tp(0) = i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
    if ((i & 0x3FU) == 0U) {
      sched_yield();
    }
  }
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
}

/* L: the target unmaps a page inside the watched range after it was armed, so
 * the protection can no longer be restored. */
void tgt_l2(ctl_t *c) {
  child_prepare(c, 4);
  wait_go(c);
  for (uint32_t i = 0; i < 50U; ++i) {
    *tp(0) = i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  if (munmap(reinterpret_cast<void *>(static_cast<uintptr_t>(TGT_BASE) +
                                     TGT_PAGE_SIZE),
             TGT_PAGE_SIZE) != 0) {
    __atomic_add_fetch(&c->corrupt, 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* L: the hole is already there when the watch is added. */
void tgt_l3(ctl_t *c) {
  child_map(c, 2);
  if (munmap(reinterpret_cast<void *>(static_cast<uintptr_t>(TGT_BASE) +
                                     TGT_PAGE_SIZE),
             TGT_PAGE_SIZE) != 0) {
    __atomic_add_fetch(&c->corrupt, 1U, __ATOMIC_SEQ_CST);
  }
  child_ready(c);
  wait_go(c);
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* K: the target exits while it is being monitored. */
void tgt_k(ctl_t *c) {
  child_prepare(c, 1);
  wait_go(c);
  for (uint32_t i = 1; i <= 40U; ++i) {
    *tp(0) = i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&c->child_exit, 7U, __ATOMIC_SEQ_CST);
  _exit(7);
}

/* M: signals that are not ours must all be forwarded. */
void tgt_m(ctl_t *c) {
  child_prepare(c, 1);
  set_handler(SIGBUS, 0);
  set_handler(SIGILL, 0);
  set_handler(SIGTRAP, 0);
  set_handler(SIGUSR1, 0);
  set_handler(SIGFPE, 0);
  wait_go(c);
  for (uint32_t i = 1; i <= 100U; ++i) {
    *tp(0) = i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  (void)raise(SIGUSR1);
  (void)raise(SIGBUS);
  (void)raise(SIGILL);
  (void)raise(SIGTRAP);
  (void)raise(SIGFPE);
  for (uint32_t i = 1; i <= 100U; ++i) {
    *tp(0) = i;
    __atomic_add_fetch(&c->total_iters, 1U, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&c->page_iters[0], 1U, __ATOMIC_SEQ_CST);
  }
  __atomic_store_n(&c->done, 1U, __ATOMIC_SEQ_CST);
  wait_quit(c);
}

/* ---------------------------------------------------------------- driver */

int g_stress_rounds = 1;
int g_stress_only = 0;
int g_only = -1;
int g_no_stress = 0;

/* Values a case expects.  Zero means "not checked" for the counters that have
 * no meaningful zero, while segv_seen/sig_counts must always match. */
struct expect_t {
  unsigned pages;
  uint32_t total_iters;
  uint32_t nthreads;
  uint64_t sums[8];
  uint32_t sig_counts[8];
  uint32_t segv_seen;
};

void report(const char *name, const obs_t *o, const mw_stats_t *st,
            int failed_before) {
  if (failed_before == g_failures) {
    return;
  }
  fprintf(stderr, "  [%s] diagnostics\n", name);
  if (o != nullptr) {
    fprintf(stderr,
            "    events=%llu checks=%llu state_viol=%llu running_viol=%llu "
            "proc_running_viol=%llu prot_viol=%llu own_viol=%llu cb_err=%llu\n",
            static_cast<unsigned long long>(o->events),
            static_cast<unsigned long long>(o->checks),
            static_cast<unsigned long long>(o->state_violations),
            static_cast<unsigned long long>(o->running_violations),
            static_cast<unsigned long long>(o->proc_running_violations),
            static_cast<unsigned long long>(o->prot_violations),
            static_cast<unsigned long long>(o->ownership_violations),
            static_cast<unsigned long long>(o->cb_errors));
  }
  if (st != nullptr) {
    fprintf(stderr,
            "    polls=%llu owned=%llu fwd=%llu remote=%llu sysfail=%llu "
            "sstep=%llu clone=%llu exits=%llu sig_fwd=%llu sig_sup=%llu "
            "inv=%llu inv_viol=%llu cleanup=%llu\n",
            static_cast<unsigned long long>(st->polls),
            static_cast<unsigned long long>(st->faults_owned),
            static_cast<unsigned long long>(st->faults_forwarded),
            static_cast<unsigned long long>(st->remote_calls),
            static_cast<unsigned long long>(st->remote_sys_fail),
            static_cast<unsigned long long>(st->ssteps),
            static_cast<unsigned long long>(st->clone_events),
            static_cast<unsigned long long>(st->thread_exits),
            static_cast<unsigned long long>(st->signals_forwarded),
            static_cast<unsigned long long>(st->signals_suppressed),
            static_cast<unsigned long long>(st->inv_checks),
            static_cast<unsigned long long>(st->inv_violations),
            static_cast<unsigned long long>(st->cleanup_failures));
  }
}

int attach_watches(mw_ctx_t **ctx, child_t *ch, obs_t *obs,
                   const expect_t *exp) {
  rc_t r = mw_ctx_init(ctx);
  if (r != rc_t::ok) {
    fprintf(stderr, "    FATAL mw_ctx_init failed\n");
    return -1;
  }
  r = mw_attach(*ctx, ch->pid);
  if (r != rc_t::ok) {
    fprintf(stderr, "    FATAL mw_attach: %s\n", mw_strerror(r));
    return -1;
  }
  for (unsigned p = 0; p < exp->pages; ++p) {
    r = mw_watch_add(*ctx,
                     static_cast<uintptr_t>(TGT_BASE) + (p * TGT_PAGE_SIZE),
                     TGT_PAGE_SIZE, obs_cb, obs);
    if (r != rc_t::ok) {
      fprintf(stderr, "    FATAL mw_watch_add(page %u): %s\n", p,
              mw_strerror(r));
      return -1;
    }
  }
  return 0;
}

void verify(const char *name, child_t *ch, obs_t *obs, const expect_t *exp,
            const mw_stats_t *st) {
  ctl_t *c = ch->ctl;
  uint32_t iters = __atomic_load_n(&c->total_iters, __ATOMIC_SEQ_CST);

  if (exp->total_iters != 0U) {
    CHECK(iters == exp->total_iters, "%s: target performed %u accesses, "
          "expected %u", name, iters, exp->total_iters);
    CHECK(obs->events == static_cast<uint64_t>(iters),
          "%s: %llu events for %u accesses", name,
          static_cast<unsigned long long>(obs->events), iters);
  }
  for (unsigned p = 0; p < exp->pages; ++p) {
    uint32_t pi = __atomic_load_n(&c->page_iters[p], __ATOMIC_SEQ_CST);
    if (pi != 0U) {
      CHECK(obs->per_page[p] == static_cast<uint64_t>(pi),
            "%s: page %u got %llu events for %u accesses", name, p,
            static_cast<unsigned long long>(obs->per_page[p]), pi);
    }
  }
  /* The target's own data must be intact: these sums are computed after the
   * borrowed thread's registers were overwritten with syscall arguments. */
  for (unsigned k = 0; k < 8U; ++k) {
    if (exp->sums[k] != 0U) {
      uint64_t got = __atomic_load_n(&c->sums[k], __ATOMIC_SEQ_CST);
      CHECK(got == exp->sums[k], "%s: thread %u checksum %llu, expected %llu",
            name, k, static_cast<unsigned long long>(got),
            static_cast<unsigned long long>(exp->sums[k]));
    }
  }
  if (exp->nthreads != 0U) {
    uint32_t nt = __atomic_load_n(&c->nthreads, __ATOMIC_SEQ_CST);
    CHECK(nt == exp->nthreads, "%s: target created %u threads, expected %u",
          name, nt, exp->nthreads);
  }
  for (unsigned k = 0; k < 8U; ++k) {
    if (exp->sig_counts[k] != 0U) {
      uint32_t got = __atomic_load_n(&c->sig_counts[k], __ATOMIC_SEQ_CST);
      CHECK(got == exp->sig_counts[k], "%s: signal slot %u seen %u times, "
            "expected %u", name, k, got, exp->sig_counts[k]);
    }
  }
  {
    uint32_t sv = __atomic_load_n(&c->segv_seen, __ATOMIC_SEQ_CST);
    CHECK(sv == exp->segv_seen, "%s: target handler saw %u SIGSEGV(s), "
          "expected %u", name, sv, exp->segv_seen);
  }
  CHECK(__atomic_load_n(&c->corrupt, __ATOMIC_SEQ_CST) == 0U,
        "%s: target reported corruption", name);

  /* The invariants observed from inside the callback. */
  CHECK(obs->running_violations == 0, "%s: memwatch believed a target thread "
        "was running inside a critical section", name);
  CHECK(obs->proc_running_violations == 0, "%s: /proc showed a running target "
        "thread while memwatch was in a critical section", name);
  CHECK(obs->state_violations == 0, "%s: callback was not run in the global "
        "critical section", name);
  CHECK(obs->prot_violations == 0, "%s: watched page was not PROT_NONE while "
        "armed", name);
  CHECK(obs->ownership_violations == 0, "%s: ownership violations", name);
  CHECK(obs->cb_errors == 0, "%s: callback received a non-owned fault", name);
  CHECK(obs->checks > 0, "%s: the kernel cross-check never ran", name);

  if (st != nullptr) {
    CHECK(st->inv_violations == 0, "%s: internal invariant violations", name);
    CHECK(st->cleanup_failures == 0, "%s: cleanup failures", name);
    CHECK(st->faults_owned == obs->events, "%s: owned faults(%llu) != "
          "events(%llu)", name, static_cast<unsigned long long>(st->faults_owned),
          static_cast<unsigned long long>(obs->events));
    CHECK(st->ssteps == obs->events, "%s: single steps(%llu) != events(%llu)",
          name, static_cast<unsigned long long>(st->ssteps),
          static_cast<unsigned long long>(obs->events));
    /* one remote mprotect to release ownership + one to re-arm, per fault. */
    CHECK(st->remote_calls >= 2U * obs->events, "%s: only %llu remote calls "
          "for %llu events", name,
          static_cast<unsigned long long>(st->remote_calls),
          static_cast<unsigned long long>(obs->events));
    CHECK(st->remote_sys_fail == 0, "%s: remote syscalls failed", name);
  }
}

int run_basic(const char *name, target_fn fn, const expect_t *exp) {
  child_t ch;
  mw_ctx_t *ctx = nullptr;
  obs_t obs;
  mw_stats_t st;
  rc_t r;
  int rc = 0;
  int fail0 = g_failures;

  (void)memset(&obs, 0, sizeof obs);
  (void)memset(&st, 0, sizeof st);
  if (!spawn_child(&ch, fn)) {
    fprintf(stderr, "    FATAL could not spawn the target\n");
    ++g_failures;
    return -1;
  }
  wait_flag(ch.ctl, &ch.ctl->ready, 1U, 5000);
  if (attach_watches(&ctx, &ch, &obs, exp) != 0) {
    kill_child(&ch);
    if (ctx != nullptr) {
      (void)mw_ctx_free(ctx);
    }
    ++g_failures;
    return -1;
  }
  __atomic_store_n(&ch.ctl->go, 1U, __ATOMIC_SEQ_CST);

  r = pump_done(ctx, ch.ctl, 120000);
  if (r != rc_t::ok) {
    ++g_failures;
    rc = -1;
  }
  (void)drain_quiet(ctx, 300);
  (void)mw_get_stats(ctx, &st);
  verify(name, &ch, &obs, exp, &st);

  {
    char perms[5];
    r = mw_detach(ctx);
    CHECK(r == rc_t::ok, "%s: detach returned %s", name, mw_strerror(r));
    CHECK(proc_perms(ch.pid, static_cast<uintptr_t>(TGT_BASE), perms),
          "%s: could not read the target's maps", name);
    CHECK(std::memcmp(perms, "rw-p", 4) == 0,
          "%s: protection not restored by detach (%s)", name, perms);
  }

  /* The target must survive the tracer untouched and exit cleanly. */
  __atomic_store_n(&ch.ctl->quit, 1U, __ATOMIC_SEQ_CST);
  {
    int status = 0;
    uint64_t deadline = now_ms() + 10000ULL;
    for (;;) {
      pid_t w = waitpid(ch.pid, &status, WNOHANG);
      if (w == ch.pid) {
        break;
      }
      if (w < 0) {
        fprintf(stderr, "    FAIL %s: waitpid failed\n", name);
        ++g_failures;
        rc = -1;
        break;
      }
      if (now_ms() > deadline) {
        fprintf(stderr, "    FAIL %s: target did not exit\n", name);
        ++g_failures;
        rc = -1;
        break;
      }
      (void)usleep(1000);
    }
    if (rc == 0) {
      CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "%s: target exited with status 0x%x", name, status);
    }
  }
  ch.pid = 0;
  (void)mw_ctx_free(ctx);
  report(name, &obs, &st, fail0);
  return rc;
}

/* ------------------------------------------------------------------ cases */

int case_a(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  e.total_iters = 300;
  e.sums[0] = sum_to(300);
  return run_basic("A write/single-thread", tgt_a, &e);
}

int case_b(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  e.total_iters = 300;
  e.sums[0] = PAT * 300ULL;
  return run_basic("B read/single-thread", tgt_b, &e);
}

int case_c(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  e.total_iters = 600;
  e.nthreads = 4;
  for (unsigned k = 0; k < 4U; ++k) {
    e.sums[k] = sum_to(150);
  }
  return run_basic("C mt/shared-page", tgt_c, &e);
}

int case_c_stress(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 2;
  e.total_iters = 720;
  e.nthreads = 6;
  for (unsigned k = 0; k < 6U; ++k) {
    e.sums[k] = sum_to(120);
  }
  return run_basic("C' mt/shared-page+pages", tgt_c_stress, &e);
}

int case_d(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 3;
  e.total_iters = 300;
  e.sums[0] = sum_to(300);
  return run_basic("D multi-page", tgt_d, &e);
}

int case_e(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  e.total_iters = 360;
  e.nthreads = 5;
  e.sums[0] = 4ULL * sum_to(29); /* main: 4 rounds of j = 0..29 */
  for (unsigned k = 1; k < 5U; ++k) {
    e.sums[k] = sum_to(60);
  }
  return run_basic("E thread-create-while-armed", tgt_e, &e);
}

int case_f(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  e.total_iters = 280;
  e.nthreads = 9;
  for (unsigned k = 0; k < 8U; ++k) {
    e.sums[k] = sum_to(25);
  }
  return run_basic("F thread-destroy-while-armed", tgt_f, &e);
}

int case_g(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  e.total_iters = 200;
  e.segv_seen = 1;
  return run_basic("G unrelated-SIGSEGV", tgt_g, &e);
}

int case_h(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  e.total_iters = 2000;
  e.sums[0] = sum_to(2000);
  return run_basic("H repeated-faults", tgt_h, &e);
}

int case_m(void) {
  expect_t e;
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  e.total_iters = 200;
  e.sig_counts[0] = 1; /* SIGBUS  */
  e.sig_counts[1] = 1; /* SIGILL  */
  e.sig_counts[2] = 1; /* SIGTRAP */
  e.sig_counts[3] = 1; /* SIGUSR1 */
  e.sig_counts[4] = 1; /* SIGFPE  */
  return run_basic("M signal-forwarding", tgt_m, &e);
}

int case_k(void) {
  child_t ch;
  mw_ctx_t *ctx = nullptr;
  obs_t obs;
  mw_stats_t st;
  rc_t r = rc_t::err_timeout;
  bool saw_gone = false;
  uint64_t deadline;

  (void)memset(&obs, 0, sizeof obs);
  (void)memset(&st, 0, sizeof st);
  if (!spawn_child(&ch, tgt_k)) {
    ++g_failures;
    return -1;
  }
  wait_flag(ch.ctl, &ch.ctl->ready, 1U, 5000);
  {
    expect_t e;
    (void)memset(&e, 0, sizeof e);
    e.pages = 1;
    if (attach_watches(&ctx, &ch, &obs, &e) != 0) {
      kill_child(&ch);
      ++g_failures;
      return -1;
    }
  }
  __atomic_store_n(&ch.ctl->go, 1U, __ATOMIC_SEQ_CST);

  deadline = now_ms() + 30000ULL;
  while (now_ms() < deadline) {
    r = mw_poll(ctx, 50);
    if (r == rc_t::err_gone) {
      saw_gone = true;
      break;
    }
    if (r != rc_t::ok && r != rc_t::err_timeout) {
      fprintf(stderr, "    FAIL K: poll returned %s\n", mw_strerror(r));
      ++g_failures;
      break;
    }
  }
  CHECK(saw_gone, "K: the target exit was never reported (last=%s)",
        mw_strerror(r));
  (void)mw_get_stats(ctx, &st);
  CHECK(st.inv_violations == 0, "K: invariant violations");
  CHECK(obs.running_violations == 0, "K: running threads during callbacks");
  CHECK(obs.ownership_violations == 0, "K: ownership violations");
  {
    uint32_t iters = __atomic_load_n(&ch.ctl->total_iters, __ATOMIC_SEQ_CST);
    CHECK(obs.events == static_cast<uint64_t>(iters),
          "K: %llu events for %u accesses",
          static_cast<unsigned long long>(obs.events), iters);
  }
  {
    /* memwatch is the target's parent and reaps the death itself, so the wait
     * status has to come from memwatch: a waitpid() here would only return
     * ECHILD. */
    int status = 0;
    CHECK(mw_target_exit(ctx, &status), "K: the exit status was not recorded");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7,
          "K: target exited with status 0x%x", status);
    {
      pid_t expect = ch.pid;
      int wstatus = 0;
      pid_t w = waitpid(expect, &wstatus, WNOHANG);
      ch.pid = 0;
      CHECK(w < 0 && errno == ECHILD,
            "K: waitpid(%d) returned %d instead of ECHILD", expect, w);
    }
  }
  {
    rc_t d = mw_detach(ctx);
    CHECK(d == rc_t::err_gone || d == rc_t::ok, "K: detach returned %s",
          mw_strerror(d));
  }
  (void)mw_ctx_free(ctx);
  return 0;
}

int case_i(void) {
  child_t ch;
  mw_ctx_t *ctx = nullptr;
  obs_t obs;
  mw_stats_t st;
  uintptr_t base = static_cast<uintptr_t>(TGT_BASE);
  bool stop = false;
  rc_t r;

  (void)memset(&obs, 0, sizeof obs);
  (void)memset(&st, 0, sizeof st);
  if (!spawn_child(&ch, tgt_loop)) {
    ++g_failures;
    return -1;
  }
  wait_flag(ch.ctl, &ch.ctl->ready, 1U, 5000);
  r = mw_ctx_init(&ctx);
  CHECK(r == rc_t::ok, "I: ctx init");
  r = mw_attach(ctx, ch.pid);
  CHECK(r == rc_t::ok, "I: attach: %s", mw_strerror(r));
  __atomic_store_n(&ch.ctl->go, 1U, __ATOMIC_SEQ_CST);

  /* argument validation */
  CHECK(mw_watch_add(ctx, base, 0, obs_cb, &obs) == rc_t::err_invalid,
        "I: a zero-length watch was accepted");
  CHECK(mw_watch_add(ctx, base, TGT_PAGE_SIZE, nullptr, &obs) ==
            rc_t::err_invalid,
        "I: a null callback was accepted");

  /* a two-page watch, then everything that overlaps it must be refused */
  r = mw_watch_add(ctx, base, 2U * TGT_PAGE_SIZE, obs_cb, &obs);
  CHECK(r == rc_t::ok, "I: two-page watch_add: %s", mw_strerror(r));
  CHECK(mw_watch_add(ctx, base, TGT_PAGE_SIZE, obs_cb, &obs) ==
            rc_t::err_already,
        "I: a watch inside another watch was accepted");
  CHECK(mw_watch_add(ctx, base + TGT_PAGE_SIZE, TGT_PAGE_SIZE, obs_cb, &obs) ==
            rc_t::err_already,
        "I: a watch overlapping the last page was accepted");
  CHECK(mw_watch_add(ctx, base + TGT_PAGE_SIZE / 2, TGT_PAGE_SIZE, obs_cb,
                     &obs) == rc_t::err_already,
        "I: a misaligned overlapping watch was accepted");
  CHECK(mw_watch_del(ctx, base, TGT_PAGE_SIZE) == rc_t::err_not_found,
        "I: deleting a watch that does not exist did not report not-found");
  r = mw_watch_del(ctx, base, 2U * TGT_PAGE_SIZE);
  CHECK(r == rc_t::ok, "I: two-page watch_del: %s", mw_strerror(r));

  /* arm for real */
  r = mw_watch_add(ctx, base, TGT_PAGE_SIZE, obs_cb, &obs);
  CHECK(r == rc_t::ok, "I: watch_add: %s", mw_strerror(r));
  CHECK(mw_watch_add(ctx, base, TGT_PAGE_SIZE, obs_cb, &obs) ==
            rc_t::err_already,
        "I: a duplicate watch was accepted");

  (void)pump(ctx, 10, 500, &stop);
  CHECK(obs.events > 0, "I: no events while armed");
  {
    uint64_t e1 = obs.events;
    char perms[5];
    CHECK(proc_perms(ch.pid, base, perms) &&
              std::memcmp(perms, "---p", 4) == 0,
          "I: the page is not PROT_NONE while armed (%s)", perms);

    /* deleting the watch must stop the events and restore the protection */
    r = mw_watch_del(ctx, base, TGT_PAGE_SIZE);
    CHECK(r == rc_t::ok, "I: watch_del: %s", mw_strerror(r));
    CHECK(proc_perms(ch.pid, base, perms) &&
              std::memcmp(perms, "rw-p", 4) == 0,
          "I: the protection was not restored by watch_del (%s)", perms);
    (void)pump(ctx, 10, 400, &stop);
    CHECK(obs.events == e1, "I: %llu events after the watch was deleted",
          static_cast<unsigned long long>(obs.events - e1));

    /* and re-arming must work again */
    r = mw_watch_add(ctx, base, TGT_PAGE_SIZE, obs_cb, &obs);
    CHECK(r == rc_t::ok, "I: re-arm: %s", mw_strerror(r));
    (void)pump(ctx, 10, 500, &stop);
    CHECK(obs.events > e1, "I: no events after re-arming");

    r = mw_watch_del_all(ctx);
    CHECK(r == rc_t::ok, "I: watch_del_all: %s", mw_strerror(r));
    (void)pump(ctx, 10, 300, &stop);
    CHECK(proc_perms(ch.pid, base, perms) &&
              std::memcmp(perms, "rw-p", 4) == 0,
          "I: the protection was not restored by del_all (%s)", perms);
    {
      uint64_t e2 = obs.events;
      (void)pump(ctx, 10, 300, &stop);
      CHECK(obs.events == e2, "I: %llu events after del_all",
            static_cast<unsigned long long>(obs.events - e2));
    }
  }

  (void)mw_get_stats(ctx, &st);
  CHECK(st.inv_violations == 0, "I: invariant violations");
  CHECK(st.cleanup_failures == 0, "I: cleanup failures");
  CHECK(obs.running_violations == 0, "I: running threads during callbacks");
  CHECK(obs.state_violations == 0, "I: callback outside the critical section");
  CHECK(obs.ownership_violations == 0, "I: ownership violations");
  {
    uint32_t iters = __atomic_load_n(&ch.ctl->total_iters, __ATOMIC_SEQ_CST);
    CHECK(obs.events > 0, "I: no events at all");
    /* The loop target was already running while the watch was armed, so only
     * "no more events than accesses" can be claimed here; the strict
     * one-event-per-access proof is what cases A-H are for. */
    CHECK(obs.events <= static_cast<uint64_t>(iters),
          "I: %llu events for %u accesses",
          static_cast<unsigned long long>(obs.events), iters);
    CHECK(obs.per_page[0] <= static_cast<uint64_t>(iters),
          "I: %llu page events for %u accesses",
          static_cast<unsigned long long>(obs.per_page[0]), iters);
  }

  {
    rc_t d = mw_detach(ctx);
    CHECK(d == rc_t::ok, "I: detach returned %s", mw_strerror(d));
  }
  __atomic_store_n(&ch.ctl->quit, 1U, __ATOMIC_SEQ_CST);
  kill_child(&ch);
  (void)mw_ctx_free(ctx);
  return 0;
}

int case_j(void) {
  child_t ch;
  mw_ctx_t *ctx = nullptr;
  obs_t obs;
  expect_t e;
  rc_t r;
  bool stop = false;
  char perms[5];
  uint32_t it1 = 0;
  uint32_t it2 = 0;
  int status = 0;

  (void)memset(&obs, 0, sizeof obs);
  (void)memset(&e, 0, sizeof e);
  e.pages = 1;
  if (!spawn_child(&ch, tgt_loop)) {
    ++g_failures;
    return -1;
  }
  wait_flag(ch.ctl, &ch.ctl->ready, 1U, 5000);
  if (attach_watches(&ctx, &ch, &obs, &e) != 0) {
    kill_child(&ch);
    ++g_failures;
    return -1;
  }
  __atomic_store_n(&ch.ctl->go, 1U, __ATOMIC_SEQ_CST);
  (void)pump(ctx, 10, 500, &stop);
  CHECK(obs.events > 0, "J: no events before detach");

  r = mw_detach(ctx);
  CHECK(r == rc_t::ok, "J: detach returned %s", mw_strerror(r));
  CHECK(proc_perms(ch.pid, static_cast<uintptr_t>(TGT_BASE), perms),
        "J: could not read the target's maps after detach");
  CHECK(std::memcmp(perms, "rw-p", 4) == 0,
        "J: the protection was not restored by detach (%s)", perms);

  /* the target must keep running, and must not be killed by detach */
  it1 = __atomic_load_n(&ch.ctl->total_iters, __ATOMIC_SEQ_CST);
  (void)usleep(300000);
  it2 = __atomic_load_n(&ch.ctl->total_iters, __ATOMIC_SEQ_CST);
  CHECK(it2 > it1, "J: the target stopped progressing after detach (%u -> %u)",
        it1, it2);
  {
    pid_t w = waitpid(ch.pid, &status, WNOHANG);
    CHECK(w == 0, "J: the target died after detach (status=0x%x)", status);
  }
  __atomic_store_n(&ch.ctl->quit, 1U, __ATOMIC_SEQ_CST);
  kill_child(&ch);
  (void)mw_ctx_free(ctx);
  return 0;
}

int case_l_range(void) {
  child_t ch;
  mw_ctx_t *ctx = nullptr;
  obs_t obs;
  rc_t r;

  (void)memset(&obs, 0, sizeof obs);
  if (!spawn_child(&ch, tgt_l3)) {
    ++g_failures;
    return -1;
  }
  wait_flag(ch.ctl, &ch.ctl->ready, 1U, 5000);
  r = mw_ctx_init(&ctx);
  CHECK(r == rc_t::ok, "L: ctx init");
  r = mw_attach(ctx, ch.pid);
  CHECK(r == rc_t::ok, "L: attach: %s", mw_strerror(r));

  /* page 1 is a hole, so the watch must be refused */
  r = mw_watch_add(ctx, static_cast<uintptr_t>(TGT_BASE), 2U * TGT_PAGE_SIZE,
                   obs_cb, &obs);
  CHECK(r == rc_t::err_range, "L: a watch over a hole returned %s",
        mw_strerror(r));
  {
    char perms[5];
    CHECK(proc_perms(ch.pid, static_cast<uintptr_t>(TGT_BASE), perms) &&
              std::memcmp(perms, "rw-p", 4) == 0,
          "L: the refused watch still changed the mapping (%s)", perms);
  }
  /* a valid watch must still work afterwards */
  r = mw_watch_add(ctx, static_cast<uintptr_t>(TGT_BASE), TGT_PAGE_SIZE,
                   obs_cb, &obs);
  CHECK(r == rc_t::ok, "L: a valid watch after a refused one: %s",
        mw_strerror(r));
  r = mw_watch_del(ctx, static_cast<uintptr_t>(TGT_BASE), TGT_PAGE_SIZE);
  CHECK(r == rc_t::ok, "L: watch_del: %s", mw_strerror(r));
  r = mw_detach(ctx);
  CHECK(r == rc_t::ok, "L: detach returned %s", mw_strerror(r));
  __atomic_store_n(&ch.ctl->go, 1U, __ATOMIC_SEQ_CST);
  __atomic_store_n(&ch.ctl->quit, 1U, __ATOMIC_SEQ_CST);
  kill_child(&ch);
  (void)mw_ctx_free(ctx);
  return 0;
}

int case_l_mprotect_failure(void) {
  child_t ch;
  mw_ctx_t *ctx = nullptr;
  obs_t obs;
  rc_t r;
  bool stop = false;

  (void)memset(&obs, 0, sizeof obs);
  if (!spawn_child(&ch, tgt_l2)) {
    ++g_failures;
    return -1;
  }
  wait_flag(ch.ctl, &ch.ctl->ready, 1U, 5000);
  r = mw_ctx_init(&ctx);
  CHECK(r == rc_t::ok, "L2: ctx init");
  r = mw_attach(ctx, ch.pid);
  CHECK(r == rc_t::ok, "L2: attach: %s", mw_strerror(r));
  r = mw_watch_add(ctx, static_cast<uintptr_t>(TGT_BASE), 4U * TGT_PAGE_SIZE,
                   obs_cb, &obs);
  CHECK(r == rc_t::ok, "L2: arm four pages: %s", mw_strerror(r));
  __atomic_store_n(&ch.ctl->go, 1U, __ATOMIC_SEQ_CST);
  (void)pump(ctx, 10, 2000, &stop);
  CHECK(__atomic_load_n(&ch.ctl->done, __ATOMIC_SEQ_CST) == 1U,
        "L2: the target never unmapped its hole");

  /* Restoring the protection must now fail loudly, and memwatch must not
   * pretend it succeeded: the watch can no longer represent reality. */
  r = mw_watch_del(ctx, static_cast<uintptr_t>(TGT_BASE), 4U * TGT_PAGE_SIZE);
  CHECK(r == rc_t::err_mprotect, "L2: watch_del over a hole returned %s",
        mw_strerror(r));
  r = mw_watch_add(ctx, static_cast<uintptr_t>(TGT_BASE), TGT_PAGE_SIZE,
                   obs_cb, &obs);
  CHECK(r == rc_t::err_poisoned, "L2: watch_add after an unrestorable watch "
        "returned %s", mw_strerror(r));
  r = mw_poll(ctx, 10);
  CHECK(r == rc_t::err_poisoned, "L2: mw_poll after an unrestorable watch "
        "returned %s", mw_strerror(r));
  __atomic_store_n(&ch.ctl->quit, 1U, __ATOMIC_SEQ_CST);
  kill_child(&ch);
  (void)mw_ctx_free(ctx);
  return 0;
}

struct case_t {
  const char *name;
  int (*fn)(void);
};

const case_t g_cases[] = {
    {"A single-thread repeated writes", case_a},
    {"B single-thread repeated reads", case_b},
    {"C multiple threads, one watched page", case_c},
    {"D multiple watched pages", case_d},
    {"E thread creation while armed", case_e},
    {"F thread destruction while armed", case_f},
    {"G unrelated SIGSEGV forwarded", case_g},
    {"H repeated faults", case_h},
    {"I watch add/delete while running", case_i},
    {"J detach while the target is alive", case_j},
    {"K target exit during monitoring", case_k},
    {"L range validation over a hole", case_l_range},
    {"L remote mprotect failure path", case_l_mprotect_failure},
    {"M non-watch signal forwarding", case_m},
};

} /* namespace */

int main(int argc, char **argv) {
  const size_t ncases = sizeof g_cases / sizeof g_cases[0];
  size_t i;
  int round;

  for (int a = 1; a < argc; ++a) {
    if (std::strncmp(argv[a], "--stress", 8) == 0) {
      g_stress_rounds = ((a + 1) < argc) ? atoi(argv[a + 1]) : 10;
      if (g_stress_rounds < 1) {
        g_stress_rounds = 1;
      }
      ++a;
    } else if (std::strcmp(argv[a], "--only-stress") == 0) {
      g_stress_only = 1;
    } else if (std::strcmp(argv[a], "-v") == 0) {
      g_verbose = 1;
    } else if (std::strncmp(argv[a], "--only", 6) == 0) {
      g_only = ((a + 1) < argc) ? atoi(argv[a + 1]) : -1;
      g_no_stress = 1;
      ++a;
    }
  }
  log_init();

  if (g_stress_only == 0) {
    for (i = 0; i < ncases; ++i) {
      int before = g_failures;
      int rc;
      if (g_only >= 0 && static_cast<int>(i) != g_only) {
        continue;
      }
      printf("[ RUN  ] %s\n", g_cases[i].name);
      (void)fflush(stdout);
      rc = g_cases[i].fn();
      if (g_failures == before && rc == 0) {
        printf("[  OK  ] %s\n", g_cases[i].name);
      } else {
        printf("[ FAIL ] %s\n", g_cases[i].name);
      }
      (void)fflush(stdout);
    }
  }

  for (round = 0; round < g_stress_rounds; ++round) {
    int before = g_failures;
    if (g_no_stress != 0) {
      break;
    }
    printf("[ RUN  ] stress round %d/%d (6 threads, 2 watched pages)\n",
           round + 1, g_stress_rounds);
    (void)fflush(stdout);
    (void)case_c_stress();
    if (g_failures != before) {
      printf("[ FAIL ] stress round %d\n", round + 1);
      return 1;
    }
    printf("[  OK  ] stress round %d\n", round + 1);
    (void)fflush(stdout);
  }

  printf("\n%s: %d check(s) failed\n", (g_failures == 0) ? "PASS" : "FAIL",
         g_failures);
  return (g_failures == 0) ? 0 : 1;
}