/* libmemwatch test harness: shared control block, child spawning and the
 * invariant-checking watch callback. */
#ifndef MWTEST_HARNESS_HPP
#define MWTEST_HARNESS_HPP

#include "memwatch/api.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define TGT_PAGE_SIZE 4096UL
#define TGT_BASE 0x0000600000000000UL
#define TGT_MAX_PAGES 8

/* Shared (MAP_SHARED) control block between the tracer (parent) and the target
 * (child).  All accesses use __atomic so the worker threads in the target stay
 * consistent with the tracer. */
struct ctl_t {
  uint32_t ready;
  uint32_t go;
  uint32_t done;
  uint32_t quit;
  uint32_t mapped_pages;
  uint32_t corrupt;
  uint32_t segv_seen;
  uint64_t segv_addr;
  uint32_t nthreads;
  uint32_t sig_counts[8];
  uint32_t page_iters[TGT_MAX_PAGES];
  uint32_t total_iters;
  uint64_t sums[8];
  uint32_t iters_per_thread[8];
  uint32_t child_exit;
  uint32_t unused;
  /* For SKIP-style tests: fault/resume targets written by asm in child. */
  uint64_t skip_fault;
  uint64_t skip_resume;
  uint32_t skip_next;
};

typedef void (*target_fn)(ctl_t *c);

struct child_t {
  pid_t   pid;
  ctl_t *ctl;
};

/* What the callback observed. */
struct obs_t {
  uint64_t events;
  uint64_t per_page[TGT_MAX_PAGES];
  uint64_t checks;
  uint64_t state_violations;
  uint64_t running_violations;
  uint64_t proc_running_violations;
  uint64_t prot_violations;
  uint64_t ownership_violations;
  uint64_t cb_errors;
};

extern ctl_t *g_child_ctl;

bool      spawn_child(child_t *ch, target_fn fn);
void      kill_child(child_t *ch);
void      wait_flag(const ctl_t *c, const uint32_t *field, uint32_t v,
                    int timeout_ms);
void      child_map(ctl_t *c, unsigned npages);
void      child_ready(ctl_t *c);
void      child_prepare(ctl_t *c, unsigned npages);
void      wait_go(ctl_t *c);
void      wait_quit(ctl_t *c);

int       proc_running_threads(pid_t pid);
bool      proc_perms(pid_t pid, uintptr_t addr, char out[5]);
uint64_t  now_ms(void);
long      page_index(uintptr_t addr);

rc_t      obs_cb(mw_ctx_t *ctx, mw_watch_t *w, mw_fault_t *f);
rc_t      pump(mw_ctx_t *ctx, int slice_ms, int total_ms, bool *stop);
rc_t      pump_done(mw_ctx_t *ctx, const ctl_t *c, int timeout_ms);
int       drain_quiet(mw_ctx_t *ctx, int quiet_ms);
void      set_handler(int sig, int sa_flags);
void      generic_handler(int sig, siginfo_t *si, void *uc);

extern int g_failures;
extern int g_verbose;
void     log_init(void);

#define CHECK(cond, ...)                                                    \
  do {                                                                      \
    if (!(cond)) {                                                          \
      ++g_failures;                                                         \
      fprintf(stderr, "    FAIL %s:%d: ", __FILE__, __LINE__);              \
      fprintf(stderr, __VA_ARGS__);                                         \
      fprintf(stderr, "\n");                                                \
    }                                                                       \
  } while (0)

#define REQUIRE(cond, ...)                                                  \
  do {                                                                      \
    if (!(cond)) {                                                          \
      ++g_failures;                                                         \
      fprintf(stderr, "    FATAL %s:%d: ", __FILE__, __LINE__);             \
      fprintf(stderr, __VA_ARGS__);                                         \
      fprintf(stderr, "\n");                                                \
      return -1;                                                            \
    }                                                                       \
  } while (0)

#endif /* MWTEST_HARNESS_HPP */
