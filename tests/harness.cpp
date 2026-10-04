#include "harness.hpp"

#include <cerrno>
#include <cstdlib>
#include <csignal>
#include <csetjmp>
#include <dirent.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int g_failures = 0;
ctl_t   *g_child_ctl = nullptr;
int      g_verbose = 0;

static void verbose_log(const char *msg) {
  if (g_verbose != 0) {
    fprintf(stderr, "        [mw] %s\n", msg);
  }
}

void log_init(void) { mw_log_set(verbose_log); }

uint64_t now_ms(void) {
  struct timespec ts;
  (void)clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000ULL +
         static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
}

/* ------------------------------------------------------------ child side */

void wait_go(ctl_t *c) {
  while (__atomic_load_n(&c->go, __ATOMIC_SEQ_CST) == 0U) {
    sched_yield();
  }
}

void wait_quit(ctl_t *c) {
  while (__atomic_load_n(&c->quit, __ATOMIC_SEQ_CST) == 0U) {
    sched_yield();
  }
}

void child_map(ctl_t *c, unsigned npages) {
  void *p = mmap(reinterpret_cast<void *>(static_cast<uintptr_t>(TGT_BASE)),
                 static_cast<size_t>(npages) * TGT_PAGE_SIZE,
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p != reinterpret_cast<void *>(static_cast<uintptr_t>(TGT_BASE))) {
    fprintf(stderr, "child: mmap at TGT_BASE failed: %s\n", strerror(errno));
    _exit(97);
  }
  (void)memset(p, 0, static_cast<size_t>(npages) * TGT_PAGE_SIZE);
  __atomic_store_n(&c->mapped_pages, npages, __ATOMIC_SEQ_CST);
}

void child_ready(ctl_t *c) { __atomic_store_n(&c->ready, 1U, __ATOMIC_SEQ_CST); }

/* The tracer may only attach after this returns, so anything the target wants to
 * have in place before the watch exists (pre-filled pages, holes) must be done
 * before ready is raised. */
void child_prepare(ctl_t *c, unsigned npages) {
  child_map(c, npages);
  child_ready(c);
}

void set_handler(int sig, int sa_flags) {
  struct sigaction sa;
  (void)memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = generic_handler;
  sa.sa_flags = sa_flags | SA_SIGINFO | SA_RESTART;
  (void)sigemptyset(&sa.sa_mask);
  if (sigaction(sig, &sa, nullptr) == -1) {
    fprintf(stderr, "child: sigaction(%d) failed: %s\n", sig, strerror(errno));
    _exit(98);
  }
}

void generic_handler(int sig, siginfo_t *si, void *uc) {
  ctl_t *c = g_child_ctl;
  (void)uc;
  if (c != nullptr) {
    if (sig == SIGSEGV) {
      __atomic_add_fetch(&c->segv_seen, 1U, __ATOMIC_SEQ_CST);
      __atomic_store_n(&c->segv_addr,
                       static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
                           si != nullptr ? si->si_addr : nullptr)),
                       __ATOMIC_SEQ_CST);
      return;
    }
    {
      int idx = -1;
      if (sig == SIGBUS) {
        idx = 0;
      } else if (sig == SIGILL) {
        idx = 1;
      } else if (sig == SIGTRAP) {
        idx = 2;
      } else if (sig == SIGUSR1) {
        idx = 3;
      } else if (sig == SIGFPE) {
        idx = 4;
      }
      if (idx >= 0 && idx < 8) {
        __atomic_add_fetch(&c->sig_counts[idx], 1U, __ATOMIC_SEQ_CST);
      }
    }
  }
}

bool spawn_child(child_t *ch, target_fn fn) {
  ctl_t *c = static_cast<ctl_t *>(
      mmap(nullptr, sizeof(ctl_t), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0));
  pid_t pid;
  if (c == MAP_FAILED) {
    return false;
  }
  (void)memset(c, 0, sizeof *c);
  pid = fork();
  if (pid < 0) {
    return false;
  }
  if (pid == 0) {
    g_child_ctl = c;
    fn(c);
    __atomic_store_n(&c->child_exit, 0U, __ATOMIC_SEQ_CST);
    _exit(0);
  }
  ch->pid = pid;
  ch->ctl = c;
  return true;
}

void kill_child(child_t *ch) {
  int status = 0;
  if (ch->pid > 0) {
    (void)kill(ch->pid, SIGKILL);
    (void)waitpid(ch->pid, &status, 0);
    ch->pid = 0;
  }
}

void wait_flag(const ctl_t *c, const uint32_t *field, uint32_t v,
               int timeout_ms) {
  uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms);
  while (__atomic_load_n(field, __ATOMIC_SEQ_CST) != v) {
    if (now_ms() > deadline) {
      fprintf(stderr, "    FATAL timeout waiting for flag %u (ctl=%p)\n", v,
              static_cast<const void *>(c));
      ++g_failures;
      return;
    }
    sched_yield();
  }
}

/* ------------------------------------------------------------- procfs view */

int proc_running_threads(pid_t pid) {
  char path[320];
  DIR *d;
  struct dirent *de;
  int bad = 0;
  (void)snprintf(path, sizeof path, "/proc/%d/task", pid);
  d = opendir(path);
  if (d == nullptr) {
    return 0;
  }
  while ((de = readdir(d)) != nullptr) {
    char line[512];
    char *p;
    FILE *f;
    if (de->d_name[0] == '.') {
      continue;
    }
    (void)snprintf(path, sizeof path, "/proc/%d/task/%s/stat", pid,
                   de->d_name);
    f = fopen(path, "r");
    if (f == nullptr) {
      continue;
    }
    if (fgets(line, sizeof line, f) == nullptr) {
      (void)fclose(f);
      continue;
    }
    (void)fclose(f);
    p = strrchr(line, ')');
    if (p == nullptr) {
      continue;
    }
    ++p;
    while (*p == ' ') {
      ++p;
    }
    if (*p == 'R' || *p == 'D') {
      ++bad;
    }
  }
  (void)closedir(d);
  return bad;
}

bool proc_perms(pid_t pid, uintptr_t addr, char out[5]) {
  char path[64];
  char line[1024];
  FILE *f;
  bool found = false;
  (void)snprintf(path, sizeof path, "/proc/%d/maps", pid);
  f = fopen(path, "r");
  if (f == nullptr) {
    return false;
  }
  while (fgets(line, sizeof line, f) != nullptr) {
    unsigned long lo = 0;
    unsigned long hi = 0;
    char perms[8];
    if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3) {
      continue;
    }
    if (addr >= static_cast<uintptr_t>(lo) &&
        addr < static_cast<uintptr_t>(hi)) {
      (void)memcpy(out, perms, 4);
      out[4] = '\0';
      found = true;
      break;
    }
  }
  (void)fclose(f);
  return found;
}

long page_index(uintptr_t addr) {
  if (addr < static_cast<uintptr_t>(TGT_BASE)) {
    return -1;
  }
  return static_cast<long>((addr - static_cast<uintptr_t>(TGT_BASE)) /
                           TGT_PAGE_SIZE);
}

/* ------------------------------------------------------- watch callback */

/* Runs inside the tracer with every target thread stopped.  Every check below
 * is an observation of the real kernel state, not of memwatch's own opinion. */
rc_t obs_cb(mw_ctx_t *ctx, mw_watch_t *w, mw_fault_t *f) {
  obs_t *o = static_cast<obs_t *>(w->ud);
  long idx;
  if (o == nullptr) {
    return rc_t::ok;
  }
  ++o->events;
  if (!f->owned || f->watch == nullptr) {
    ++o->cb_errors;
  }
  if (f->addr < w->r.base || (f->addr - w->r.base) >= w->r.size) {
    ++o->ownership_violations;
  }
  if (!w->armed) {
    /* The ownership guard must be set while the callback runs. */
    ++o->ownership_violations;
  }
  idx = page_index(f->p.addr);
  if (idx >= 0 && idx < TGT_MAX_PAGES) {
    ++o->per_page[idx];
  }

  /* Invariant 1: the state machine must be in the global critical section. */
  if (mw_get_state(ctx) != mw_state_t::critical) {
    ++o->state_violations;
  }

  /* Invariant 1: zero target user threads execute during the callback. */
  if (mw_threads_running(ctx) != 0) {
    ++o->running_violations;
  }

  /* Cross-check against the kernel, and check that PROT_NONE is really there. */
  if ((o->events % 8U) == 1U) {
    char perms[5];
    ++o->checks;
    if (proc_running_threads(ctx->pid) != 0) {
      ++o->proc_running_violations;
    }
    if (!proc_perms(ctx->pid, f->p.addr, perms) ||
        std::memcmp(perms, "---p", 4) != 0) {
      ++o->prot_violations;
    }
  }
  return rc_t::ok;
}

/* ------------------------------------------------------------- event loop */

rc_t pump(mw_ctx_t *ctx, int slice_ms, int total_ms, bool *stop) {
  uint64_t deadline = now_ms() + static_cast<uint64_t>(total_ms);
  *stop = false;
  for (;;) {
    rc_t r;
    /* The deadline is checked every pass, not only after a quiet poll: a
     * target that faults continuously never lets mw_poll() time out, and this
     * pump is bounded by wall time. */
    if (now_ms() >= deadline) {
      *stop = true;
      return rc_t::ok;
    }
    r = mw_poll(ctx, slice_ms);
    if (r == rc_t::ok || r == rc_t::err_timeout) {
      continue;
    }
    return r;
  }
}

/* Pump until the target reports that it finished its work, or the deadline. */
rc_t pump_done(mw_ctx_t *ctx, const ctl_t *c, int timeout_ms) {
  uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms);
  for (;;) {
    rc_t r;
    if (__atomic_load_n(&c->done, __ATOMIC_SEQ_CST) == 1U) {
      return rc_t::ok;
    }
    if (now_ms() >= deadline) {
      fprintf(stderr, "    FAIL target did not finish within %d ms\n",
              timeout_ms);
      return rc_t::err_timeout;
    }
    r = mw_poll(ctx, 20);
    if (r != rc_t::ok && r != rc_t::err_timeout) {
      fprintf(stderr, "    FAIL pump returned %s\n", mw_strerror(r));
      return r;
    }
  }
}

int drain_quiet(mw_ctx_t *ctx, int quiet_ms) {
  uint64_t deadline = now_ms() + static_cast<uint64_t>(quiet_ms);
  uint64_t last = now_ms();
  for (;;) {
    rc_t r = mw_poll(ctx, 10);
    if (r == rc_t::ok) {
      last = now_ms();
      continue;
    }
    if (r != rc_t::err_timeout) {
      return -1;
    }
    if (now_ms() - last >= static_cast<uint64_t>(quiet_ms) ||
        now_ms() >= deadline + 2000ULL) {
      return 0;
    }
  }
}
