#include "memwatch/internal.hpp"
#include "memwatch/api.hpp"
#include "memwatch/thr.hpp"
#include "memwatch/watch.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>

/* ------------------------------------------------------------------ logging */

static mw_logfn_t g_log_fn = nullptr;

void mw_log_set(mw_logfn_t fn) { g_log_fn = fn; }

void mw_log(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  if (g_log_fn == nullptr) {
    return;
  }
  va_start(ap, fmt);
  (void)vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  g_log_fn(buf);
}

void mw_log_errno(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  int e = errno;
  if (g_log_fn == nullptr) {
    return;
  }
  va_start(ap, fmt);
  (void)vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  (void)snprintf(buf + strlen(buf), sizeof buf - strlen(buf), ": %s",
                 strerror(e));
  g_log_fn(buf);
}

/* -------------------------------------------------------------------- errno */

const char *mw_strerror(rc_t r) {
  switch (r) {
    case rc_t::ok:           return "ok";
    case rc_t::action_skip:   return "action skip (handled/stepped)";
    case rc_t::action_disarm: return "action disarm";
    case rc_t::action_kill:   return "action kill";
    case rc_t::err_attach:   return "ptrace attach/seize failed";
    case rc_t::err_ptrace:   return "ptrace/waitpid failure";
    case rc_t::err_mprotect: return "remote mprotect failed";
    case rc_t::err_proc:     return "procfs/alloc failure";
    case rc_t::err_invalid:  return "invalid argument";
    case rc_t::err_not_found:return "not found";
    case rc_t::err_already:  return "duplicate or overlapping watch";
    case rc_t::err_state:    return "illegal state transition";
    case rc_t::err_unexpected: return "unexpected event in controlled scope";
    case rc_t::err_timeout:  return "timeout";
    case rc_t::err_syscall:  return "remote syscall failed";
    case rc_t::err_stub_write: return "remote stub write/restore failed";
    case rc_t::err_nothread: return "no borrowable thread";
    case rc_t::err_nogadget: return "no syscall gadget in target";
    case rc_t::err_invariant:return "internal invariant violated";
    case rc_t::err_gone:     return "target process exited";
    case rc_t::err_range:    return "bad or unmappable range";
    case rc_t::err_poisoned: return "context poisoned";
  }
  return "unknown";
}

/* ------------------------------------------------------------------ procfs */

int mw_perms_to_prot(const char perms[4]) {
  int prot = 0;
  if (perms[0] == 'r') prot |= PROT_READ;
  if (perms[1] == 'w') prot |= PROT_WRITE;
  if (perms[2] == 'x') prot |= PROT_EXEC;
  return prot;
}

rc_t mw_read_maps(pid_t pid, std::vector<mw_map_t> *out) {
  char path[64];
  char line[1024];
  FILE *f;
  out->clear();
  (void)snprintf(path, sizeof path, "/proc/%d/maps", pid);
  f = fopen(path, "r");
  if (f == nullptr) {
    return (errno == ENOENT) ? rc_t::err_gone : rc_t::err_proc;
  }
  while (fgets(line, sizeof line, f) != nullptr) {
    unsigned long lo = 0;
    unsigned long hi = 0;
    char perms[8];
    mw_map_t m;
    int n = sscanf(line, "%lx-%lx %7s", &lo, &hi, perms);
    if (n < 3) {
      continue;
    }
    m.lo = static_cast<uintptr_t>(lo);
    m.hi = static_cast<uintptr_t>(hi);
    (void)memcpy(m.perms, perms, 4);
    m.perms[4] = '\0';
    m.prot = mw_perms_to_prot(perms);
    {
      const char *sp = strchr(line, '/');
      m.path = (sp != nullptr) ? sp : "";
    }
    out->push_back(m);
  }
  (void)fclose(f);
  return rc_t::ok;
}

rc_t mw_list_tasks(pid_t pid, std::vector<pid_t> *out) {
  char path[64];
  DIR *d;
  struct dirent *de;
  out->clear();
  (void)snprintf(path, sizeof path, "/proc/%d/task", pid);
  d = opendir(path);
  if (d == nullptr) {
    return (errno == ENOENT) ? rc_t::err_gone : rc_t::err_proc;
  }
  while ((de = readdir(d)) != nullptr) {
    char *end = nullptr;
    long v;
    if (de->d_name[0] == '.') {
      continue;
    }
    errno = 0;
    v = strtol(de->d_name, &end, 10);
    if (errno != 0 || end == de->d_name || *end != '\0' || v <= 0) {
      continue;
    }
    out->push_back(static_cast<pid_t>(v));
  }
  (void)closedir(d);
  return rc_t::ok;
}

bool mw_task_alive(pid_t pid, pid_t tid) {
  char path[80];
  (void)snprintf(path, sizeof path, "/proc/%d/task/%d", pid, tid);
  return access(path, F_OK) == 0;
}

char mw_task_state(pid_t pid, pid_t tid) {
  char path[80];
  char line[512];
  FILE *f;
  char *p;
  char st = 0;
  (void)snprintf(path, sizeof path, "/proc/%d/task/%d/stat", pid, tid);
  f = fopen(path, "r");
  if (f == nullptr) {
    return 0;
  }
  if (fgets(line, sizeof line, f) == nullptr) {
    (void)fclose(f);
    return 0;
  }
  (void)fclose(f);
  p = strrchr(line, ')');
  if (p == nullptr) {
    return 0;
  }
  ++p;
  while (*p == ' ') {
    ++p;
  }
  st = *p;
  return st;
}

/* ------------------------------------------------------------------- memory */

ssize_t mw_vm_read(pid_t pid, uintptr_t addr, void *buf, size_t len) {
  struct iovec l;
  struct iovec r;
  l.iov_base = buf;
  l.iov_len = len;
  r.iov_base = reinterpret_cast<void *>(addr);
  r.iov_len = len;
  return process_vm_readv(pid, &l, 1, &r, 1, 0);
}

ssize_t mw_vm_write(pid_t pid, uintptr_t addr, const void *buf, size_t len) {
  struct iovec l;
  struct iovec r;
  l.iov_base = const_cast<void *>(buf);
  l.iov_len = len;
  r.iov_base = reinterpret_cast<void *>(addr);
  r.iov_len = len;
  return process_vm_writev(pid, &l, 1, &r, 1, 0);
}

long mw_ptrace_enter(void) { return 0; }

size_t mw_page_count(uintptr_t base, size_t size, size_t page_size) {
  uintptr_t last;
  if (size == 0) {
    return 0;
  }
  last = base + size - 1U;
  if (last < base) {
    return 0; /* overflow */
  }
  return static_cast<size_t>((last / page_size) - (base / page_size)) + 1U;
}

/* --------------------------------------------------------------- invariants */

static const char *state_name(mw_state_t s) {
  switch (s) {
    case mw_state_t::idle:      return "idle";
    case mw_state_t::entering:  return "entering";
    case mw_state_t::critical:  return "critical";
    case mw_state_t::rcall:     return "rcall";
    case mw_state_t::sstep:     return "sstep";
    case mw_state_t::rearming:  return "rearming";
    case mw_state_t::detaching: return "detaching";
  }
  return "?";
}

rc_t mw_inv_check(mw_ctx_t *ctx, const char *where) {
  size_t running = mw_thr_count_running(ctx);
  bool bad = false;
  const char *why = nullptr;

  ++ctx->stats.inv_checks;

  /* I1: the borrow flags and the rcall state are never dissociated. */
  if (ctx->in_rcall != (ctx->borrow_tid != 0)) {
    bad = true;
    why = "in_rcall != (borrow_tid != 0)";
  }
  if (ctx->in_rcall && ctx->st != mw_state_t::rcall) {
    bad = true;
    why = "in_rcall outside rcall state";
  }

  /* I4: a pending fault exists exactly while a fault is being handled, and
   * that spans the whole sequence: critical (callback), rcall (the remote
   * mprotect that releases ownership), sstep (the single step) and rearming.
   * It must never survive into idle, entering or detaching. */
  if (ctx->have_fault && ctx->fault_watch == nullptr) {
    bad = true;
    why = "have_fault without fault_watch";
  }
  if (ctx->have_fault && ctx->st != mw_state_t::critical &&
      ctx->st != mw_state_t::rcall && ctx->st != mw_state_t::sstep &&
      ctx->st != mw_state_t::rearming) {
    bad = true;
    why = "have_fault outside a fault-handling state";
  }

  switch (ctx->st) {
    case mw_state_t::idle:
    case mw_state_t::detaching:
      break;
    case mw_state_t::entering:
    case mw_state_t::critical:
    case mw_state_t::rearming:
      /* I3: zero target user threads execute. */
      if (running != 0) {
        bad = true;
        why = "target thread running inside a zero-run state";
      }
      break;
    case mw_state_t::rcall:
    case mw_state_t::sstep:
      /* I2: at most one target thread executes, and it is the right one. */
      if (running > 1) {
        bad = true;
        why = "more than one thread running in rcall/sstep";
      } else if (running == 1) {
        thr_t *t = mw_thr_find(ctx, ctx->in_rcall ? ctx->borrow_tid
                                                 : ctx->fault_tid);
        if (t == nullptr || !t->running) {
          bad = true;
          why = "the running thread is not the borrowed/faulting one";
        }
      }
      break;
  }

  if (bad) {
    ++ctx->stats.inv_violations;
    mw_log("INVARIANT VIOLATION at %s (state=%s running=%zu alive=%zu): %s",
           where, state_name(ctx->st), running, mw_thr_count_alive(ctx), why);
    return rc_t::err_invariant;
  }
  return rc_t::ok;
}

void mw_poison(mw_ctx_t *ctx, rc_t why, const char *where) {
  if (!ctx->poisoned) {
    ctx->poisoned = true;
    ctx->poison_rc = why;
    ++ctx->stats.cleanup_failures;
    mw_log("ctx poisoned: %s (%s)", mw_strerror(why), where);
  }
}

void mw_fault_clear(mw_ctx_t *ctx) {
  ctx->have_fault = false;
  ctx->fault_tid = 0;
  ctx->fault_addr = 0;
  ctx->fault_watch = nullptr;
}

/* ------------------------------------------------------------ public helpers */

size_t mw_threads_alive(const mw_ctx_t *ctx) {
  return mw_thr_count_alive(ctx);
}

size_t mw_threads_running(const mw_ctx_t *ctx) {
  return mw_thr_count_running(ctx);
}

mw_state_t mw_get_state(const mw_ctx_t *ctx) { return ctx->st; }

rc_t mw_get_stats(const mw_ctx_t *ctx, mw_stats_t *out) {
  if (out == nullptr) {
    return rc_t::err_invalid;
  }
  *out = ctx->stats;
  return rc_t::ok;
}

bool mw_target_exit(const mw_ctx_t *ctx, int *wait_status) {
  if (ctx == nullptr || !ctx->target_exited) {
    return false;
  }
  if (wait_status != nullptr) {
    *wait_status = ctx->exit_status;
  }
  return true;
}

ssize_t mw_read_mem(mw_ctx_t *ctx, uintptr_t addr, void *buf, size_t len) {
  return mw_vm_read(ctx->pid, addr, buf, len);
}

ssize_t mw_write_mem(mw_ctx_t *ctx, uintptr_t addr, const void *buf,
                     size_t len) {
  return mw_vm_write(ctx->pid, addr, buf, len);
}

rc_t mw_regs_get(mw_ctx_t *ctx, pid_t tid, struct user_regs_struct *out) {
  if (ctx == nullptr || out == nullptr || tid <= 0) {
    return rc_t::err_invalid;
  }
  if (ptrace(PTRACE_GETREGS, tid, nullptr, out) == -1) {
    if (errno == ESRCH) {
      return rc_t::err_not_found;
    }
    mw_log_errno("mw_regs_get(%d)", tid);
    return rc_t::err_ptrace;
  }
  return rc_t::ok;
}

rc_t mw_regs_set(mw_ctx_t *ctx, pid_t tid, const struct user_regs_struct *in) {
  if (ctx == nullptr || in == nullptr || tid <= 0) {
    return rc_t::err_invalid;
  }
  if (ptrace(PTRACE_SETREGS, tid, nullptr,
             const_cast<struct user_regs_struct *>(in)) == -1) {
    if (errno == ESRCH) {
      return rc_t::err_not_found;
    }
    mw_log_errno("mw_regs_set(%d)", tid);
    return rc_t::err_ptrace;
  }
  return rc_t::ok;
}

rc_t mw_fpregs_get(mw_ctx_t *ctx, pid_t tid, struct user_fpregs_struct *out) {
  if (ctx == nullptr || out == nullptr || tid <= 0) {
    return rc_t::err_invalid;
  }
  if (ptrace(PTRACE_GETFPREGS, tid, nullptr, out) == -1) {
    if (errno == ESRCH) {
      return rc_t::err_not_found;
    }
    mw_log_errno("mw_fpregs_get(%d)", tid);
    return rc_t::err_ptrace;
  }
  return rc_t::ok;
}

rc_t mw_fpregs_set(mw_ctx_t *ctx, pid_t tid,
                   const struct user_fpregs_struct *in) {
  if (ctx == nullptr || in == nullptr || tid <= 0) {
    return rc_t::err_invalid;
  }
  if (ptrace(PTRACE_SETFPREGS, tid, nullptr,
             const_cast<struct user_fpregs_struct *>(in)) == -1) {
    if (errno == ESRCH) {
      return rc_t::err_not_found;
    }
    mw_log_errno("mw_fpregs_set(%d)", tid);
    return rc_t::err_ptrace;
  }
  return rc_t::ok;
}

rc_t mw_addr_resolve(mw_ctx_t *ctx, uintptr_t addr, char *buf, size_t buf_len) {
  std::vector<mw_map_t> maps;
  rc_t r;
  if (ctx == nullptr || buf == nullptr || buf_len == 0) {
    return rc_t::err_invalid;
  }
  r = mw_read_maps(ctx->pid, &maps);
  if (r != rc_t::ok) {
    (void)snprintf(buf, buf_len, "0x%lx", static_cast<unsigned long>(addr));
    return r;
  }
  for (size_t i = 0; i < maps.size(); ++i) {
    if (addr >= maps[i].lo && addr < maps[i].hi) {
      uintptr_t off = addr - maps[i].lo;
      if (!maps[i].path.empty()) {
        const char *p = maps[i].path.c_str();
        const char *slash = strrchr(p, '/');
        const char *base = (slash != nullptr) ? slash + 1 : p;
        (void)snprintf(buf, buf_len, "%s+0x%lx", base,
                       static_cast<unsigned long>(off));
      } else {
        (void)snprintf(buf, buf_len, "[anon]+0x%lx",
                       static_cast<unsigned long>(off));
      }
      return rc_t::ok;
    }
  }
  (void)snprintf(buf, buf_len, "0x%lx", static_cast<unsigned long>(addr));
  return rc_t::err_not_found;
}

