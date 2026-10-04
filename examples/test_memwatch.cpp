/* test_memwatch - watch one page of a running process.
 *
 *   ./build/examples/test_memwatch                 spawns test_target itself
 *   ./build/examples/test_memwatch <PID> <ADDR_HEX>  watches a process you
 *                                                    started elsewhere
 *
 * Prints one line per access the target makes on the watched page.  The target
 * is left untouched: after mw_detach() its page is writable again and it keeps
 * running.
 */
#include "memwatch/api.hpp"

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

uint64_t g_touches = 0;
volatile int g_running = 0;

rc_t on_touch(mw_ctx_t *ctx, mw_watch_t *w, mw_fault_t *f) {
  uint64_t v = 0U;
  (void)w;
  ++g_touches;
  /* Every target thread is stopped here and the watched page is still
   * PROT_NONE, so this read goes through the tracer, not the target. */
  if (mw_read_mem(ctx, f->addr, &v, sizeof v) < 0) {
    v = 0U;
  }
  fprintf(stdout,
          "[MW] touch | tid=%d | addr=0x%" PRIxPTR " | page=0x%" PRIxPTR
          " | rip=0x%" PRIx64 " | value=%" PRIu64 "\n",
          (int)f->tid, f->addr, f->p.addr,
          static_cast<uint64_t>(f->rip), v);
  (void)fflush(stdout);
  return rc_t::ok;
}

void log_line(const char *msg) { fprintf(stderr, "[MW] %s\n", msg); }

/* Start test_target as our own child (so ptrace/seize is always permitted) and
 * read back the single address line it prints on stdout. */
bool spawn_target(pid_t *out_pid, uintptr_t *out_addr) {
  int fds[2];
  pid_t pid;
  char buf[256];
  ssize_t got;
  char exe[4096];
  ssize_t n;
  std::string path;

  if (pipe(fds) != 0) {
    perror("[MW] pipe");
    return false;
  }
  pid = fork();
  if (pid < 0) {
    perror("[MW] fork");
    return false;
  }
  if (pid == 0) {
    (void)close(fds[0]);
    if (dup2(fds[1], STDOUT_FILENO) < 0) {
      _exit(126);
    }
    (void)close(fds[1]);
    n = readlink("/proc/self/exe", exe, sizeof exe - 1U);
    if (n <= 0) {
      _exit(126);
    }
    exe[n] = '\0';
    path = std::string(exe);
    path = path.substr(0, path.find_last_of('/')) + "/test_target";
    execl(path.c_str(), "test_target", static_cast<char *>(nullptr));
    _exit(127);
  }

  (void)close(fds[1]);
  got = read(fds[0], buf, sizeof buf - 1U);
  (void)close(fds[0]);
  if (got <= 0) {
    fprintf(stderr, "[MW] the target produced no address line\n");
    return false;
  }
  buf[got] = '\0';
  {
    const char *key = "addr=0x";
    const char *at = std::strstr(buf, key);
    if (at == nullptr) {
      fprintf(stderr, "[MW] cannot parse the target's banner: %s", buf);
      return false;
    }
    *out_addr =
        static_cast<uintptr_t>(std::strtoull(at + std::strlen(key), nullptr, 16));
  }
  *out_pid = pid;
  return true;
}

} /* namespace */

int main(int argc, char **argv) {
  mw_ctx_t *ctx = nullptr;
  rc_t r;
  pid_t pid = 0;
  uintptr_t addr = 0U;
  bool ours = false;

  if (argc == 3) {
    pid = static_cast<pid_t>(std::atoi(argv[1]));
    addr = static_cast<uintptr_t>(std::strtoull(argv[2], nullptr, 16));
  } else if (argc == 1) {
    ours = true;
  } else {
    fprintf(stderr,
            "usage: %s [<PID> <ADDR_HEX>]   (no arguments: start a target)\n",
            argv[0]);
    return 2;
  }
  if (!ours && (pid <= 0 || addr == 0U)) {
    fprintf(stderr, "%s: bad arguments\n", argv[0]);
    return 2;
  }
  if (ours && !spawn_target(&pid, &addr)) {
    return 1;
  }

  mw_log_set(log_line);

  r = mw_ctx_init(&ctx);
  if (r != rc_t::ok) {
    fprintf(stderr, "[MW] ctx_init: %s\n", mw_strerror(r));
    return 1;
  }
  r = mw_attach(ctx, pid);
  if (r != rc_t::ok) {
    fprintf(stderr, "[MW] attach: %s\n", mw_strerror(r));
    if (ours) {
      (void)kill(pid, SIGKILL);
    }
    (void)mw_ctx_free(ctx);
    return 1;
  }
  fprintf(stderr, "[MW] attached to %d, watching 0x%" PRIxPTR "\n", (int)pid,
          addr);

  r = mw_watch_add(ctx, addr, 4096U, on_touch, nullptr);
  if (r != rc_t::ok) {
    fprintf(stderr, "[MW] watch_add: %s\n", mw_strerror(r));
    (void)mw_detach(ctx);
    (void)mw_ctx_free(ctx);
    return 1;
  }
  fprintf(stderr, "[MW] armed. waiting for touches\n");

  g_running = 1;
  while (g_running != 0) {
    int status = 0;
    r = mw_poll(ctx, 200);
    if (r == rc_t::err_timeout) {
      continue;
    }
    if (r != rc_t::ok) {
      fprintf(stderr, "[MW] poll: %s\n", mw_strerror(r));
      break;
    }
    if (mw_target_exit(ctx, &status)) {
      fprintf(stderr, "[MW] target is gone (status=0x%x)\n", status);
      break;
    }
  }

  r = mw_detach(ctx);
  fprintf(stderr, "[MW] detached (%s) after %" PRIu64 " touches\n",
          mw_strerror(r), g_touches);
  (void)mw_ctx_free(ctx);

  if (ours) {
    /* The target keeps running after a detach; this demo owns it, so stop it. */
    (void)kill(pid, SIGTERM);
    {
      int wstatus = 0;
      while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) {
        /* retry */
      }
    }
  }
  return 0;
}