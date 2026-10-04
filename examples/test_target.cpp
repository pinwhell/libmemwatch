/* test_target - a process that keeps touching one page.
 *
 * Manual two-terminal run (needs ptrace permission on the target, see README):
 *
 *   Terminal A:  ./build/examples/test_target
 *                -> "[TARGET] pid=... addr=0x..." on stdout
 *   Terminal B:  ./build/examples/test_memwatch <PID> <ADDR_HEX>
 *
 * test_memwatch can also start this program itself (no arguments), which is
 * the reliable path under Yama ptrace_scope=1 because then the tracer is the
 * target's parent.
 *
 * The target allocates its own page, prints the address once on stdout and then
 * increments a counter on it forever, reporting progress on stderr.  Every
 * increment faults while memwatch owns the page (PROT_NONE) and is replayed by
 * the tracer, so the counter keeps growing without the target ever crashing.
 */
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
  long ps = sysconf(_SC_PAGESIZE);
  size_t page = (ps > 0) ? static_cast<size_t>(ps) : 4096U;
  volatile uint64_t *counter = static_cast<volatile uint64_t *>(
      mmap(nullptr, page, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  struct timespec ts;

  if (counter == MAP_FAILED) {
    fprintf(stderr, "[TARGET] mmap failed\n");
    return 1;
  }
  *counter = 0U;

  /* stdout carries exactly one line: the address the tracer needs. */
  fprintf(stdout, "[TARGET] pid=%d addr=%p val=0\n", (int)getpid(),
          static_cast<void *>(const_cast<uint64_t *>(counter)));
  (void)fflush(stdout);

  for (;;) {
    /* A plain read-modify-write on the watched page. */
    *counter += 1U;
    ts.tv_sec = 0;
    ts.tv_nsec = 200000000L; /* 200ms: readable output, no flood */
    (void)nanosleep(&ts, nullptr);
    fprintf(stderr, "[TARGET] val=%" PRIu64 "\n", *counter);
  }
  return 0;
}