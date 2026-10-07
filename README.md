# libmemwatch

A page-fault based watchpoint engine for Linux/WSL **x86_64**: an unlimited
number of watched ranges, no hardware debug registers involved.

**Longer documentation lives in [`docs/`](docs/):**
[`architecture.md`](docs/architecture.md) (mechanism, state machine, remote-call
protocol) · [`invariants.md`](docs/invariants.md) (the audit behind every
guarantee) · [`testing.md`](docs/testing.md) (how to run and extend the suite) ·
[`design-notes.md`](docs/design-notes.md) (kernel findings, decisions,
limitations). [`AGENTS.md`](AGENTS.md) is the working agreement for this repo.

* Mechanism: `ptrace` + `PROT_NONE` + `SIGSEGV`.
* Watched pages are kept `PROT_NONE`; every access traps, the tracer stops the
  whole target, runs the user callback, replays the faulting instruction and
  re-arms. The target never crashes and never observes the window.
* Remote calls are atomic: exactly one already-stopped thread is borrowed to
  execute the `mprotect` syscall that releases/reacquires ownership, and its
  complete register image is restored afterwards.

```
attach -> arm(PROT_NONE) -> SIGSEGV -> idle/entering -> global stop -> critical
   -> double validation -> callback -> armed=false -> remote mprotect(restore)
   -> sstep(PTRACE_SINGLESTEP on fault_tid only) -> rearming
   -> remote mprotect(PROT_NONE) -> armed=true -> clear fault -> resume -> idle
```

## Layout

| path | contents |
| --- | --- |
| `include/memwatch/types.hpp` | `rc_t`, `mw_state_t`, `rng_t`, `pg_t`, `thr_t`, `mw_watch_t`, `mw_fault_t`, `mw_ctx_t` |
| `include/memwatch/api.hpp` | public API |
| `include/memwatch/{thr,remote,watch,event,internal}.hpp` | internal interfaces |
| `src/util.cpp` | procfs, `process_vm_readv/writev`, logging, poisoning, `mw_inv_check` |
| `src/thr.cpp` | thread bookkeeping, global stop/resume, `waitpid` classification helper |
| `src/remote.cpp` | `syscall` gadget discovery, code cave, register borrow/restore |
| `src/watch.cpp` | range validation, protection capture, arm/disarm ordering |
| `src/event.cpp` | event loop, fault sequence, clone/exit/signal handling |
| `src/ctx.cpp` | context lifecycle, attach/detach |
| `tests/` | test harness and 14 cases (A-M) plus stress rounds |
| `examples/` | manual two-terminal demo, or self-contained |
| `docs/` | architecture, invariants, testing, design notes |

## Build and test (WSL)

```sh
make            # strict optimised build + tests + examples
make test       # whole suite (A-M)
make stress     # 40 multithreaded stress rounds
make debug      # -O0 -g3 build (build-debug/)
make clean
```

Strictness is on by default: `-Wall -Wextra -Wpedantic -Wshadow -Wconversion
-Wsign-conversion -Wcast-qual -Wdouble-promotion -Wnull-dereference -Wformat=2
-Wundef -Wpointer-arith -Wwrite-strings -Wmissing-declarations -Wredundant-decls
-Wstrict-overflow=2 -Wvla -Wswitch -Winit-self -Werror`. No warning is
suppressed anywhere.

The suite must run where the tracer is the target's **parent**
(`PTRACE_SEIZE` needs that under Yama `ptrace_scope=1`); the test cases fork
their own targets. Useful switches:

```sh
./build/memwatch_tests -v              # verbose, with memwatch's own log
./build/memwatch_tests --only 3        # one case (0=A 1=B 2=C 3=D ... 13=M)
./build/memwatch_tests --only-stress   # stress rounds only
./build/memwatch_tests --stress 40     # 40 rounds after the normal cases
```

### Manual demo

```sh
./build/examples/test_memwatch              # spawns the target itself
./build/examples/test_target                # terminal A
./build/examples/test_memwatch <PID> <ADDR_HEX>   # terminal B (needs CAP_SYS_PTRACE
                                                  #  or ptrace_scope=0)
```

## API

### Low-Level Interceptor API (`extern "C"`)

```c
rc_t mw_ctx_init(mw_ctx_t **out);
rc_t mw_attach(mw_ctx_t *ctx, pid_t pid);
rc_t mw_watch_add(mw_ctx_t *ctx, uintptr_t base, size_t size, mw_callback_t cb, void *ud);
rc_t mw_watch_del(mw_ctx_t *ctx, uintptr_t base, size_t size);

/* Low-level tools available inside the watch callback */
rc_t    mw_regs_get(mw_ctx_t *ctx, pid_t tid, struct user_regs_struct *out);
rc_t    mw_regs_set(mw_ctx_t *ctx, pid_t tid, const struct user_regs_struct *in);
ssize_t mw_read_mem(mw_ctx_t *ctx, uintptr_t addr, void *buf, size_t len);
ssize_t mw_write_mem(mw_ctx_t *ctx, uintptr_t addr, const void *buf, size_t len);

/* Zero-dependency address resolution via /proc/<pid>/maps -> "libxyz.so+0x1120" */
rc_t    mw_addr_resolve(mw_ctx_t *ctx, uintptr_t addr, char *buf, size_t buf_len);

/* Remote function call execution in target */
rc_t    mw_remote_call(mw_ctx_t *ctx, pid_t tid, uintptr_t func_addr,
                       const unsigned long *args, size_t nargs, unsigned long *out_ret);

rc_t mw_poll(mw_ctx_t *ctx, int timeout_ms);
rc_t mw_detach(mw_ctx_t *ctx);
```

### Clean Interceptor Example

```c
mw_action_t on_touch(mw_ctx_t *ctx, const mw_intercept_t *ic, void *ud) {
    char sym[128];
    uint64_t val = 0;

    mw_addr_resolve(ctx, ic->rip, sym, sizeof(sym)); // e.g., "libxyz.so+0x1120"
    mw_read_mem(ctx, ic->addr, &val, sizeof(val));
    printf("[WATCH] TID %d at %s touched 0x%lx (val=0x%lx)\n", ic->tid, sym, ic->addr, val);

    return MW_ACTION_REPLAY; // or MW_ACTION_SKIP if emulating!
}
```


The callback receives [`mw_fault_t`](file:///c:/Users/User/Documents/lab/libmemwatch/include/memwatch/types.hpp#L106-L114) `{ tid, addr, page, si_code, rip, watch, owned }`
and runs in the tracer with every target thread stopped and the page still
`PROT_NONE`; [`mw_read_mem`](file:///c:/Users/User/Documents/lab/libmemwatch/src/util.cpp#L346)/[`mw_write_mem`](file:///c:/Users/User/Documents/lab/libmemwatch/src/util.cpp#L350) (`process_vm_readv/writev`) are the only safe way to look at
target memory from there.

**Ownership of the exit status.** memwatch is the target's parent, so it is the
only component that can `waitpid()` the target's death; a caller's own
`waitpid()` returns `ECHILD` once `mw_poll`/`mw_detach` reported `err_gone`.
[`mw_target_exit()`](file:///c:/Users/User/Documents/lab/libmemwatch/src/util.cpp#L336) hands back the wait status the kernel reported.

**Failure policy.** Once an invariant is violated, or a remote call or restore
fails in a way the tracer cannot undo, the context is *poisoned*: watches keep
their `PROT_NONE` ownership (the target keeps faulting instead of running
unwatched memory), and every API except `mw_detach`/`mw_ctx_free` returns
`err_poisoned`. `mw_detach` always tries to restore the protections.

## Fault sequence

1. `mw_poll` reaps the SIGSEGV signal-delivery-stop and records `fault_tid`.
2. `entering`: `mw_thr_stop_all` interrupts every running thread and waits until
   their stops have actually been reaped, so "all stopped" is a fact, not a
   hope. Events that arrive meanwhile are drained with `resume_now=false` and
   left stopped, so their faulting instructions simply re-fault later.
3. `critical`: `PTRACE_GETSIGINFO` is re-read and accepted **only** if
   `si_code` is `SEGV_MAPERR`/`SEGV_ACCERR` **and** the address is covered by a
   watch with `armed == true`. Otherwise the original signal is forwarded
   untouched (`PTRACE_CONT` with the original siginfo) and the target sees its
   own `SIGSEGV` exactly as if memwatch did not exist.
4. The callback runs with zero target threads executing.
5. `armed = false`, then a remote `mprotect` restores the original protections.
6. `sstep`: `PTRACE_SINGLESTEP` on `fault_tid` only, so the faulting
   instruction completes; the SIGTRAP is consumed here and nowhere else.
7. `rearming`: remote `mprotect(PROT_NONE)`, then `armed = true`.
8. Fault bookkeeping cleared, every thread resumed, back to `idle`.

## Invariant audit

Every invariant is checked in code (`mw_inv_check`, 17 call sites, counting
`stats.inv_checks` and `stats.inv_violations`) and observed independently from
the tests against the kernel's own view (`/proc/<pid>/task/*/stat`,
`/proc/<pid>/maps`).

| INVARIANT | CODE LOCATION | TEST | RESULT |
| --- | --- | --- | --- |
| I1 `in_rcall == (borrow_tid != 0)`, and only in `rcall` | `src/util.cpp:236-244` | every case, `st.inv_violations` | PASS |
| I2 at most one target thread executes, and it is `borrow_tid`/`fault_tid` | `src/util.cpp:274-288` | A-M + 40 stress rounds | PASS |
| I3 zero target threads execute in `entering`/`critical`/`rearming` | `src/util.cpp:265-273` | `obs_cb` `mw_threads_running()==0` + `/proc` task states (`proc_running_threads`), A-M | PASS |
| I4 a pending fault exists only in `critical`/`rcall`/`sstep`/`rearming` | `src/util.cpp:246-259` | A-M, K exit sequence | PASS |
| I5 `armed == true` iff the pages are really `PROT_NONE` (ownership flips around the remote call) | `src/watch.cpp:103-148`, `src/event.cpp:441-530` | `obs_cb` reads `/proc/<pid>/maps` (`prot_violations`), I add/del/re-arm, D multi-page | PASS |
| I6 double validation: fault accepted only if covered by an armed watch after the global stop | `src/event.cpp:386-403` | G unrelated SIGSEGV forwarded, L hole ranges | PASS |
| I7 remote call: only the borrowed thread runs, full register restore, controlled SIGTRAP only | `src/remote.cpp:129-380`, `unwind` at `:109` | A-H (one event per access, checksums intact) | PASS |
| I8 single-step is exclusive to `fault_tid` and its SIGTRAP is consumed there | `src/event.cpp:447-518` | H 2000 repeated faults, A-H event counts | PASS |
| I9 new threads (`PTRACE_EVENT_CLONE`) are tracked and never escape the discipline | `src/event.cpp:154-169`, `mw_thr_add_cloned` at `src/thr.cpp:87` | E creation while armed, C 4 threads, F short-lived threads | PASS |
| I10 unrelated signals reach the target untouched | `src/event.cpp:310-325`, `forward_and_resume` | G SIGSEGV (handler ran once, `corrupt==0`), M SIGBUS/SIGILL/SIGTRAP/SIGUSR1/SIGFPE | PASS |
| I11 a failed restore never leaves memory unwatched (poison) | `mw_poison` at `src/util.cpp:300`, re-arm-on-failure at `src/watch.cpp:130-142` | L remote mprotect failure path (target unmaps a page inside the range) | PASS |
| I12 one owner for `waitpid`: the target's wait status is never lost | `src/event.cpp:131-138`, `mw_target_exit` at `src/util.cpp:336` | K target exit (status 0x700 = exit 7, caller `waitpid` = ECHILD) | PASS |

Suite totals: 15/15 cases pass (`A`-`M` plus a stress round) in ~13 s, 8/8
consecutive full-suite repetitions with 2 stress rounds each, 40/40 stress
rounds, and the `-O0 -g3` debug build. `st.inv_violations == 0` and
`obs.*_violations == 0` in every case.

### Notes on the fixes that were needed

* `PTRACE_SEIZE` does **not** stop the threads it attaches to, so the baseline
  is "every thread is running" (`mw_thr_sync_seized`) and the first
  `mw_thr_stop_all` creates the real baseline.
* An interrupt's group-stop can be published just after the drain that was
  supposed to consume it. `mw_thr_stop_all` therefore polls until the running
  count reaches zero, and both borrow paths tolerate an in-flight group-stop
  (`PTRACE_EVENT_STOP`) by continuing instead of failing the call.
* The code cave cannot unmap itself (it would return into the page it just
  removed), so the final `munmap` runs through the `syscall` gadget.
* `sigsetjmp`/`siglongjmp` split across translation units breaks the non-local
  return; case G keeps the jump buffer, the arming flag and the handler in the
  same unit as the `sigsetjmp()` call.