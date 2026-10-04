# Testing

Everything runs under WSL on Linux x86_64. The suite is a single binary with
its own tracer/tracee pairs: every case forks its own target, because
`PTRACE_SEIZE` requires the tracer to be the target's **parent** under Yama
`ptrace_scope=1`.

```sh
make                    # optimised build: library, tests, examples
make test               # build + full suite (14 cases + 1 stress round), ~13 s
make stress             # 40 stress rounds
make debug              # -O0 -g3 into build-debug/
make examples           # demo binaries only
make clean
```

Strictness is on by default and `-Werror` is always in `CXXFLAGS`. A build that
emits a single warning is a failed build.

## Running

```sh
./build/memwatch_tests                 # everything
./build/memwatch_tests -v              # verbose, with memwatch's own log
./build/memwatch_tests --only 3        # one case by index
./build/memwatch_tests --only-stress --stress 20
./build/memwatch_tests --stress 4      # cases + 4 stress rounds
```

`--only <n>` indexes `g_cases[]` in `tests/t_main.cpp:1095`:

| n | case | what it pins down |
| --- | --- | --- |
| 0 | A single-thread repeated writes | the basic loop: one event per store, `rw-p` restored |
| 1 | B single-thread repeated reads | read faults are caught identically |
| 2 | C multiple threads, one watched page | the global stop really stops *all* of them |
| 3 | D multiple watched pages | per-page protection capture and per-page events |
| 4 | E thread creation while armed | `PTRACE_EVENT_CLONE` tracking |
| 5 | F thread destruction while armed | `PTRACE_EVENT_EXIT` handling, no resume of the dead |
| 6 | G unrelated SIGSEGV forwarded | transparency: `0x1` handler runs once, data intact |
| 7 | H repeated faults (2000) | single-step fidelity over a long run |
| 8 | I watch add/delete while running | arm/disarm ordering, `armed` ⇔ real `PROT_NONE` |
| 9 | J detach while the target is alive | restore-then-detach, target keeps running |
| 10 | K target exit during monitoring | `err_gone`, exit status via `mw_target_exit()` |
| 11 | L range validation over a hole | a refused watch must not touch the mapping |
| 12 | L remote mprotect failure | failure is loud, then the context is poisoned |
| 13 | M non-watch signal forwarding | SIGBUS/SIGILL/SIGTRAP/SIGUSR1/SIGFPE forwarded |

Always bound a run while iterating: `timeout 120 ./build/memwatch_tests --only 6`.
A regression in the fault sequence usually manifests as a **hang**, not a
failure — the target sits in `PROT_NONE` and nobody re-arms it.

## How a case is checked

The harness (`tests/harness.hpp`, `tests/harness.cpp`) never trusts memwatch's
own opinion. Three independent sources of truth:

1. **The kernel, from inside the callback.** `obs_cb()` runs on every event and
   re-derives the invariants from `/proc`: `proc_running_threads()` (any task
   state `R` during `critical` → `proc_running_violations`) and `proc_perms()`
   (the watched page must read `---p` while armed → `prot_violations`). The
   callback also checks that its own state is `critical` and that the fault it
   received is `owned` (`state_violations`, `cb_errors`).
2. **The target's own shared memory.** The child publishes `total_iters`,
   `page_iters[]`, `sums[]`, `sig_counts[]`, `corrupt` and `segv_seen` in a
   `MAP_SHARED` `ctl_t`, all accessed with `__atomic` so the worker's threads
   and the tracer agree. `verify()` (tests/t_main.cpp:479) compares them with
   what the case expects: event count per access, per-page counts, per-thread
   checksums, signal counts, `corrupt == 0`.
   The checksums matter more than they look: they are computed *after* the
   borrowed thread's registers have been overwritten with syscall arguments, so
   a missing `unwind()` shows up as corrupted data rather than as a crash.
3. **memwatch's own stats**, only as a secondary signal:
   `faults_owned == events`, `ssteps == events`,
   `remote_calls >= 2 * events` (one `mprotect` to release ownership, one to
   re-arm), `remote_sys_fail == 0`, `inv_violations == 0`,
   `cleanup_failures == 0`.

Plus `mw_get_state()`, `mw_get_stats()` for state-machine assertions, and the
process-level checks the runner does after each case.

## Stress rounds

`case_c_stress` (tests/t_main.cpp:673) runs 6 threads against 2 watched pages
for a configurable number of iterations with hand-checked per-thread sums.
40 rounds is the default gate (`make stress`). This is the case that finds
clone/exit races, because every round creates and joins threads while a watch
is armed.

## Flakiness policy

Timing-dependent faults have bitten this suite more than once. A single green
run is not evidence for this code:

```sh
make clean && make
for i in $(seq 8); do ./build/memwatch_tests --stress 2 || break; done
make debug && ./build-debug/memwatch_tests --stress 2
./build/memwatch_tests --only-stress --stress 20
```

Any change to `src/thr.cpp`, `src/remote.cpp` or the event loop requires the
8-run loop. If you see an intermittent `unexpected stop status=0x...` from
`call_via_stub`, read `docs/design-notes.md` §1 before changing anything: that
status was a *real* kernel ordering bug, not a test artifact.

## Examples

```sh
./build/examples/test_target &            # prints "pid=... addr=..."
./build/examples/test_memwatch <pid> <hex-addr>   # two-terminal mode
./build/examples/test_memwatch            # self-contained: spawns the target
```

Self-contained mode is the reliable one under `ptrace_scope=1`; the two-terminal
mode needs `CAP_SYS_PTRACE` or `ptrace_scope=0`. Both report touch counts and
validate them against the counter the target maintains.

## Writing a new case

1. Write a `target_fn` in `tests/t_main.cpp` (or `tests/harness.cpp` for
   reusable ones). It must publish what it did into `ctl_t` — a case that cannot
   fail from the outside is a useless case.
2. Fill an `expect_t`: pages, `total_iters`, per-thread `sums[]`,
   `nthreads`, `sig_counts[]`, `segv_seen`.
3. If the defaults fit, `return run_basic("X what-it-proves", tgt_x, &e);` —
   that gets attach, arm, pump, verify and detach for free.
4. Otherwise write the case explicitly: `mw_ctx_init` → `mw_attach` →
   `mw_watch_add` → set `ctl->go` → `pump()`/`pump_done()` loop → assertions →
   `mw_watch_del*` → `mw_detach` → `mw_ctx_free`. Use `REQUIRE` for setup
   failures (it returns), `CHECK` for assertions.
5. Register it in `g_cases[]` (tests/t_main.cpp:1095). **Append it** — the index
   is the `--only` selector, and reordering silently changes what everyone
   else's one-liners run.
6. If it proves an invariant, add the row to `docs/invariants.md` and note the
   case letter there.

## Environment notes

* The suite needs `/proc` mounted and `process_vm_readv` available; it does not
  need root. It does need the tracer to be the parent (`ptrace_scope=1`).
* WSL wipes `/tmp` on VM restart. Put long logs in
  `/mnt/c/Users/User/AppData/Local/Temp/opencode/`.
* PowerShell mangles `$` inside `wsl ... bash -lc '...'`. For anything with
  variables or loops, write a script under
  `/mnt/c/Users/User/AppData/Local/Temp/opencode/` and run
  `wsl -d Ubuntu -e bash /mnt/c/.../<script>.sh`.
* A hung test leaves children behind: `pkill -f memwatch_tests`.