# AGENTS.md — working in this repository

`libmemwatch` is a page-fault based watchpoint engine for Linux **x86_64**
(`ptrace` + `PROT_NONE` + `SIGSEGV`). It is a tracer library: the process that
links it becomes the parent-tracer of the target it watches. There is no
hardware-debug-register path and no design freedom in the fault sequence — the
correctness argument rests on a strict state machine, so read
`docs/architecture.md` before changing anything in `src/`.

- `docs/architecture.md` — mechanism, state machine, remote-call protocol.
- `docs/invariants.md` — the hard invariants, where each is checked, how each is tested.
- `docs/testing.md` — how to build, run, filter and extend the suite.
- `docs/design-notes.md` — the non-obvious kernel/library facts, decisions, limitations.

## Layout

| path | contents |
| --- | --- |
| `include/memwatch/types.hpp` | `rc_t`, `mw_state_t`, `rng_t`, `pg_t`, `thr_t`, `mw_watch_t`, `mw_fault_t`, `mw_stats_t`, `mw_ctx_t` |
| `include/memwatch/api.hpp` | the only public header (`extern "C"`) |
| `include/memwatch/{thr,remote,watch,event}.hpp` | internal interfaces |
| `include/memwatch/internal.hpp` | shared internals: wait flags, ptrace options, procfs, logging, invariants |
| `src/thr.cpp` | thread table, global stop/resume, waits, seized baseline |
| `src/remote.cpp` | gadget discovery, code cave, borrow/register restore |
| `src/watch.cpp` | range validation, protection capture, arm/disarm ordering |
| `src/event.cpp` | event classification, the fault sequence, clone/exit/signal handling |
| `src/util.cpp` | procfs, `process_vm_readv/writev`, logging, poison, `mw_inv_check` |
| `src/ctx.cpp` | context lifecycle, attach, detach |
| `tests/` | harness + suite (cases A-M, stress rounds) |
| `examples/` | `test_target` + `test_memwatch` demo |

## Build and verify

Run everything through WSL; the project root is the repo root.

```sh
make                 # strict optimised build: lib, tests, examples
make test            # whole suite (14 cases + 1 stress round), ~13 s
make stress          # 40 multithreaded stress rounds
make debug           # -O0 -g3 into build-debug/
make examples        # demo binaries only
make clean
```

Case selection while iterating:

```sh
./build/memwatch_tests -v --only 3            # one case, verbose
./build/memwatch_tests --only-stress --stress 20
```

`--only <n>` indexes `g_cases[]` in `tests/t_main.cpp`:
`0 A`, `1 B`, `2 C`, `3 D`, `4 E`, `5 F`, `6 G`, `7 H`, `8 I`, `9 J`, `10 K`,
`11 L hole`, `12 L mprotect failure`, `13 M`.

## Definition of done

Do not report a change as working until all of this has been run:

```sh
make clean && make                 # 0 warnings, -Werror is always on
make test                          # 15/15
./build-debug/memwatch_tests --stress 2   # after `make debug`
./build/memwatch_tests --only-stress --stress 20
```

Timing-dependent faults have bitten this suite before: after any change to
`src/thr.cpp`, `src/remote.cpp` or the event loop, run the full suite **at least
8 times in a row** (`for i in $(seq 8); do ./build/memwatch_tests --stress 2 || break; done`).
A single green run is not evidence for this code.

## Rules that must not be broken

1. **Never resume a thread inside a critical state.** `resume_now` is `false`
   for every event drained inside `entering`/`critical`/`rcall`/`sstep`/
   `rearming`. A pending faulting instruction re-faults by itself; do not
   "help" it forward.
2. **`armed` is an ownership flag, not a cache.** It is set to `false` *before*
   the remote `mprotect` that restores protections and to `true` only *after*
   `PROT_NONE` is really installed. Never reorder.
3. **The borrow is exclusive.** Exactly one alive, stopped thread runs, chosen
   by `pick_borrow`, and its full `user_regs_struct` is restored. Never
   `PTRACE_CONT` anybody else during `rcall`.
4. **The only accepted stop in a borrow is the controlled SIGTRAP** — except an
   in-flight `PTRACE_EVENT_STOP`/`SIGSTOP` group stop, which is tolerated by
   continuing (see `docs/design-notes.md`). Any other signal is `err_unexpected`.
5. **Unowned signals are forwarded untouched**, with the original siginfo
   (`PTRACE_CONT` with the signal number plus `PTRACE_SETSIGINFO`). The target
   must not be able to tell memwatch exists.
6. **Failure is fail-safe.** If a restore or an invariant fails, poison the
   context (`mw_poison`): pages keep their `PROT_NONE` ownership and only
   `mw_detach`/`mw_ctx_free` stay legal. Never un-protect memory you could not
   restore.
7. **No new dependencies, no new build modes, no suppressed warnings.** The
   Makefile must stay warning-clean under its own flag list.

## Conventions

- `enum class rc_t` for every fallible call; no exceptions, no `errno` leakage.
  A `nullptr`/invalid argument is `err_invalid`, never a crash.
- Comments explain *why* (kernel behaviour, ordering constraint, invariant).
  Do not narrate what the next line does.
- Internal headers keep `#if !defined(__x86_64__) #error` — the stub encoding is
  x86_64-specific even though the state machine is not.
- Tests observe the **kernel**, not memwatch's opinion: `/proc/<pid>/task/*/stat`
  for "is anything running", `/proc/<pid>/maps` for the real protection,
  shared-memory counters in the child for "did it really do the work". A test
  that only asserts on memwatch's own counters proves nothing.
- New public API needs a line in `docs/invariants.md` only if it changes what is
  guaranteed; otherwise update `README.md`'s API block.

## Environment gotchas (cost real time)

- The tracer must be the target's **parent** under Yama `ptrace_scope=1`
  (`wsl -d Ubuntu -e cat /proc/sys/kernel/yama/ptrace_scope`). Test cases fork
  their own targets for that reason.
- **WSL wipes `/tmp` when the VM restarts.** Write test logs to
  `/mnt/c/Users/User/AppData/Local/Temp/opencode/`, not `/tmp`.
- The shell here is PowerShell 5.1: `$` inside a `wsl ... bash -lc '...'` one-liner
  gets mangled or split. For anything with variables, loops or `;`, put the
  script in `/mnt/c/Users/User/AppData/Local/Temp/opencode/<name>.sh` and run
  `wsl -d Ubuntu -e bash /mnt/c/.../<name>.sh`.
- Always bound a run (`timeout 120 ./build/memwatch_tests --only 6`); a
  regression in the fault sequence shows up as a hang, not a failure.

## Git

Single logical change per commit, message in the imperative mood
(`thr: wait for interrupt stops before claiming the global stop`). Do not commit
`build/`/`build-debug/` (already ignored). Update `docs/` in the same commit as
any behaviour change it describes.