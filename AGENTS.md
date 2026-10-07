# AGENTS.md — Developer & AI Agent Directive for `libmemwatch`

`libmemwatch` is a high-performance, page-fault-driven **Execution Interceptor & Memory Watchpoint Engine** for Linux **x86_64** (`ptrace` + `PROT_NONE` + `SIGSEGV`). It turns the process that links it into an out-of-process parent-tracer capable of monitoring and controlling arbitrary memory regions in a tracee without hardware debug registers (`DR0`–`DR7`) and without target cooperation.

---

## 1. Core Philosophy: Low-Level Freedom & Zero Bloat

1. **The Frozen Sandbox**:
   When a watchpoint triggers, the entire target process is frozen in a verified ptrace group stop (`mw_thr_count_running() == 0`). The user callback receives full low-level machine freedom:
   * Inspect/modify general-purpose registers (`user_regs_struct`).
   * Zero-copy virtual memory read/write via `process_vm_readv/writev`.
   * Translate raw addresses to human-readable `module+0xoffset` (e.g. `libxyz.so+0x1120`) using `/proc/<pid>/maps` with **zero external dependencies**.
   * Execute target functions or syscalls synchronously inside the target context.
2. **Actionable Continuations**:
   The callback chooses the execution policy via `mw_action_t`:
   * `MW_ACTION_REPLAY`: Standard replay (temporarily restore permissions, single-step faulting thread, re-arm `PROT_NONE`, resume all).
   * `MW_ACTION_SKIP`: User emulated the access or advanced `rip`. **The page never drops `PROT_NONE`**—eliminating the window of vulnerability against concurrent threads.
   * `MW_ACTION_DISARM`: Permanently drop the watchpoint.
3. **Lean Core vs Companion Libraries**:
   * **Core Engine**: Pure C/C++ relying solely on Linux kernel primitives (`ptrace`, `/proc`, `process_vm_readv`). No bloat.
   * **Companion Leverage**: Capstone (`libcapstone`) for decoding instruction sizes and assembly at `rip`. Linenoise for embedding an interactive debugger shell inside watch callbacks.

---

## 2. Layout

| Path | Purpose |
| :--- | :--- |
| `include/memwatch/types.hpp` | Core types (`rc_t`, `mw_state_t`, `rng_t`, `pg_t`, `thr_t`, `mw_watch_t`, `mw_fault_t`, `mw_ctx_t`) |
| `include/memwatch/api.hpp` | Public C interface (`extern "C"`) |
| `include/memwatch/{thr,remote,watch,event}.hpp` | Subsystem internal headers |
| `include/memwatch/internal.hpp` | Wait flags, ptrace options, logging, procfs, invariants |
| `src/thr.cpp` | Thread inventory, global stop/resume convergence, waits |
| `src/remote.cpp` | Bootstrap gadget scan, code cave lifecycle, register snapshot/unwind |
| `src/watch.cpp` | Range validation, heterogeneous protection capture, arm/disarm ordering |
| `src/event.cpp` | Event loop, fault sequence, clone/exit/signal transparency |
| `src/util.cpp` | Procfs maps parsing, `process_vm_readv/writev`, poisoning, invariant checker |
| `src/ctx.cpp` | Context lifecycle (`mw_ctx_init`, `mw_attach`, `mw_detach`) |
| `tests/` | Test harness (`harness.cpp`) and verification suite (`t_main.cpp`, cases A-M + stress) |
| `examples/` | Standalone and two-terminal demo drivers |
| `docs/` | `architecture.md`, `design-notes.md`, `invariants.md`, `testing.md` |

---

## 3. Strict Non-Negotiable Rules

1. **Never resume threads inside a critical section**:
   `resume_now` must remain `false` for every event drained inside `entering`, `critical`, `rcall`, `sstep`, and `rearming`. Faulting instructions re-fault naturally after release; never "help" them forward.
2. **`armed` is an ownership contract, not a status cache**:
   * Disarming: Set `armed = false` **before** the remote `mprotect` that restores original protections.
   * Arming: Set `armed = true` **only after** `PROT_NONE` has successfully been installed by the kernel.
   * Reversing this order creates critical race windows and violates Invariant $I_5$.
3. **Exclusive Thread Borrowing ($I_7$)**:
   Exactly one alive, stopped thread is borrowed via `pick_borrow()`. Its full `user_regs_struct` is restored on unwind. Never issue `PTRACE_CONT` to any other thread during `rcall`.
4. **Controlled Stops Only ($I_7, I_8$)**:
   The only stop accepted during code cave execution is the `SIGTRAP` from its trailing `int3` (with tolerance for in-flight `PTRACE_EVENT_STOP` group stops). Any other signal aborts and poisons the context.
5. **Signal Transparency ($I_{10}$)**:
   Signals not owned by an armed watch must be forwarded untouched with their original `siginfo_t` using `PTRACE_SETSIGINFO` and `PTRACE_CONT(tid, sig)`. The target process must never perceive the tracer's existence on unmonitored signals.
6. **Fail-Safe Poisoning ($I_{11}$)**:
   If an invariant is breached or a register/protection restore fails, poison the context (`mw_poison()`). Watched pages stay `PROT_NONE` to prevent unwatched memory execution. Only `mw_detach()` and `mw_ctx_free()` remain legal.
7. **Zero Suppressed Warnings**:
   The build must compile warning-free with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror`. No warnings may be suppressed.

---

## 4. Build, Verification & Definition of Done

All builds and tests run through WSL from the repository root:

```sh
# Clean build and run complete test suite (14 cases + stress)
make clean && make
make test

# Run stress rounds (concurrency race verification)
./build/memwatch_tests --only-stress --stress 20

# Debug build (-O0 -g3)
make debug && ./build-debug/memwatch_tests --stress 2

# Targeted iteration on specific test case
./build/memwatch_tests -v --only 3   # 0=A, 1=B, 2=C, 3=D, ..., 13=M
```

### Definition of Done
Do not declare a change functional until:
1. `make clean && make` succeeds with 0 warnings.
2. `make test` passes all 15/15 cases.
3. Stress testing passes: `./build/memwatch_tests --only-stress --stress 20`.
4. After changes to `src/thr.cpp`, `src/remote.cpp`, or `src/event.cpp`, run the suite at least 8 times consecutively:
   ```sh
   for i in $(seq 8); do ./build/memwatch_tests --stress 2 || break; done
   ```

---

## 5. Critical Environment Nuances

* **Yama LSM `ptrace_scope=1`**: Under Linux/WSL defaults, a tracer must be the **parent** of the tracee (`fork()` before `PTRACE_SEIZE`) or have `CAP_SYS_PTRACE`. Test cases must spawn their own children.
* **WSL Filesystem**: WSL wipes `/tmp` upon VM restart. Long-lived temporary test logs must be written to `/mnt/c/Users/User/AppData/Local/Temp/opencode/`.
* **PowerShell Syntax**: When running commands via PowerShell into WSL, escape `$` characters or write scripts directly to a file before invoking `wsl -d Ubuntu -e bash <script>.sh`.
* **Timeout Guards**: Always bound test executions with timeouts (`timeout 120 ./build/memwatch_tests --only 6`) because state machine regressions manifest as hangs rather than crashes.