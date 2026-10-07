# Design notes

The non-obvious parts: kernel behaviours that shaped the implementation,
decisions that were deliberate, and the limitations worth knowing before you
extend this.

## 1. An in-flight `PTRACE_INTERRUPT` looks exactly like an unexpected stop

**Symptom.** Case D failed intermittently with
`remote call: unexpected stop status=0x80057f (expected SIGTRAP)`. `0x80057f`
decodes as `SIGTRAP | 0x80<<8` — i.e. `PTRACE_EVENT_STOP`.

**Cause.** `mw_thr_stop_all()` sent `PTRACE_INTERRUPT` to every thread and then
drained waits. The interrupt for thread B is *queued* the moment it is issued,
but B may be running at that point and only reaches its group stop later. If the
drain finished (because A's stop was the last one reaped) and the fault
sequence proceeded into a borrow, thread B's group stop arrived **inside the
borrow** instead of inside the global stop. The borrow accepts exactly one stop
— its own `SIGTRAP` from the `int3` — so a `PTRACE_EVENT_STOP` there is fatal.

This is not a test artifact and it is not a rare race: the window is one
instruction-to-one-wait wide, and it grows with thread count.

**Fix, in two layers.**

* `mw_thr_stop_all()` (src/thr.cpp:290) no longer trusts a single drain. It
  loops: interrupt everyone, drain everything non-blocking, and only return
  when `mw_thr_count_running() == 0`. Because the count is the ground truth
  (a thread is "running" until its stop is *reaped*), a late group stop keeps
  the loop alive. Bounded by a 50 ms deadline and `MW_STOP_MAX_ROUNDS` (4096)
  re-interrupt rounds so a target that clones in a tight loop cannot hang the
  tracer.
* Both borrow paths tolerate the residual race instead of failing: a
  `PTRACE_EVENT_STOP`/`SIGSTOP` group stop (`is_group_stop()`,
  src/remote.cpp:59) is *continued* and waited for again, up to
  `MW_BORROW_MAX_SPURIOUS_STOPS` (8) times. Anything else is still
  `err_unexpected`.

**Lesson.** With `PTRACE_INTERRUPT`, "I drained all the waits" does not imply
"I own all the group stops". Ownership has to be tracked as a per-thread fact,
which is exactly what `thr_t::running` is.

## 2. `PTRACE_SEIZE` does not stop what it attaches to

`PTRACE_SEIZE` installs tracing without stopping the tracee (unlike
`PTRACE_ATTACH`). So the natural assumption "after seizing, every thread is
stopped" is false: after `mw_attach()`, all target threads are *running* until
the first `mw_thr_stop_all()`.

`mw_thr_sync_seized()` (src/thr.cpp:110) therefore seeds every existing thread
with `running = true`. Getting this wrong does not crash — it produces a
"global stop" that never actually stopped anything, and the first multi-thread
fault then races. It is the reason the attach baseline is documented in
`docs/invariants.md` rather than left to the reader.

## 3. A code cave cannot unmap itself

`mw_remote_fini()` (src/remote.cpp:439) has to remove the private `RWX` page
from the target. It cannot use the stub for that: `munmap` would return into
the very page it just removed, and the target would die with `SIGSEGV` at the
`int3` instead of stopping cleanly — an unreapable, untraceable zombie.

So the teardown `munmap` is executed **via the `syscall` gadget**, which lives
in a mapping the target does not own. The gadget path exists anyway (it is how
the cave is created), so this costs one extra code path, not a new mechanism.

## 4. `sigsetjmp`/`siglongjmp` does not work across translation units

Case G hung with the child taking an endless stream of `SIGSEGV` at address
`0x1`. The cause was in the test, not the library: the jump buffer lived in
`harness.cpp` while the `sigsetjmp()` call lived in `t_main.cpp`, and
`siglongjmp()` from the signal handler returned into a frame whose state was
already gone. The target re-executed the instruction that faulted, which
re-faulted, which called the handler again — forever, with `ready` cleared so
the second pass behaved differently from the first.

Non-local jumps are not a cross-TU mechanism. The whole `sigsetjmp`/`siglongjmp`
trio (buffer, arm flag, handler) now lives in `tests/t_main.cpp` next to the
`case_g()` that uses it.

## 5. One owner of `waitpid`

memwatch is the target's parent (that is a Yama requirement, §7), so it is also
the only process that can reap the target. It must reap: `err_gone` is part of
the API contract. The consequence is that the caller's own `waitpid()` returns
`ECHILD` and the exit status would be lost.

Rather than leave callers to discover that, the kernel's status is stored in
the context and exposed through `mw_target_exit()` (src/util.cpp:336). The
alternative designs considered and rejected:

* *Let the caller reap* — impossible; the tracer gets the stop first.
* *Delegate the parent role to a helper process* — adds a process to every
  watch, for a 4-byte status.

## 6. Failure policy: poison, loudly

If an invariant breaks, a register restore fails, or a protection restore
fails, the context is poisoned (`mw_poison()`, src/util.cpp:300): watched pages
keep their `PROT_NONE`, and only `mw_detach()`/`mw_ctx_free()` remain legal.

The tempting alternative — best-effort restore the pages and continue — was
rejected because it hands the target back memory that nothing is watching, with
no signal to the user that the guarantee lapsed. A watchpoint engine whose
failure mode is "silently stopped watching" is worse than one that stops
working loudly. Case L-mprotect pins this behaviour: `mw_watch_del` over a
target-mapped hole returns `err_mprotect`, and the next `mw_watch_add` and
`mw_poll` return `err_poisoned`.

## 7. Decisions

* **No hardware debug registers.** They are limited to 1–4 addresses, per-cpu
  and privilege-bound, and consume them for good on some kernels. The design
  brief is a page-fault engine; this is also what makes arbitrary ranges and
  per-page bookkeeping possible.
* **Faults are handled strictly one at a time.** No batching, no reentrancy.
  Batching would require either letting threads run against a temporarily
  unprotected page (breaks I3) or stopping threads with a fault each (kernel
  does not queue them usefully). Sequential handling costs latency and buys a
  state machine that can be proved.
* **The callback runs with every thread stopped.** It is the only point where
  "the watched value cannot change under you" is true. Consequently the
  callback must not block on anything that needs the target to run, and must not
  assume the value is still current after `mw_poll()` returns.
* **Watches may not overlap** (`mw_watch_page_free`, src/watch.cpp:88 →
  `err_already`). Overlapping watches would make `armed` ambiguous and the
  double validation unable to pick an owner.
* **Per-page protection snapshot.** A watch spanning pages with different
  protections restores each one individually; a range that crosses a hole is
  refused (`err_range`) rather than partially armed.
* **A `syscall` gadget is located by scanning for `0f 05`** in `PROT_EXEC`
  mappings of at most 4 MiB (src/remote.cpp:363). The byte pair is almost always
  a whole instruction in practice, and it does not need to be: memwatch sets
  `rip` to it and executes it as `syscall`, never returning to the surrounding
  context. If no mapping qualifies, the result is `err_nogadget` — never a
  fallback to a fabricated instruction stream, and never address 0.
* **`process_vm_readv`/`writev` for memory access**, so the tracer can inspect
  watched pages while they are `PROT_NONE` without `PTRACE_PEEKDATA`'s
  word-at-a-time semantics.

## 8. Limitations

* **x86_64 only.** The state machine, thread bookkeeping and event
  classification are portable; the stub encoding, the `movabs` emitter and the
  gadget assumptions are not. `include/memwatch/internal.hpp:18` fails the
  build elsewhere rather than producing a broken tracer.
* **Worst case for gadget discovery**: a statically linked target with no
  `0f 05` in a ≤ 4 MiB executable mapping cannot be watched at all
  (`err_nogadget`). Dynamic binaries — everything the test suite and the
  examples use — always have one in libc.
* **Read vs write is not distinguished.** The page fault carries the address,
  not the direction, and memwatch does not try to reconstruct it from the
  faulting instruction.
* **Concurrent faults are not merged.** Two threads faulting on the same page
  produce two sequential events; the second thread's instruction re-faults after
  re-arming and is reported separately.
* **Not invisible.** Signals are forwarded untouched (I10), but a target that
  inspects `/proc/self/maps`, measures fault latency, or counts its own SIGTRAPs
  can infer that it is traced.
* **Cost per event** is structural: one global stop (an interrupt and a wait per
  thread), two remote `mprotect`s and one single step. That is the price of the
  exclusivity guarantees; there is no cheaper path that keeps I2 and I3.
* **`mw_poll` is timeout-driven**, so a caller that never polls never sees
  faults, and the target stays stopped in its handler. This is inherent to the
  "the tracer is the one that un-protects" design.

## 9. Possible future work

In rough order of value:

1. **Non-x86_64 stub emitters** (aarch64 `mov`+`svc #0`, arm32 `svc`), behind
   the same remote-call interface. The state machine does not change.
2. **Read/write classification** by decoding the faulting instruction at
   `f->rip` for the common load/store forms, exposed as a new field on
   `mw_fault_t`. Useful, and strictly a superset of current behaviour.
3. **A `userfaultfd`-based path** for write-protection faults (`PROT_WRITE` +
   `UFFDIO_WRITEPROTECT`), which would avoid the single step entirely for
   writes. It does not help reads and adds a second mechanism, so it is a
   parallel implementation, not a replacement.
4. **Batch reporting** with an explicit "you may run now" callback, if the
   sequential cost ever becomes the binding constraint. It must preserve I3 by
   re-arming before the batch is released.
5. **A fault-rate watchdog** that trips `mw_poison()` when a target's access
   pattern would make the tracer a bottleneck, instead of letting the target
   spend its life in `PROT_NONE`.

## 10. The Lifecycle Scoping Trap: Why `mw_get_fault()` Was Phantom Post-Poll

A classic design defect found in early tracer iterations:
`mw_get_fault(ctx, &out)` was intended to allow callers to inspect the fault that caused `mw_poll()` to return. However, in `src/event.cpp`:

```cpp
  mw_fault_clear(ctx);             // have_fault = false
  ctx->st = mw_state_t::critical;
  ...
  mw_thr_resume_all(ctx, true);
  ctx->st = mw_state_t::idle;
  return r;
```

Because `mw_fault_clear()` is executed immediately before returning to `idle`, `ctx->have_fault` is `false` when `mw_poll()` returns to user code. Calling `mw_get_fault()` after `mw_poll()` unconditionally returns `rc_t::err_not_found`.

**The Architectural Remedy:**
Rather than exposing an ephemeral global context field whose validity is tied to transient internal state transitions, fault reporting belongs either:
1. Direct in the callback invocation parameter (`mw_cb_t(ctx, w, f)`), or
2. Captured in a persistent `last_fault` record that survives transition back to `idle`, or
3. Returned as a direct value in modern C++: `std::optional<fault_info> mw::context::poll(...)`.

## 11. Complex Instructions & Single-Step Replay Fidelity

When `PTRACE_SINGLESTEP` executes on `fault_tid`, not all x86_64 instructions are equal:

* **Repeated String Instructions (`rep movsb`, `rep stosb`)**:
  A `rep`-prefixed instruction executes iteratively, decrementing `rcx`. On Linux x86_64, `PTRACE_SINGLESTEP` over a `rep` string instruction steps **one iteration** (one element transfer), not the entire loop. When the watched page is re-armed with `PROT_NONE`, the subsequent iteration immediately traps again as a new page fault. This guarantees that `libmemwatch` captures every individual element access inside the watched range, rather than skipping the remainder of the rep sequence.
* **Atomic RMW Instructions (`lock cmpxchg`, `lock xadd`)**:
  Bus locks and cacheline locks assert hardware atomicity. Single-stepping a locked instruction causes the entire atomic memory transaction to commit in a single step trap. Because all other target threads are kept in a ptrace stop, inter-thread bus contention is eliminated during the step window.

## 12. Linux & WSL2 Virtualization Nuances

* **`process_vm_readv` / `writev` vs `PTRACE_PEEKDATA`**:
  `PTRACE_PEEKDATA` incurs a context switch and ptrace wait per 8 bytes. For reading memory structures from inside watch callbacks, `process_vm_readv` bypasses ptrace serialization entirely, performing a direct kernel copy between address spaces via page table walks. Under WSL2 (Hyper-V VM running Linux kernel), `process_vm_readv` exhibits minimal overhead.
* **Yama LSM `ptrace_scope=1`**:
  On Ubuntu under WSL2, `/proc/sys/kernel/yama/ptrace_scope` defaults to 1. Non-root tracers can only attach to child processes created via `fork()` (or processes that explicitly call `prctl(PR_SET_PTRACER, tracer_pid)`). Self-contained test drivers must fork their own tracees to guarantee attach authorization.

## 13. Event Loop Latency: From Sleep-Polling to Event Descriptors

Currently, `mw_thr_wait_any()` implements timeout-bounded waiting using a non-blocking `waitpid(-1, WNOHANG)` loop paired with `nanosleep(200us)`. While resilient against lost wait wakeups, 200us sleep slices introduce latency jitter for real-time memory monitoring.

The high-performance architectural path forward:
* **`pidfd_open` + `epoll`**: Linux 5.3+ supports `pidfd_open(pid, 0)`. While standard `waitpid()` is signal-based, integrating `signalfd` on `SIGCHLD` into an `epoll_wait` event loop enables sub-microsecond event reaction without spinning in userland sleeps.

## 14. Zero-Dependency Address Symbolization via `/proc/<pid>/maps`

Developers debugging or tracing memory access rarely want raw pointers like `0x7ffff7dd2120`. They need human-readable identifiers: `libxyz.so+0x1120`.

Full DWARF/ELF parsing (e.g. `libdw`, `libbacktrace`) adds heavy external dependencies, requires parsing `.debug_info` sections, and fails on stripped binaries. 
By contrast, `/proc/<pid>/maps` provides an ideal zero-dependency solution:
1. Each line maps a virtual range `[lo, hi)` to a shared library, binary path, or pseudo-path (`[heap]`, `[stack]`, `[vdso]`).
2. An address $A \in [\text{lo}, \text{hi})$ is uniquely represented as `basename(path) + (A - lo)`.
3. Because `libmemwatch` already parses `/proc/<pid>/maps` during `capture_prot()`, address resolution is essentially an in-memory lookup taking $\mathcal{O}(M)$ where $M$ is the number of mappings (typically $< 100$).

## 15. Disassembly Leverage: Capstone vs Ad-hoc Opcode Parsing

Inferring whether an access is a read or write by manually parsing x86_64 opcodes is a notorious rabbit hole:
* Variable-length instructions (1 to 15 bytes).
* ModR/M and SIB bytes.
* REX prefixes, legacy prefixes, operand-size overrides (`0x66`, `0x67`).
* RMW instructions (`add [rax], 1`) which are both a read and a write.

Rather than leaking complex, fragile architecture-dependent decoding into `libmemwatch`'s core:
* The core engine stays lean and purely reports the exact faulting `addr`, `rip`, and machine registers.
* For consumers needing disassembly or instruction size (to advance `regs.rip` and use `MW_ACTION_SKIP`), **Capstone (`libcapstone`)** is the recommended companion. In under 10 lines of code, Capstone disassembles the instruction at `regs.rip`, yields `insn.size` for instantaneous instruction skipping, and cleanly classifies operand registers without bloating the tracer library.

## 16. The Interactive Console Architecture (Linenoise)

A natural evolution for `libmemwatch` is dropping into an interactive CLI shell when a watchpoint hits.
Because the callback executes while all threads are stopped:
* **Linenoise** (< 1,000 lines of pure C, zero dependencies) can be embedded to read commands from `stdin`.
* Commands like `regs` (dump GPRs), `x/16b <addr>` (examine memory), `bt` (print backtrace via maps), `skip` (advance RIP), or `c` (continue) can drive the interceptor directly from the terminal without GDB.