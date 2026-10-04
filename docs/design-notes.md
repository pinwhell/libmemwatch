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