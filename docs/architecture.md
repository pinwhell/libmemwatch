# Architecture

`libmemwatch` watches a range of another process's address space and reports
every access to it, without cooperation from that process and without hardware
debug registers. It is a **tracer library**: the process that links it becomes
the parent-tracer of the target (`ptrace`), so under Yama `ptrace_scope=1` the
target must be a child of the caller.

## 1. Mechanism

Three kernel facts do all the work:

1. `PTRACE_SEIZE` + `PTRACE_INTERRUPT` gives a *group stop* of every thread of
   the tracee without disturbing their register state or pending signals.
2. `mprotect(PROT_NONE)` on a page makes any access to it raise `SIGSEGV` with
   `si_addr` set to the exact faulting address, in *every* thread that touches
   it, at the instruction that touches it.
3. A stopped tracee can be made to execute a `syscall` on the tracer's behalf
   (register injection + `PTRACE_SINGLESTEP`), and `PTRACE_GETSIGINFO`
   reports the address of the faulting instruction.

So the engine is: **make the pages unfaultable, let the kernel stop the
offender, take the whole process away from itself, ask the user what to do,
unprotect, let exactly one instruction execute, re-protect, and give the
process back.** Everything in `src/` exists to make step 4 ("take the whole
process away") and step 6 ("let exactly one instruction execute") provably
exclusive, because a tracer that is not exclusive is just a race generator.

```
   target threads           memwatch (parent-tracer)
   ---------------          --------------------------
   running freely
        |  write to watched page
        v
   SIGSEGV (si_addr, faulting rip)
        |                          mw_poll() reaps it, classify()
        |                          state = entering
        |                          PTRACE_INTERRUPT to every tid
        |<-- group stop ---------  mw_thr_stop_all(): drain until 0 running
        |                          state = critical
        |                          double validation (GETSIGINFO + coverage)
        |                          callback(ctx, watch, fault)   <-- all stopped
        |                          state = rcall: armed=false, remote mprotect
        |                          remote mprotect(restore real prot)
        |                          restore full user_regs_struct
        |                          state = sstep: only fault_tid runs, 1 insn
        |<-- SIGTRAP ------------  re-entering/critical, remote mprotect(PROT_NONE)
        |                          state = rearming -> idle, armed=true
        |                          resume every thread
   running again
```

## 2. State machine

`mw_state_t` (include/memwatch/types.hpp:58) is the spine of the design. Every
legal transition is listed below; `state_allows_remote()`
(src/remote.cpp:47) refuses a remote syscall in any other state, and
`mw_inv_check()` (src/util.cpp:229) asserts the state-dependent invariants.

| state | meaning | threads allowed to execute user code |
| --- | --- | --- |
| `idle` | target runs freely | all |
| `entering` | candidate fault seen, forcing the global stop | shrinking to none |
| `critical` | all alive threads stopped, no remote call / single step active | **none** |
| `rcall` | remote syscall in progress | **only `borrow_tid`** |
| `sstep` | `PTRACE_SINGLESTEP` in progress | **only `fault_tid`** |
| `rearming` | post-single-step, re-installing `PROT_NONE` | **none** |
| `detaching` | restoring protections and detaching | none |

The fault sequence is `mw_ev_handle_fault()` (src/event.cpp:346):

1. `entering` — `mw_thr_stop_all()`.
2. `critical` — re-read the siginfo *after* the stop, classify
   `SEGV_MAPERR`/`SEGV_ACCERR`, and require the fault address to be covered by
   an **armed** watch. Anything else is an unrelated fault and is forwarded
   untouched.
3. callback — the user's `mw_cb_t` runs here, with zero target threads running,
   so the target cannot make progress underneath it.
4. `rcall` — `armed = false` **before** the remote `mprotect` that restores the
   captured protections.
5. restore the borrowed thread's complete `user_regs_struct` (the `syscall`
   clobbers everything).
6. `sstep` — `PTRACE_SINGLESTEP` on `fault_tid` only. Its `SIGTRAP` is the
   continuation of this function, not an event for `mw_poll`.
7. `rearming` — global stop again, remote `mprotect(PROT_NONE)`, `armed = true`
   **after** the protection is really installed.
8. clear the pending fault, resume everything, back to `idle`.

Steps 4-7 happen on *every* owned fault, including faults raised from inside the
user's own callback. There is no fast path, because a fast path is a window in
which two threads can execute against an unprotected page.

## 3. Ownership of memory: `armed`

`mw_watch_t::armed` is **not** a cache of the last `mprotect` argument. It is
the ownership flag that says "these pages are `PROT_NONE`, therefore a fault on
them is memwatch's business, therefore the tracer is responsible for it". The
ordering around it is the single most delicate rule in the codebase:

```
   armed = false;                        <-- BEFORE the mprotect
   remote mprotect(real protections);    <-- window where pages are readable
   ...
   remote mprotect(PROT_NONE);
   armed = true;                         <-- AFTER the mprotect
```

`mw_watch_arm()` (src/watch.cpp:103) and `mw_watch_disarm()`
(src/watch.cpp:116) are the only places that flip it, both inside a critical
section with all threads stopped. Case I of the test suite asserts this ordering
directly against `/proc/<pid>/maps`.

A watch keeps the **requested** range in `w->r` plus the page-aligned
expansion (`p0`, `pcount`) and a per-page `prot[]` snapshot (`capture_prot`,
src/watch.cpp:14). Watches never overlap (`mw_watch_page_free`, src/watch.cpp:88);
overlap is `err_already`, because two watches owning one page would make
`armed` ambiguous.

## 4. Remote calls

memwatch cannot call `mprotect` in the target's context: `ptrace` has no
"execute this function for me". It therefore builds a syscall stub in the
target's address space.

**Bootstrap.** `gadget_scan()` (src/remote.cpp:363) looks for the two bytes
`0f 05` (`syscall`) in any `PROT_EXEC` mapping of at most 4 MiB. That is almost
always libc or the vDSO. With a gadget and the faulting thread already stopped,
`call_via_gadget()` (src/remote.cpp:129) sets the six argument registers plus
`rax` to the syscall number, points `rip` at the gadget and
`PTRACE_SINGLESTEP`s. The instruction after `syscall` traps, the return value
is in `rax`, and the snapshot is restored.

**Code cave.** That single ability is used to `mmap` one private
`PROT_READ|WRITE|EXEC` page in the target (`mw_remote_init`,
src/remote.cpp:403). From then on, `call_via_stub()` (src/remote.cpp:232)
writes a 73-byte stub at the start of that page and runs it with `PTRACE_CONT`:

```
   movabs rax, nr              48 b8 ....      syscall number
   movabs rdi, a0              48 bf ....
   movabs rsi, a1              48 be ....
   movabs rdx, a2              48 ba ....
   movabs r10, a3              49 ba ....
   movabs r8,  a4              49 b8 ....
   movabs r9,  a5              49 b9 ....      6th argument
   syscall                     0f 05
   int3                        cc             controlled exit -> SIGTRAP
```

(The six argument registers are `rdi, rsi, rdx, r10, r8, r9` — the x86-64
syscall ABI does not use `rcx`.) The stub lives entirely in memwatch's own page,
so a crash inside it damages nothing but the cave, which is discarded anyway.
The `int3` is the *only* accepted stop while the cave runs (src/remote.cpp:329);
any other signal is `err_unexpected` and poisons the context.

**Teardown.** `mw_remote_fini()` (src/remote.cpp:439) cannot let the cave
`munmap` itself — the syscall would return into the page it just removed and
die with `SIGSEGV` instead of reaching the `int3`. It therefore runs
`munmap` *via the gadget*, which lives in a mapping the target does not own.

## 5. Threads

`thr_t::running` means exactly one thing: *we issued `PTRACE_CONT` or
`PTRACE_SINGLESTEP` for this tid and have not yet reaped the resulting stop.*
That is the only definition that makes the global stop provable — zero running
threads means zero user instructions can be executing.

* `mw_thr_sync()` (src/thr.cpp:139) reconciles the table with
  `/proc/<pid>/task`, reaping dead threads and discovering threads that
  appeared without an event.
* `PTRACE_O_TRACECLONE` delivers `PTRACE_EVENT_CLONE`; the new tid arrives
  already in a ptrace-stop (`init_stop`) and is registered by
  `mw_thr_add_cloned()` (src/thr.cpp:87).
* `mw_thr_stop_all()` (src/thr.cpp:290) sends `PTRACE_INTERRUPT` to every alive
  thread and then drains until `mw_thr_count_running() == 0`, bounded by a 50 ms
  deadline and `MW_STOP_MAX_ROUNDS` re-interrupt rounds. The deadline is not
  paranoia: a target that clones in a tight loop can absorb interrupts
  indefinitely, and this loop is what keeps the tracer from hanging.
* `pick_borrow()` (src/remote.cpp:77) chooses the remote-call thread: alive,
  in a ptrace-stop, not the thread currently single-stepping, preferring one
  that is not about to be reported as dead. If there is no such thread, the
  result is `err_nothread` — never a guess.

## 6. Events

`mw_ev_classify()` (src/event.cpp:56) turns a wait status into one `ev_t`
(include/memwatch/event.hpp:7):

| event | source | action |
| --- | --- | --- |
| `target_exit` | last thread of the process | record status, set `err_gone` semantics |
| `thread_exit` | `PTRACE_EVENT_EXIT` or reap | mark dead, never resume |
| `clone` | `PTRACE_EVENT_CLONE` | register the new tid, resume it |
| `fault` | `SIGSEGV`/`SIGBUS` with `SEGV_MAPERR`/`ACCERR` | `mw_ev_handle_fault()` |
| `step_trap` | the `SIGTRAP` we asked for in `sstep` | consumed by the state machine |
| `stray_trap` | any other `SIGTRAP` | forwarded (not ours) |
| `group_stop` | `SIGSTOP`, `PTRACE_EVENT_STOP` | record, do not resume inside a critical state |
| `signal` | anything else | `forward_and_resume()` with the original siginfo |

`forward_and_resume()` (src/event.cpp:310) is the transparency rule: it
re-installs the original `siginfo_t` with `PTRACE_SETSIGINFO` and resumes with
`PTRACE_CONT(tid, sig, 0)`, so a signal memwatch did not cause is delivered to
the target exactly as if memwatch did not exist. Case G proves it: a child
handler at `0x1` runs exactly once for a fault memwatch did not own, and the
watched data is not corrupted.

## 7. Failure policy

Every internal check funnels into `mw_inv_check()` (src/util.cpp:229). On
violation — or on any failed register restore or failed protection restore —
`mw_poison()` (src/util.cpp:300) marks the context unusable: watched pages keep
their `PROT_NONE`, `stats.inv_violations`/`cleanup_failures` are bumped, and
only `mw_detach()` and `mw_ctx_free()` remain legal. The alternative
(un-protecting memory whose restore failed) would silently give the target
unwatched memory back, which is exactly the failure mode the library exists to
prevent.

`rc_t` (include/memwatch/types.hpp:36) extends the design's error set with
`err_nogadget`, `err_invariant`, `err_gone`, `err_range` and `err_poisoned` so
that no failure can be reported as success.

## 8. Public API

`include/memwatch/api.hpp` is the only public header (`extern "C"` plus C++
types):

| function | role |
| --- | --- |
| `mw_ctx_init` / `mw_ctx_free` | lifecycle; `free` detaches |
| `mw_attach(pid)` | seize all threads, install options, discover gadgets |
| `mw_detach()` | restore protections, drop the watches, detach |
| `mw_watch_add(base, size, cb, ud)` | validate, capture protections, arm |
| `mw_watch_del(base, size)` / `mw_watch_del_all()` | disarm and forget |
| `mw_poll(ctx, timeout_ms)` | reap and handle events; returns on owned faults |
| `mw_get_fault()` | the last owned fault |
| `mw_target_exit(ctx, &status)` | the wait status memwatch reaped, if the target died |
| `mw_read_mem` / `mw_write_mem` | `process_vm_readv/writev` |
| `mw_get_state`, `mw_get_stats`, `mw_strerror` | introspection |

Note `mw_target_exit()`: memwatch must reap the target's death itself (it is the
parent, and it needs the exit to report `err_gone`), so the kernel's wait
status is kept in the context rather than lost — the caller's own `waitpid()`
returns `ECHILD`.