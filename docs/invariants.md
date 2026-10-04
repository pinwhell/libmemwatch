# Invariants

The library's correctness claim is a small set of statements about *who is
allowed to execute user instructions in the target*. Everything else in
`src/` is bookkeeping. This file lists the statements, where each is enforced
in code, and how each one is tested **against the kernel** rather than against
memwatch's own opinion.

Last full run: optimised and `-O0 -g3` builds warning-free, 14/14 cases,
40/40 stress rounds, `stats.inv_violations == 0` everywhere.

## The checker

`mw_inv_check()` — src/util.cpp:229 — is called from 17 sites, named by the
transition it guards:

```
ctx.cpp:175     detach/stopped            remote.cpp:123  remote/unwind
event.cpp:326   forward_and_resume        remote.cpp:225  call_via_gadget
event.cpp:334   abort_and_resume          remote.cpp:358  call_via_stub
event.cpp:337   abort_and_resume/idle     thr.cpp:372     stop_all
event.cpp:381   fault/after_global_stop   thr.cpp:378     ensure_all_stopped/fast
event.cpp:465   sstep/armed               thr.cpp:384     ensure_all_stopped
event.cpp:517   rearming/after_step       watch.cpp:55    enter_critical
event.cpp:532   fault/before_resume       watch.cpp:61    leave_critical
event.cpp:538   fault/after_resume
```

It bumps `stats.inv_checks`, logs the violated rule with the state and the
running/alive counts, and returns `err_invariant`. The caller decides what to
do; in the middle of a fault sequence that means `mw_poison()`.

The rules, in the order the checker tests them:

| # | rule | audit |
| --- | --- | --- |
| 1 | `in_rcall == (borrow_tid != 0)`, and `in_rcall` only in state `rcall` | I1 |
| 2 | `have_fault` implies a non-null `fault_watch` and a fault-handling state (`critical`, `rcall`, `sstep`, `rearming`) | I4 |
| 3 | `entering`/`critical`/`rearming`: **zero** threads with `running == true` | I3 |
| 4 | `rcall`/`sstep`: at most one running thread, and if one, it is `borrow_tid`/`fault_tid` respectively | I2 |

`idle` and `detaching` are deliberately **not** constrained: after
`mw_thr_resume_all()` the target is running by design, and
`mw_inv_check(ctx, "fault/after_resume")` runs in exactly that state. Adding a
"no thread may run in `idle`" rule would fire on every single event.

`have_fault` is deliberately allowed in `rcall`/`sstep`/`rearming`: the fault
being serviced *is* why those states exist. An earlier version of the design
said `critical` only, which fired spuriously on every event.

## Audit

Each row is enforced in the listed code and observed from outside the library.

| ID | invariant | where enforced | how it is tested | result |
| --- | --- | --- | --- | --- |
| I1 | `in_rcall == (borrow_tid != 0)`, and only while in `rcall` | src/util.cpp:236-244 | every case; `remote_calls`/`inv_checks` in stats | PASS |
| I2 | at most one thread executes user code, and only `borrow_tid` (rcall) or `fault_tid` (sstep) | src/util.cpp:274-288 | cases A-M + 40 stress rounds; `obs.running_violations`, `obs.proc_running_violations` | PASS |
| I3 | zero threads execute user code in `entering`/`critical`/`rearming` | src/util.cpp:265-273 | `obs_cb` re-checks from `/proc/<pid>/task/*/stat` on **every** event; cases A, C, D, G, H, I, M | PASS |
| I4 | a pending fault exists only in the states that handle it | src/util.cpp:246-259 | all cases, especially K (target exit mid-sequence) and I (add/del mid-run) | PASS |
| I5 | `armed` ⇔ the pages really are `PROT_NONE`, and it flips around the remote `mprotect` | src/watch.cpp:103-148, src/event.cpp:441-530 | `obs_cb` reads `/proc/<pid>/maps` on every event (`obs.prot_violations`); cases D, I, L-mprotect | PASS |
| I6 | double validation after the stop: siginfo re-read *and* covered by an armed watch | src/event.cpp:386-403 | G (a SIGSEGV at `0x1`, unrelated to any watch, is forwarded instead of owned), M (non-watch signals never become owned faults); the range half is checked at arm time by L | PASS |
| I7 | a remote call is atomic: one thread, registers fully restored, only the controlled `SIGTRAP` accepted | src/remote.cpp:129-380, `unwind()` src/remote.cpp:109 | every basic case is effectively 1 event per access, so a lost or duplicated event fails immediately; `verify()` checks the target's own per-thread checksums (computed *after* its registers were overwritten with syscall arguments) and `remote_calls >= 2 * events` | PASS |
| I8 | the single step is exclusive to `fault_tid` and consumed by the state machine, not by `mw_poll` | src/event.cpp:447-518 | H (2000 faults); `verify()` asserts `ssteps == events` and `faults_owned == events` | PASS |
| I9 | threads created by the target are tracked and cannot escape the discipline | src/event.cpp:154-169, `mw_thr_add_cloned()` src/thr.cpp:87 | E (creation while armed), C (4 threads), F (short-lived threads) | PASS |
| I10 | signals memwatch did not cause are forwarded untouched, with their original siginfo | src/event.cpp:310-325 | G (child handler at `0x1` runs exactly once, `corrupt == 0`), M (SIGBUS/SIGILL/SIGTRAP/SIGUSR1/SIGFPE, one each) | PASS |
| I11 | if a restore fails, poison: the watch stops representing reality and the context refuses further work | src/util.cpp:300, src/watch.cpp:130-142 | L-mprotect: `mw_watch_del` over the target's hole returns `err_mprotect`, and the next `mw_watch_add`/`mw_poll` return `err_poisoned` | PASS |
| I12 | exactly one owner of `waitpid`: memwatch keeps the exit status | src/event.cpp:131-138, `mw_target_exit()` src/util.cpp:336 | K (status `0x700` = exit 7; the caller's `waitpid` gets `ECHILD`) | PASS |

## What is *not* guaranteed

Stated explicitly, because a watchpoint engine that oversells itself is worse
than one that does not exist:

* **The callback is not atomic with respect to *future* accesses.** During the
  callback nothing runs; immediately after `mw_poll()` returns, every thread
  runs again. A callback must not assume the watched value is still what it
  read.
* **The kernel reports the address, not the access.** `si_code` distinguishes
  `SEGV_MAPERR` from `SEGV_ACCERR` and `si_addr` gives the byte; memwatch does
  not claim to distinguish reads from writes (x86_64 page faults do not carry
  that bit in a form memwatch relies on).
* **No ordering between concurrent faults from different threads.** The first
  fault to be reaped wins the `critical` section; a second thread's fault is
  re-raised after the pages are re-armed, so it is reported as a separate
  event. Two faults are never merged.
* **Poisoned contexts are not usable.** After `err_invariant`,
  `err_stub_write`, a failed register restore or a failed protection restore,
  only `mw_detach()`/`mw_ctx_free()` are legal; the pages stay `PROT_NONE`,
  which means the *target* keeps faulting. That is deliberate (see
  `docs/design-notes.md` §6).
* **x86_64 only.** The state machine is portable; the stub encoding and the
  `movabs` emitter are not. `include/memwatch/internal.hpp:18` refuses to
  compile elsewhere instead of pretending.
* **Not transparent to a hostile target.** A target that reads
  `/proc/self/maps`, times the faults, or simply calls
  `ptrace(PTRACE_TRACEME)`-style anti-debug tricks can tell it is being traced.
  memwatch's guarantee is I10 (no *signal* is altered), not invisibility.

## Adding an invariant

1. Add the rule to `mw_inv_check()` with a comment naming the failure it
   prevents, not the code it reads.
2. Call it at the transition where the rule becomes true (not only where it
   becomes false).
3. Add or extend a case in `tests/t_main.cpp` that can *fail*: a checker-only
   invariant with no test is documentation, not verification.
4. Extend the `obs_cb` kernel cross-check in `tests/harness.cpp` if the
   invariant is observable from `/proc`.
5. Add the row here and put the case letter in the "how it is tested" column.