# #988 PR2 plan: Swift authority, systemd unit, AppArmor and sudo

Status: draft for Toni. Builds on PR1 (#994, stub authority, 29/29 on one host).
PR2 runs the rows that `docs/linux-single-owner-design.md` leaves to it ("Cases in
PR1", last paragraph, and "Not verified"). It is still an opt-in experiment. It adds
no production executor and no installer.

## Scope

1. Replace the Python stub authority with a Swift authority built from the composed
   fixture. It keeps decision verification, the SQLite transaction and the permit.
2. Run O (the PR1 `owner.c`, unchanged except where noted below) inside a transient
   systemd unit with exactly the unit options in the design's "Unit options".
3. Load an AppArmor profile for O with the `ux` rule, kernel-only, as the monitor
   confinement experiment does.
4. Measure `sudo` inside the command: the password prompt and the `sudo` child's
   capability sets.

## Files

| Path | Change |
| --- | --- |
| `experiments/linux-single-owner/authority/Package.swift` (new) | Swift 6.2 package. Same dependencies as `experiments/linux-composed-caller-command/Package.swift`: `LinuxApprovalFixtureCore`, `LinuxOSObservation`, `RemozioHostCore`, `RemozioProtocol`, swift-crypto. |
| `experiments/linux-single-owner/authority/Sources/.../main.swift` (new) | The authority A. Uses `FixtureStore.consume(...)` for the decision and the SQLite transaction, `FixtureStore.dispatched(_:)` for the durable `beginDispatch`, then `succeeded()`, `failed()`, `provedNoDispatch()` or `lostOutcome()` for the outcome. It issues the one-use permit bound to O's generation (boot_id, pid + start time, 128-bit random) and checks O through `SO_PEERPIDFD`, as the PR1 stub does now. It runs as its own disposable user with no capabilities. |
| `experiments/linux-single-owner/owner.c` | Only if Toni agrees to the two-dispatch row (open question 1): a `poll` loop so that one thread can hold two dispatches. Otherwise unchanged. |
| `experiments/linux-single-owner/apparmor.in` (new) | Template like `experiments/linux-monitor-confinement/profiles.in`: one profile for O with `capability sys_ptrace, setuid, setgid`, the ptrace/signal peer rules for the frontend, and `ux` for the command image. Loaded with `apparmor_parser -a -K`, removed by name at the end. |
| `scripts/run-linux-single-owner-experiment.py` | A `--pr2` mode (or a separate runner, Toni's choice): it starts the authority and O as transient units with `systemd-run` (no file under `/etc`), and adds the cases below. The PR1 cases stay as they are. |
| `tests/test_linux_single_owner_experiment.py` | Non-root tests for the new parsing and the negative controls (unit-option rendering, `NoNewPrivs:` and namespace checks, AppArmor template rendering, report rules). |
| `scripts/ci-build-cache.py`, `docs/ci-build-cache.md` | Linux-only inputs for the Swift package. |
| `docs/experiments/linux-single-owner.md`, `docs/linux-single-owner-design.md` | PR2 cases, the recorded result, and "Not verified". |

## Cases

Every case records the authority outcome from SQLite, the marker count and O's
restart log, as in PR1.

| Case | Expected result |
| --- | --- |
| Unit options from inside a command: `NoNewPrivs:` and the mount namespace (`/proc/self/ns/mnt` vs PID 1's) | `NoNewPrivs: 0`, host mount namespace |
| Negative controls: the same unit with `NoNewPrivileges=yes`, and with `PrivateTmp=yes` | The check fails: `NoNewPrivs: 1`, or a different mount namespace (proves that the check can fail) |
| `KillMode=process`: unit stop and unit restart while a command runs after S6 | The command keeps running; marker count 1 |
| `OOMPolicy=continue`: an out-of-memory kill of a memory hog in the unit cgroup while a command runs | O and the command keep running (how to cause it: open question 3) |
| `TasksMax=infinity`, `Limit*=` max | Read back from `systemctl show` and from `/proc/<O>/limits` |
| Capability sets of the command under the unit | `CapPrm/Eff/Inh/Amb` empty, `CapBnd` the full system set |
| `sudo` child of the command (non-interactive rule, open question 2) | Root's normal sets |
| `sudo` with a password prompt, streams on a terminal | Expected: `sudo` finds no controlling terminal and refuses. Recorded as the measured result, not fixed (the design leaves the terminal relay to a decision) |
| AppArmor: O under its profile with `ux` | O's label is the profile; the command's label is `unconfined`; `sudo` works inside it |
| Two dispatches at the same time (if accepted) | Each K holds only its streams and its two pipe ends; O holds only its own ends |
| `dispatch-race-limitation` from the composed fixture | No command for every O death before the go byte |
| Swift authority: a replayed permit, a permit of an earlier O generation, a wrong peer | Refused; marker count 0 |

The report can set `strictAdmission` to true only when every case passes
(open question 4). `productionAdmission` stays false.

## CI and the Root run

- CI: build the fixtures and the Swift package on Linux, run the non-root tests.
  No root, no systemd, no AppArmor, as in PR1.
- The Root run: once, supervised, on the Linux host owner's machine, through sudo,
  with the owner present. The runner removes every transient unit, the AppArmor
  profile, the disposable users and any sudoers file it added, and it reports each
  cleanup step. The evidence holds booleans, errno names, categories, settings and
  hashes only.
- The PR1 conditions apply again: refuse if the new UIDs already have processes,
  bounded `O_NOFOLLOW` reads, cleanup in `finally` with a test, `--allow-sysctl`
  off by default, the delta to Toni before the Root run.

## What stays off

- No production executor. No unit file under `/etc/systemd`, no installer change
  (the repository has no Linux installer today), nothing enabled at boot.
- `productionAdmission` false. No change to the host contract.

## Open questions for Toni

1. **Two dispatches at the same time.** O is single-threaded and handles one
   dispatch at a time. Overlap needs a `poll` loop in `owner.c`. Do it in PR2, or
   measure only "a second dispatch while the first command runs after S6"?
2. **The `sudo` child.** Its capability sets need `sudo` to succeed. Options: a
   disposable caller account with a `NOPASSWD` drop-in in `/etc/sudoers.d` that
   the runner writes with mode 0440, checks with `visudo -cf`, and removes in
   cleanup; or skip that row. The PR1 runner changed no sudoers file.
3. **Out-of-memory kill.** A case-only `MemoryMax=` on the unit with a memory hog
   in the command, or `SIGKILL` to O as a stand-in? `MemoryMax=` sets no
   `no_new_privs` and no mount namespace.
4. **`strictAdmission`.** The `sudo` password-prompt row will fail by design (no
   controlling terminal). Does that row gate `strictAdmission`, or is it recorded
   as a known limitation that waits for the terminal decision?
5. **One runner or two.** A `--pr2` mode in the PR1 runner, or a separate script?

## What PR2 does not establish

- A production executor, an installed unit, the installer setting, or upgrade from
  an older unit.
- The terminal relay for `sudo` (a separate decision).
- More than one host and kernel, more than one local account (decision 7), TPM use
  (decision 4), a target identity of Root, and the post-dispatch contract for C
  after S6.
