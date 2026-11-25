# Give the command target ownership of its private PTY

[Issue #861](https://github.com/rock3r/remozio/issues/861) · Design based on `062e9ad509e6af7eeb006e9f0426d423de00a51b`

## Current behavior

The Root command controller allocates a fresh pseudoterminal (PTY) after checking the approved target and retained resources. The caller’s terminal supplies only attributes and size. `RetainedCommandPTY` calls `remozio_command_pty_create`, which uses `openpty`, sets close-on-exec on both descriptors and makes the master nonblocking. [Command preparation](../macos/core/Sources/RemozioCore/CommandExecution.swift#L69-L99) · [PTY allocation](../macos/core/Sources/RemozioMach/CommandPTY.c#L16-L40)

Apple’s `openpty` calls `grantpt` and unlocks the slave before opening it. In the published XNU source, the slave starts as `root:tty` with mode `0620`. The grant sets the owner to the allocating identity and applies the same group and mode. A Root allocation therefore gives the slave `root:tty` and `0620`. This is a source-based finding. Capture the actual metadata on each supported macOS runtime when qualifying the change. [Apple Libc](https://github.com/apple-oss-distributions/Libc/blob/main/util/pty.c#L69-L91) · [XNU allocation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/tty_ptmx.c#L353-L356) · [XNU grant](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/tty_dev.c#L1037-L1045)

The monitor receives the slave and sets up the controlling terminal. The controller closes its own slave descriptor after spawn. The launcher validates and adopts the target credentials, then waits for release before `execve`. Changing the launcher’s UID leaves the device node owned by Root. Inherited descriptors still work. A non-Root target normally lacks read/write access when a program reopens its own slave by name. [Descriptor mapping](../macos/core/Sources/RemozioCore/CommandExecution.swift#L99-L131) · [Monitor setup](../macos/app/CommandMonitor/MonitorMain.c#L117-L141) · [Credential adoption](../macos/core/Sources/RemozioMach/CommandAccountCredentials.c#L52-L58) · [Launch and release](../macos/app/CommandChild/ChildMain.c#L126-L151)

## Access during preparation

From the time Darwin unlocks the slave, an unrelated process with access through the `tty` group has write permission on the slave node under `0620`. The group bit grants no read access. A different unprivileged account outside that group has neither permission. Terminal job control and platform policy can impose further restrictions. The current default persists for the life of the pair. Root and processes with existing descriptors retain their access. [XNU grant and unlock](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/tty_dev.c#L1037-L1077)

With the proposed `0600` mode, the target UID gets read/write access when ownership transfers. Other processes under the same UID share that permission from then on, including before release. An independent UID gets no access through the mode bits. Changing mode controls future opens. Existing descriptors keep their access. The master stays inside the controller.

## Proposed change

1. Pass `capture.target.uid` and its primary `gid` from the checked command capture into private PTY preparation. These are the same values the private launch frame supplies to the launcher. Keep the current account and release checks. [Target recheck](../macos/core/Sources/RemozioCore/CommandExecution.swift#L69-L84) · [Launch frame](../macos/core/Sources/RemozioCore/CommandChildLaunchSpecification.swift#L69-L78)
2. For a non-Root target, use the fresh, owned slave descriptor inside `CommandPTY.c`. Confirm it is a terminal character device. Set `0600` with `fchmod` as soon as `openpty` returns and before changing the owner. Transfer the UID and primary GID with `fchown` before handing the slave to the monitor. Use `fstat` to check the device identity, UID, GID and mode before continuing. This keeps permission changes on the open device and gives the destination account owner access only after group write permission is removed. The brief interval inside `openpty` still has Darwin’s default permissions.
3. Send any allocation, ownership, permission or verification error through the existing pre-spawn failure path. Close both descriptors and stop before starting the monitor. Use the same path for full and mapped PTYs. Keep the Root target on the existing allocation path. Pipe mode and borrowed caller descriptors have no ownership operation. [Allocation cleanup](../macos/core/Sources/RemozioMach/CommandPTY.c#L25-L40) · [Mapped and full PTY paths](../macos/core/Sources/RemozioCore/CommandExecution.swift#L119-L131)

Allocation under the target account would require a separate credential-bound helper and a descriptor handoff. The descriptor change uses the existing controller and preserves its process credentials.

## Verification

| Case | Expected result |
| --- | --- |
| Non-Root target, full PTY | The fixture captures the fresh slave metadata before spawn and confirms the target UID, primary GID and `0600`. After release, the target reopens its own fixture terminal read/write. The reopened device matches the inherited slave, and the original stream drain and exit checks pass. |
| Non-Root target, mapped PTY | The controlling terminal and PTY-backed stream descriptors refer to the same slave. Direct stream descriptors retain their original identity and metadata. |
| Allocation or metadata fault | Inject failures in `fchmod`, `fchown` and verification. The controller closes the fresh pair, starts no monitor and reports a failure before start. |
| Root target | Compare the slave metadata to a fresh baseline allocation under the same Root fixture. The existing owner, group and mode remain the same. Controlling terminal, release and drain still work. |
| Pipe mode and caller terminal | Pipe mode allocates no PTY. In PTY mode the caller terminal supplies geometry and attributes while its metadata stays the same. |

Extend the [PTY tests](../macos/core/Tests/RemozioCoreTests/CommandPTYTests.swift#L30-L49) and [native process tests](../macos/core/Tests/RemozioCoreTests/CommandProcessTests.swift#L288-L386). Run fault and lifecycle checks with ordinary fixtures. Verify the actual UID and GID transfer and the Root baseline in attended macOS fixtures with the required privileges. This review branch records source findings and proposed checks. Runtime validation is pending.
