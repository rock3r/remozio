# Firebase credential file import

[Issue #866](https://github.com/rock3r/remozio/issues/866) · source `e677208cf2065f3f84d6fccb0df81e0cd75b86f3`

## Current path

- [`GatewaySetupSheet.swift:34–42`](../macos/app/App/GatewaySetupSheet.swift#L34-L42) handles the picker result in the SwiftUI callback. It starts security-scoped access, opens the URL synchronously at line 38, reads up to 65,537 bytes at line 39, and parses them at line 40. The open has neither an explicit nonblocking flag nor a check that the descriptor represents a regular file. The byte count limits the read only after the open completes. This is a source finding.
- [`GatewaySetupForm.swift:99–111`](../macos/core/Sources/RemozioCore/GatewaySetupForm.swift#L99-L111) already rejects empty or oversized data and validates the Firebase service account fields. Keep this validator and the 65,536-byte limit.
- [`SetupFilePreviewReader.swift:17–53`](../macos/core/Sources/RemozioCore/SetupFilePreviewReader.swift#L17-L53) shows the existing actor and security-scope pattern. Its low-level read is nonblocking, validates the opened descriptor, and caps bytes even if the file grows. It uses the encrypted setup file limit and currently allows the open to follow a final symlink.

## Proposed change

1. Let the picker start an async import. Use a dedicated reader actor outside `MainActor` for security-scoped access, open, read, and validation. Pass the selected URL into the actor and return only the validated `SetupFCMConfiguration`. Pair security-scope cleanup with successful acquisition and close the descriptor on every path.
2. Share the bounded descriptor read from `SetupFilePreviewReader` as an internal implementation detail. Give the Firebase reader its own flags and size limit. Use `O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`. Preserve the encrypted setup preview's existing flags and size limit.
3. Use `fstat` on the open descriptor. Require a regular file (`st_mode & S_IFMT == S_IFREG`) and a size from 1 through 65,536 bytes before reading. Reject a final symlink at open. Read from that same descriptor with a maximum of 65,537 bytes so an observed extra byte rejects a file that grows. Keep the existing handling of interrupted reads and cancellation. Pass accepted bytes through `SetupFCMConfiguration(serviceAccountJSON:)`.
4. Keep picker state and result handling on `MainActor`. Show progress and disable choose, replace, and prepare while an import is in flight. Keep Close available. Cancel and invalidate the import on close or disappearance so a late result cannot restore a credential or change another sheet's state. Only a successful current import replaces the provider and clears the import warning. Keep credentials in memory until the existing explicit preparation path.

## Rejected file

Show the existing inline warning next to the Firebase chooser ([`GatewaySetupSheet.swift:168–178`](../macos/app/App/GatewaySetupSheet.swift#L168-L178)). On the first import it asks for a valid Firebase JSON file. On replacement it says that the previous project is still selected. Re-enable the chooser when the import finishes. Keep picker cancellation silent and retain existing choices. Keep raw errors, paths, and credential contents out of the warning and logs.

## Validation for the implementation

- Reader tests with synthetic fixtures. Accept valid Firebase JSON, including a valid fixture padded to exactly 65,536 bytes. Reject empty, oversized, unreadable, malformed, and unsupported files. Cover a regular-file symlink and non-regular descriptor classification. Check that oversized or non-regular descriptors are rejected before any read. Cover a file that grows past the cap with a controlled read fixture. Retain the existing encrypted-preview reader tests if shared code changes.
- Import state tests with a controlled async reader. Show that the main actor can update progress while the reader is pending. Verify that success replaces the provider, failure preserves the prior provider, picker cancellation leaves state alone, and completion after close cannot install a provider. Check that the pending state disables prepare and that a rejection re-enables selection.
- Proposed local gate through ATC after implementation and review. Run the new reader and state test classes, `GatewaySetupFormTests`, and `SetupFilePreviewReaderTests` if shared code changes. Build the macOS Debug app. Send actual test discovery, time forecast, and proposed cap before running. The plan has not run tests or exercised the GUI.
- Attended check in the macOS setup sheet with synthetic JSON. Verify valid import, a rejected first selection, a rejected replacement, silent cancellation, and close while loading. Confirm the sheet remains responsive and the prior project remains visible after a rejected replacement.
