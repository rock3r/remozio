# Validate command caller settings before saving

[Issue #858](https://github.com/rock3r/remozio/issues/858) · Source review of `062e9ad509e6af7eeb006e9f0426d423de00a51b`

## Where the values go

The Settings form binds eight values directly to `@AppStorage`. A picker change or a text edit writes its value immediately. The form calls `CommandFrontendCallerSettings` to decide whether to display a warning. The warning has no control over the write. [Bindings and warning](../macos/app/App/RemozioApp.swift#L61-L107)

The CLI loads the protected configuration for the caller and reads the persistent domain for the app. It passes the saved values and the installation defaults to `CommandFrontendCallerSettings`. An invalid override returns `EX_CONFIG` before either `run` or `sudo` reaches command execution. `--help` returns before preferences are read. The bundled CLI selects the matching Debug or Release domain. [CLI validation and error](../macos/core/Sources/RemozioCore/CommandFrontendMain.swift#L31-L67) · [Preference domains](../macos/app/CommandFrontend/FrontendMain.swift#L3-L12)

## Fields and rules

| Settings field | Persistent key | Accepted override |
| --- | --- | --- |
| Default command I/O | `commandDefaultIOMode` | `pty` or `pipes` |
| If the caller disconnects | `commandDefaultDisconnect` | `terminate` or `continue` |
| Readiness wait | `commandReadinessTimeoutMilliseconds` | 1 through `UInt64.max` ms |
| Initial connection backoff | `commandInitialBackoffMilliseconds` | 1 through 60,000 ms |
| Maximum connection backoff | `commandMaximumBackoffMilliseconds` | Initial backoff through 60,000 ms |
| Control validation timeout | `commandControlTimeoutMilliseconds` | 1 through 60,000 ms |
| Control retry interval | `commandControlRetryMilliseconds` | 1 through 60,000 ms |
| Foreground retry interval | `commandForegroundRetryMilliseconds` | 1 through 60,000 ms |

Present values must be strings. Numeric overrides accept ASCII digits and allow leading zeros. Missing keys use the relevant defaults. The five interval fields have a 60,000 ms limit. The readiness wait uses the larger range shown above. [Keys, parser and defaults](../macos/core/Sources/RemozioCore/CommandFrontendCallerSettings.swift#L8-L61) · [Backoff relationship](../macos/core/Sources/RemozioCore/CommandCallerReadiness.swift#L14-L27)

| Value or edit | Settings today | CLI today |
| --- | --- | --- |
| Clear Readiness wait, enter `0`, or type ` 50` | Saves the intermediate text and shows a warning. | Rejects the new saved value with `EX_CONFIG`. |
| Set Control retry interval to `60001` | Saves the value and shows a warning. | Rejects it with `EX_CONFIG`. |
| Set initial backoff to `1000` and maximum backoff to `500` | Saves the values and shows a warning. | Rejects the pair with `EX_CONFIG`. |
| Save only maximum backoff `3000` when the installation supplies initial backoff `4000` | Shows no warning. The form fills the missing initial value with `250`. | Rejects the pair `4000/3000`. |
| Save only initial backoff `3000` when the installation supplies maximum backoff `5000` | Saves the value and shows a warning. The form fills the missing maximum with `2000`. | Accepts the pair `3000/5000`. |

The last two rows use valid hypothetical installation defaults to show the effect of a sparse preference domain. The form supplies its own display defaults. The CLI derives its defaults from the selected installation. A malformed picker value or a non-string is also possible in an existing domain. The ordinary picker presents only supported choices. [Settings defaults](../macos/app/App/RemozioApp.swift#L62-L98) · [CLI defaults](../macos/core/Sources/RemozioCore/CommandFrontendMain.swift#L43-L54) · [Configuration selection](../macos/core/Sources/RemozioCore/CommandFrontendConfigurationSelection.swift#L5-L24)

## Proposed change

1. Keep `CommandFrontendCallerSettings` as the single validator. Teach it to identify the field and rule when validation fails. Return the typed settings on success. Use the same validator in the CLI, the Settings save path, and the existing portable preferences paths. Let Settings use the same protected configuration selection to obtain only the caller defaults. Continue to use the account-specific configuration first and fall back to the shared file only when the account-specific file is absent. [Current validator](../macos/core/Sources/RemozioCore/CommandFrontendCallerSettings.swift#L23-L61) · [Protected selection](../macos/core/Sources/RemozioCore/CommandFrontendConfigurationSelection.swift#L8-L23)
2. Bind the controls to a local draft. Load the explicit overrides from the same persistent domain the CLI reads. Display defaults for absent keys and retain their absence in the draft. Apply validates the entire proposed snapshot, including the backoff pair, before any write. Keep the draft on error, focus the invalid field, and explain the correction. For example, show “Maximum connection backoff must be at least the initial connection backoff.” On Cancel or close, discard the draft.
3. Publish the validated change as one domain update. Read the current domain again on Apply, preserve unrelated preferences, and publish the validated command overrides together. If the command overrides changed since editing began, refresh the draft before saving. Serialize the form save and the existing in-app import writer. Have the import path use the same destination defaults before it applies command overrides. The portable format and its explicit-key allowlist stay the same. The CLI validates every snapshot it reads, including changes made by another process. [Import merge and validation](../macos/core/Sources/RemozioCore/PortableAppPreferences.swift#L44-L61) · [App import writer](../macos/app/App/SetupFilePreview.swift#L397-L420)
4. Load an already invalid domain without rewriting it. Show the affected fields in Settings. For a value of the wrong type, show a repair prompt instead of treating it as an absent override. Let the user repair the values or choose **Reset Command Caller Settings**, which removes only the eight explicit overrides and restores the installation defaults. Cancel leaves the saved domain as it was. The CLI keeps returning `EX_CONFIG` for invalid preferences and directs the user to the affected field or the reset action. It leaves the stored values alone. The protected metadata error remains separate.
5. When Settings cannot load the installation defaults, explain why Apply is unavailable. Still offer an explicit reset of command overrides. A reset does not repair missing or invalid installation metadata. The caller settings control readiness and stream behavior. They carry no authority pins and grant no command authorization. [Protected metadata validation](../macos/core/Sources/RemozioCore/CommandFrontendConfiguration.swift#L49-L53) · [CLI error paths](../macos/core/Sources/RemozioCore/CommandFrontendMain.swift#L55-L69)

## Verification

- Extend the existing parser tests with exact bounds, empty and malformed overrides, wrong types, valid leading zeros, and a backoff pair at equality. Check that errors identify the right field. Exercise both sparse examples above with injected installation defaults. [Parser tests](../macos/core/Tests/RemozioCoreTests/CommandFrontendCallerSettingsTests.swift#L6-L48)
- Test the draft and commit logic against an isolated preference domain. Clear a field and check that the saved snapshot stays valid while editing and after a rejected Apply. Apply a valid backoff pair and read the result through the CLI path. Check that untouched optional keys stay absent and unrelated preferences survive. Test Cancel, a conflicting change after the editor opens, and the scoped reset.
- Seed a legacy invalid value. Verify Settings can open it and report the field. Verify `run` and `sudo` return `EX_CONFIG` before dispatch. Repair or reset the value, then verify the next CLI invocation gets the expected typed defaults. Keep test execution inside the existing fixtures.
- Exercise the account-specific defaults, the shared-file fallback on a missing account file, and refusal of malformed protected metadata. Cover sparse portable import against a destination with different defaults. [Configuration selection tests](../macos/core/Tests/RemozioCoreTests/CommandFrontendConfigurationSelectionTests.swift) · [Portable merge tests](../macos/core/Tests/RemozioCoreTests/PortableAppPreferencesApplicationTests.swift)
- On the macOS Settings screen, check that the error names the invalid field, keyboard focus reaches it, and closing without Apply leaves the saved values alone. Verify that reset stays scoped to Command Caller Settings.

This branch records a design and source findings. No build or runtime verification has been performed.
