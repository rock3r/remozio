# Mac presence signal experiment

This probe prepares the platform checks for section 14 of the design. It does not detect human presence or select a routing destination.

## Run one observation

Build first, before changing the desktop state:

```sh
swift build --package-path experiments/macos --triple arm64-apple-macosx26.0
probe_dir=$(swift build --package-path experiments/macos --triple arm64-apple-macosx26.0 --show-bin-path)
"$probe_dir/remozio-presence-probe" --help
"$probe_dir/remozio-presence-probe" --sample-after 15
```

The explicit sampling command waits 0–300 seconds, prints one JSON object, then exits. Use the delay to establish the test state without typing at the observation instant. Run it from a Terminal in the target account's GUI session. A command launched through SSH or an agent executor can have different session access; record that context separately.

There is no recurring sampler, event tap, process scan, permission request, service registration or network connection. The probe neither posts input nor changes display or lock state. It creates no evidence file. Save selected output under the ignored `experiment-results/` directory if needed. Do not create a continuous activity trace.

## Reading the result

| Field | Meaning and limit |
| --- | --- |
| `sessionDictionaryAvailable` | Quartz returned a dictionary for the caller. This does not establish the target account's presence. |
| `onConsole`, `loginCompleted` | Documented session flags, or null when unavailable. Neither means unlocked or actively used. |
| `combinedSessionInputAgeSeconds` | Whole seconds since any input in the combined session event table. Includes sources that post to that table; not proof of human input. |
| `hardwareInputAgeSeconds` | Hardware event table comparison. It must not become a filter that rejects remote input. |
| `displayListStable` | Two bounded display enumerations agreed. This does not make the intervening property reads atomic. |
| `displays` | Online display entries with built-in, online, active and asleep flags. No persistent display identifiers are emitted. |
| `sampleIndex` | Position in this sample only. Never match displays across samples by this value. |
| `brightness`, `lockState`, `usableRemoteDesktop` | Always null: these observations are not implemented. Null never means dark, unlocked or disconnected. |
| `routingDecision` | Always `not-evaluated`. The result never enters the product router. |
| `samplingDurationSeconds` | Time spent gathering the sequential observations. No wall-clock timestamp is emitted. |

Missing session dictionaries suppress both input ages. Negative or non-finite counters become null. Failed enumeration, more than 32 displays or changed display identities suppress the entire display list. Other flags can change during a sample; inconsistent observations need a new explicit sample.

An active display is connected, awake and drawable according to Core Graphics. It does not establish readable brightness or a usable remote desktop. A completed login can remain true at a lock screen. Input can come from automation, including future Remozio actions. The combined table alone cannot meet the requirement to exclude Remozio's own input.

The JSON omits usernames, user IDs, hostnames, window contents, display serials, key values, pointer positions and provider connection details. Review evidence before committing it.

## Interactive matrix

For each case, record the actual macOS version, launch context, manually observed workspace and one sample. Follow the shared [evidence format](interactive-handoff.md#evidence-record).

| Case | Observation to compare | What this cannot prove |
| --- | --- | --- |
| Local typing, then no input | Input age near zero after typing, then increasing | That all recorded input is human |
| Local input idle for over two minutes | Combined age crosses the default idle interval | A safe routing decision without the other signals |
| Lock screen | Session flags and display states before/after lock | Public lock detection; the field stays unknown |
| Display sleep/wake | Per-display active/asleep flags | Remote workspace usability |
| Internal brightness zero, external display awake | Online entries remain separately visible | Darkness; brightness stays unknown |
| Lid closed with an external display | Entries and active/asleep flags | Stable display identity between samples |
| Chrome Remote Desktop input | Combined and hardware ages after remote input | Provider connection status or account binding |
| Screen Sharing input | Same comparison in the actual target session | Coverage of another provider or session type |
| Remote reading without input for over two minutes | Ages may grow while the desktop remains usable | Absence: a connected reading session still counts as present |
| Remote client disconnect; service still running | Manually confirmed disconnect and a new sample | A running service must never count as connected |
| Remote view shows only a lock screen | Manually confirm that account dialogs are inaccessible | A usable account workspace from connection alone |
| Target account switch or unavailable GUI session | Availability and null fields | That another account's activity belongs to this account |

Start delayed observations before sleep, lock or disconnect. Do not run a command through remote input at the sampling instant, because that alters the signal. No test automatically changes system settings. Coordinate each change with the user and restore their original state afterward.

## Next implementation gate

Physical observations remain pending. Compilation establishes API availability only. Before connecting a detector to routing, establish usable remote-session detection, account association, freshness and disconnect behavior for CRD and Screen Sharing. Reading without input is a required positive case.

Also establish supported lock/brightness observations and how to exclude the app's own injected activity. Unsupported providers and displays must retain explicit unknown states. Choose the bounded detector-recovery interval from evidence, not this probe. Preserve the existing manual Present/Away controls in the design; do not silently add privileges or private hooks.

## API basis

The probe uses Apple's public [session dictionary](https://developer.apple.com/documentation/coregraphics/cgsessioncopycurrentdictionary()), [event source tables](https://developer.apple.com/documentation/coregraphics/cgeventsourcestateid), [input age](https://developer.apple.com/documentation/coregraphics/cgeventsource/secondssincelasteventtype(_:eventtype:)), [online display list](https://developer.apple.com/documentation/coregraphics/cggetonlinedisplaylist(_:_:_:)) and [display sleep query](https://developer.apple.com/documentation/coregraphics/cgdisplayisasleep(_:)). The installed SDK headers define the exact session keys and display flag semantics used here. No undocumented lock dictionary key is read.
