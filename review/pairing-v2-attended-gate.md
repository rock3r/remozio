# Attended gate for v2 pairing

[Issue #852](https://github.com/rock3r/remozio/issues/852) tracks these checks. Run them with the user present on the selected Mac and physical phone. Record a result for installed pairing and a separate result for LAN activation.

The current Mac pairing sheet calls the public `MacPairingSession` initializer with v2 disabled. The current v2 listener requires IPv4 loopback. Use the current production build for the default-path control. Run the installed v2 checks only with an approved attended build that exposes the v2 path through the normal signed app and protected service policies. The LAN checks require a separately approved build and network scope. Until those inputs exist, mark the corresponding rows **Blocked**. [Mac session](../macos/core/Sources/RemozioCore/MacPairingSession.swift) · [Pairing sheet](../macos/app/App/PairingSheet.swift) · [Listener](../macos/core/Sources/RemozioCore/PairingSetupListener.swift)

[PR #962](https://github.com/rock3r/remozio/pull/962) frees the general bootstrap connection after proof handoff. [PR #964](https://github.com/rock3r/remozio/pull/964) implements fairness by source. [PR #967](https://github.com/rock3r/remozio/pull/967) supplies the 16/32 limits used below. Verify the final merge and the artifact source before using those limits. Its local gate passed 347 tests. Its native regression used real localhost TLS, fixture source keys, and anonymous XPC.

## Activation slice

The attended gate presupposes this slice. New and existing releases retain a disabled default until the gate passes and the user approves activation. Before that decision, enable v2 only in the selected attended build and disposable scope through the reviewed protected configuration path.

### Protected configuration and owner

- Put one authoritative enable flag in a versioned extension of the Root-private pairing startup configuration. The current `AuthorityPairingSetupConfiguration` pins the Transport key and the window lifetime. Preserve the existing schema's bytes and disabled behavior for an absent flag. Refuse unknown versions, malformed enabled settings, mismatched pins and stale activation state. Bind the internal activation request to the current `AuthorityClock.epoch` and the SHA-256 digest of the exact canonical protected pairing configuration. A changed epoch or digest makes it stale. Check both before drain and before promotion. Refuse a stale request without changing the current mode.
- The Root pairing owner consumes that setting before admitting a window. The installed app learns the effective mode from authenticated Root state. The Transport owner binds only for a current enabled Authority window on its authenticated proof link. Send Transport the public window projection through that path. Keep the full invitation with the signed app and the phone. User preferences, temporary environment flags and network clients cannot enable the path.
- Bind the v2 listener to the approved LAN scope only when the same protected setting is enabled and the current proof link is ready. A disabled or invalid setting starts no v2 LAN listener. Preserve TLS identity pinning, TLS 1.3, the v2 application protocol, the three-second deadline, and all quotas. Verify the actual socket binding during the attended gate. [Protected pairing configuration](../macos/core/Sources/RemozioCore/AuthorityPairingSetup.swift) · [Transport owner](../macos/core/Sources/RemozioCore/TransportPairingSetupOwner.swift)

### Installed app behavior and v1 retirement

- Wire `PairingSheet` through the installed `MacPairingSession` to open the Authority v2 window, start its Transport listener, and stage the exact proved candidate through the signed app. Keep native administrator consent, complete code comparison, biometric proof, durable commit and receipt recovery on the existing paths.
- Quiesce admitted v1 attempts and their replies before entering active v2 mode. Use the Authority-wide owner to deny fresh v1 setup on every signed app connection while v2 is active. Preserve durable results and ambiguous preparations. A failed v2 start leaves pairing unavailable under the active v2 policy.
- The user opens **Pair a phone…** and sees the short-lived v2 QR or text invitation only after the listener is ready. The candidate list shows a phone only after the possession proof succeeds. Keep the complete code comparison and confirmation prompts. Show expiry, restart, and unavailable states with the existing recoverable actions. Explain if a fresh invitation is required. Keep the QR and proof data out of diagnostics.

### Disable and recover

Apply disable through the supported protected configuration workflow. Close v2 admission, retire the current proof link and pending candidates, and wait for actual listener and Authority work to settle. Verify the LAN listener is gone and late replies cannot publish or mutate a new window. Retain durable receipts, the established enrollment, and any Unknown preparation. Keep admission closed if shutdown or policy state is uncertain. Where the previously approved policy permits v1, restore it only after the disabled state and completed drain are confirmed. Test disable after both an unproved connection and a completed pairing in the disposable scope.

### Proposed PR order

1. **Protected activation policy.** Add the versioned default-disabled setting, one Authority-wide mode and admission transition, and coverage for legacy inputs, invalid settings and v1 work in flight. Retain the disabled installed behavior.
2. **Installed proof and app path.** Connect the signed app, Root owner, and authenticated Transport control to v2 under the same protected setting. Verify the ready and unavailable UI, exact candidate ownership, and one-use receipt through the native loopback fixtures. Keep the production setting disabled.
3. **Controlled LAN binding and disable.** Add the gated binding transition and confirm listener retirement before reopening admission. Qualify the exact attended artifacts and approved observations for signing, cross-process proof access, restart and LAN measurements. Keep the production setting disabled while the gate is open.

## Select the artifacts and evidence folder

- [ ] Record the approved source commit, merge receipts, package and APK digests, signing mode, public signing pins, app versions, and both OS versions. Record the expected Authority and Transport service roles and their job labels from the selected installed inventory.
- [ ] Verify the Mac installation and its protected metadata through the [installed handoff](../docs/experiments/interactive-handoff.md). Resolve any installation, signing, or retained-state blocker before proceeding. Verify that the same reviewed source produced the phone artifact. Keep the phone app in the foreground.
- [ ] Use an approved disposable pairing scope. Record existing enrollments and any unresolved receipt before starting. Obtain explicit approval for the enrollment, replacement, and separate process restart cases. Keep existing unrelated data and services in place.
- [ ] For each native control, record the exact approved fixture action and its expected observation in the session plan. Record how the fixture reads the actual peer, process incarnation, and candidate timing. A fixture unable to expose that observation leaves the row **Blocked**.
- [ ] Use the existing [ATC workflow](../AGENTS.md) for any approved build or device command. Use the installed app and phone UI for the attended actions. Confirm installed IPC and signing before connecting the physical phone to the approved pilot pairing listener. Leave optional ADB disabled unless the user approves it for this session.

Run these read-only checks in a dedicated `sh` shell from the repository root. Fill in the values from the approved artifact manifest before running the block. Keep the output in the ignored evidence directory.

```sh
set -eu
capacity_merge='REPLACE_WITH_VERIFIED_PR_967_MERGE_COMMIT'
artifact_source='REPLACE_WITH_APPROVED_ARTIFACT_SOURCE_COMMIT'
approved_pkg='REPLACE_WITH_APPROVED_PACKAGE_PATH'
approved_apk='REPLACE_WITH_APPROVED_APK_PATH'
installed_app='REPLACE_WITH_VERIFIED_INSTALLED_APP_PATH'
signing_mode='REPLACE_WITH_notarized_OR_development'

case "$signing_mode" in
  notarized|development) ;;
  *) printf '%s\n' 'Set the signing mode from the artifact manifest.' >&2; exit 2 ;;
esac
git merge-base --is-ancestor "$capacity_merge" "$artifact_source"
umask 077
mkdir -p experiment-results
evidence_dir=$(mktemp -d experiment-results/pairing-v2-attended.XXXXXX)
git rev-parse HEAD > "$evidence_dir/review-checkout.txt"
sw_vers > "$evidence_dir/macos-version.txt"
shasum -a 256 "$approved_pkg" "$approved_apk" > "$evidence_dir/artifact-sha256.txt"
codesign --verify --strict --verbose=2 "$installed_app"
codesign -d --verbose=4 "$installed_app" 2> "$evidence_dir/app-signing.txt"
if spctl --assess --type execute --verbose=4 "$installed_app" > "$evidence_dir/gatekeeper.txt" 2>&1; then
  printf '%s\n' 'spctl exit 0' >> "$evidence_dir/gatekeeper.txt"
else
  status=$?
  printf 'spctl exit %s\n' "$status" >> "$evidence_dir/gatekeeper.txt"
  if [ "$signing_mode" = notarized ]; then exit "$status"; fi
fi
printf 'Private evidence directory: %s\n' "$evidence_dir"
```

Compare the checksums and public signing pins with the artifact receipt. A notarized candidate must pass the configured Gatekeeper assessment. For an approved development candidate, record an expected Gatekeeper refusal due to its signing mode. Count that expected result as a development control. Keep the notarization gate open for that candidate. Treat an unexpected refusal or a code signature mismatch as a failed prerequisite. Use the [initial package guide](../docs/macos-initial-package.md) for previously approved installation steps.

At the before and after points below, use the documented live status surface of the selected build. When the service diagnostics are available without elevation, these read-only commands supplement that evidence. Set the service targets and PIDs from the selected installed inventory and live observations. Each launchd target includes its verified domain and job label. Review the command output privately before retaining it.

```sh
launchctl print "$authority_target" | awk '/^[[:space:]]*(state|pid|last exit code) = /'
launchctl print "$transport_target" | awk '/^[[:space:]]*(state|pid|last exit code) = /'
ps -p "$authority_pid,$transport_pid" -o pid=,uid=,lstart=
lsof -nP -a -p "$transport_pid" -iTCP -sTCP:LISTEN
```

A permission error, missing observation, or unrelated listener leaves that check unresolved. Record the pairing listener separately from other Transport listeners. Keep appearance, disappearance, and relevant process timing in the sanitized record. For the binding itself, share only the class `loopback`, `LAN`, or `any`. Keep addresses and ports from `lsof` in private evidence.

## Installed positive and negative controls

| Check | Operator action | Evidence and pass criterion |
| --- | --- | --- |
| Default behavior | On the production candidate, open **Pair a phone…** and close it without enrolling. Record the pairing version from the available diagnostics. | The current default remains v1. The approved source and runtime observations show no v2 LAN listener. Record the selected release and its default behavior. |
| Root composition and pairing configuration | In the attended v2 build, open a window through the signed app with the provisioned pairing configuration. Check signed-app and Transport access to the same Authority pairing owner. Run the approved absent, invalid, and wrong-pin configuration controls only in their prepared fixtures. | One installed Root Authority serves both paths with the recorded configuration and correct transport pin. Invalid configuration refuses pairing without a version fallback or a candidate. Record the owner role, effective UID, configuration schema, public pins, and refusal categories. |
| Installed signing and role checks | Complete the positive handshake using the installed Transport. Use the approved controls for a wrong caller role, wrong signing requirement, wrong effective UID, and a wrong audit session if the policy binds one. | The expected Transport and Root peers authenticate. Other callers gain no valid proof link, registration, Setup access, or administrative right. Record the effective credentials and verdict of each control. Static signature inspection alone leaves the runtime check unresolved. |
| Second signed process | While the first link is live, use the approved cross-process fixture to present the proof endpoint from a separate correctly signed process. Record the expected original PID and the actual second PID in private evidence. | The second process cannot negotiate or allocate proof state. The first link stays usable, without replacement or eviction. A same-process XPC fixture counts only as local evidence. |
| Bootstrap and slot isolation | Observe the signed Transport bootstrap, proof negotiation, window binding, and handoff. Use the approved fixture to check general admission counts before and after, and to try a second concurrent dedicated link. | The bootstrap releases its general slot after successful handoff and the proof exchange continues. The dedicated link uses its own slot. A concurrent or stale proof link is refused. Record slot counts, transition order, and a successful general connection after handoff. |
| Restart a separate Transport | With an open v2 window, use the preapproved test control to end and restart its Transport process. Capture the old and new start times and the unchanged Authority process. Open a fresh window and complete a valid pairing attempt. | The original link and reservations retire. Its slot becomes reusable within the recovery bound recorded in the session plan. Late output from the old link cannot publish or retire the new slot. The Authority remains up. Record actual recovery time from observed death through successful new link reservation. |
| Authority-wide version exclusion | In the approved two-connection fixture, try v1 staging through another signed app connection while v2 is open. Separately hold an admitted v1 attempt or its reply, then request v2. Let the existing v1 attempt settle or expire. | Each conflicting operation is refused across connections. A fresh v2 window opens after the admitted v1 work settles or expires. Fresh v1 stays refused after the window closes while v2 mode stays active. Verify legitimate v1 under the approved disabled policy. Record both connection roles and the refusal and recovery order. |
| Proof and publication | Use the valid phone invitation and an approved control with no valid invitation proof. Exercise the prepared wrong-binding and expired-candidate controls, including a late confirmation. | A verified proof precedes candidate publication. The valid peer uses the same live link and exact proposal from registration through confirmation. No-proof, wrong-binding, and expired controls publish no candidate and commit nothing. The original three-second deadline starts at TCP accept, includes TLS and queue time, and never extends at challenge or confirmation. |
| Replay and registration budget | Use the approved bounded case for repeated bindings on the same link, including a retired candidate. Observe an approved temporary budget refusal and retry after credits return while the window is still live. Inspect the source and qualification evidence for the replay bound. | Repeated connection IDs and exporters remain refused for the link lifetime. The new valid request can proceed when credit and a slot are available. Record pending, drain, and budget outcomes separately. Confirm the 10,000-entry cap covers `16 + 32 × 300 = 9,616` registrations. A full-capacity fixture alone does not prove installed behavior. |
| NSXPC input boundary | Record the signed Transport-only interface and the ordering of decode and validation in the reviewed source. Use the approved fixed-size and proposal-size controls if the installed fixture exposes them. | Authority checks the 65-byte peer point, 32-byte exporter and tag, 16-byte handles, and 66,128-byte prelude limit before application proposal decoding and proof verification. NSXPC has already decoded the `Data` arguments when the method starts. Record this residual boundary and the owner's disposition. Authority relies on the authenticated Transport for the TLS socket binding. Do not claim a pre-NSXPC envelope bound. |
| Physical Mac–phone pairing | With the selected v2 build and disposable scope, share a fresh invitation using the approved app path. On the phone, scan or paste it in **Pair a Mac**. Compare the complete code on both screens. Complete normal consent and the biometric prompt. Exercise the approved mismatch or cancel control on a separate attempt. | Both devices complete pairing only after the actual consent and biometric proof. Authority commits once and the phone verifies the receipt. A mismatch or cancel leaves no committed enrollment. Record stages and consent outcomes without recording codes. |
| Single use and receipt recovery | After a valid proof, observe retirement of the remaining candidates for that window. Use the approved lost-reply case if available, then **Check pairing** on the phone using its retained preparation. | At most one candidate spends the invitation. After durable commit, the authentic receipt recovers the same enrollment. An unavailable reply remains Unknown. Preserve the retained preparation and keys and stop any retry that could start another enrollment. |

Record the chosen restart bound before the session. It must cover the actual installed lifetime, quiescence and launch behavior. The three-second deadline above applies to each proof candidate. It is separate from service recovery time. [Cross-process and restart criteria](https://github.com/rock3r/remozio/issues/852#issuecomment-7142358611) · [Proof budget](https://github.com/rock3r/remozio/issues/852#issuecomment-7144960815) · [Bootstrap and NSXPC decode boundary](https://github.com/rock3r/remozio/issues/852#issuecomment-7144971067) · [Installed scope](https://github.com/rock3r/remozio/issues/852#issuecomment-7146634650)

## LAN availability

- [ ] Run only on the explicitly approved LAN and attended build after installed IPC, signing and the physical pairing control pass. Record the exact approved traffic harness and command, the authorized sources, valid-attempt count, load, run duration, capture points, and stop condition before the run. The issue sets outcome thresholds and leaves the reference workload to the session plan. If the workload or harness is missing, mark LAN **Blocked**.
- [ ] Establish a no-load control with the real phone. Under the approved sustained reference workload, record every scheduled valid attempt. Use a fresh invitation for each attempt that spends a window. Keep independent trial windows and reuse policy in the record. Use exact monotonic accept and candidate-publication events on the same host. Include refused and expired valid attempts in the publication denominator.
- [ ] Check a distinct-source phone, then the approved shared-address case. Record the normalized-key count, peak pending and drain occupancy, refusal reasons, elapsed times, and any visible pairing failure. IPv4-mapped IPv6 shares the IPv4 key. Full IPv6 addresses use separate keys with scope ignored. A real phone that stays excluded under the shared-key control leaves the LAN criterion open.
- [ ] Record the successful publication fraction and p95 accept-to-candidate latency for each reference run. Pass requires at least 99% publication and p95 at or below 2.5 s under the approved load, with the real phone completing pairing. Compute p95 across all valid attempts. Assign 3,000 ms to each failed or expired attempt, including refusals. Report the sample count, missing timing observations, median, p95 and maximum scored latency. Treat a missing timing observation for a published candidate as unresolved.
- [ ] Check the report against the profile from PR #967. The listener has 16 pending slots, one per key, two admissions per source per second, four drain slots, and an 8-credit burst at 32/s. Authority has 16 pending reservations and a 16-credit burst at 32/s. The sustained listener threshold is `min(16, floor(32 / 2)) = 16` keys. Burst demand, drain occupancy, shared addresses, and IPv6 address rotation can lower available capacity. The localhost evidence cannot qualify LAN by itself.

For a completed run, put the approved collector's sanitized valid-attempt records in one CSV with the columns `published` and `accept_to_candidate_ms`. Use `1` for publication before the proof deadline and `0` for failure or expiry. Leave latency blank on failed attempts. The calculation assigns those rows the 3,000 ms proof deadline. An observed publication at or after the deadline is a protocol failure. Calculate the empirical thresholds offline with Python 3.13 on each predeclared scenario separately.

```sh
python3.13 - "$evidence_dir/valid-attempts.csv" <<'PY'
import csv, math, statistics, sys

with open(sys.argv[1], newline="") as source:
    rows = list(csv.DictReader(source))
assert rows and all(row["published"] in {"0", "1"} for row in rows)
deadline_ms = 3000
published = [row for row in rows if row["published"] == "1"]
observed = [float(row["accept_to_candidate_ms"]) for row in published]
assert all(math.isfinite(ms) and 0 <= ms < deadline_ms for ms in observed)
failures = len(rows) - len(published)
latencies = sorted(observed + [deadline_ms] * failures)
p95 = latencies[math.ceil(0.95 * len(latencies)) - 1]
print(f"published={len(published)}/{len(rows)} scored_at_deadline={failures}")
print(f"median_ms={statistics.median(latencies):.3f} p95_ms={p95:.3f} max_ms={latencies[-1]:.3f}")
raise SystemExit(0 if 100 * len(published) >= 99 * len(rows) and p95 <= 2500 else 1)
PY
```

The calculation checks the numeric thresholds only. Verify the workload, scope, instrumentation, real phone receipt, and shared-address result separately. [Approved LAN criteria](https://github.com/rock3r/remozio/issues/852#issuecomment-7148272028) · [Capacity measurements](https://github.com/rock3r/remozio/issues/852#issuecomment-7149371803) · [Proposed residual threshold](https://github.com/rock3r/remozio/issues/852#issuecomment-7151095535)

## Close and report

- [ ] Close the attended pairing window and fixtures through their supported controls. Verify the proof endpoint and listener retire and the original Authority remains healthy. Verify the intended retained enrollments. Preserve any unresolved receipt and its keys. Keep logs before any retry.
- [ ] For every row, record **Pass**, **Fail**, **Blocked**, or **Unknown** with the source, artifact, device OS, capture time, observed result, evidence path, and cleanup result. Record an explicit disposition for the signed Transport and NSXPC residual boundary. Keep raw results in the private ignored directory. Share only reviewed summaries. Exclude QR codes, invitations, comparison codes, proof material, key material, admin forms, account identifiers, device serials, and network addresses.
- [ ] Request a release decision only after the applicable installed and LAN rows pass and the user reviews the remaining limits. Keep v2 production activation and LAN exposure off until that separate decision.
