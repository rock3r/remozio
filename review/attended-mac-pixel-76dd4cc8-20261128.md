# Attended Mac–Pixel session on 76dd4cc8

**Test source:** main at `76dd4cc82b15b20b52a92af081fcd8688f0a5928`. Build the Mac and Pixel candidates from this source. This includes the merged #822, #992, #821 and #889 changes. PR #1079 is outside this build. This runbook records planned checks. It does not establish an installed result.

## 1. Artifacts

Use an Apple Silicon Mac on macOS 26 or later and the designated Pixel on Android 17 or later. Record the actual OS and build versions. Use a clean checkout already at the pinned source. Run these blocks from its root in zsh or a POSIX shell. Stop if a command fails. The repository gate does not install an app or contact the phone.

```sh
test "$(git rev-parse HEAD)" = 76dd4cc82b15b20b52a92af081fcd8688f0a5928
test -z "$(git status --porcelain)"
./scripts/check-local.sh
```

### Mac Developer ID Release

**Seb selects the approved Developer ID Application certificate, independently verifies its Team ID, unlocks the signing key if asked, and supplies the existing local notary profile.** Enter any Keychain or authorization prompt privately. Use the notarized app inside the local developer package. The package itself is unsigned. The unnotarized export and the ad-hoc Release build are unsuitable for the installed Setup daemon check. Use new paths for this run.

```sh
python3 scripts/check-macos-app.py
python3 scripts/run-macos-release-signing-experiment.py \
  --signing-identity CERTIFICATE_SHA1 --trusted-team TEAM_ID \
  --secure-timestamp --export-app .build/Remozio-76dd4cc8-timestamped.app
python3 scripts/prepare-macos-notarized-candidate.py prepare \
  --app .build/Remozio-76dd4cc8-timestamped.app --trusted-team TEAM_ID \
  --workspace .build/notary-76dd4cc8
python3 scripts/prepare-macos-notarized-candidate.py submit \
  --workspace .build/notary-76dd4cc8 --keychain-profile LOCAL_NOTARY_PROFILE
python3 scripts/prepare-macos-notarized-candidate.py status \
  --workspace .build/notary-76dd4cc8 --keychain-profile LOCAL_NOTARY_PROFILE
```

When the authenticated status is Accepted, finish the same workspace. On an uncertain upload, reconcile the recorded attempt using the notary guide. Do not submit a second copy from another workspace.

```sh
python3 scripts/prepare-macos-notarized-candidate.py finish \
  --workspace .build/notary-76dd4cc8
shasum -a 256 .build/notary-76dd4cc8/Remozio-developer.pkg
```

Retain the source SHA and sanitized final journal summary, package SHA-256, public publisher identity, signed app fingerprint, and ticket and Gatekeeper results. Allow **25–60 minutes** for build and signing, plus Apple processing time. Keep the notary workspace private. [Notarization workflow](../docs/macos-notarization.md) · [Package procedure](../docs/macos-initial-package.md)

### Pixel debug APK

Use JDK 21 and the installed Android SDK with platform 37 and build tools 37.0.0. Use the designated debug signing key if this updates an earlier debug installation. **Seb approves any Pixel install confirmation and USB file transfer.** Keep ADB disabled unless the owner separately needs it.

```sh
atc exec gradle tasks :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug --brief
APK=android/app/build/outputs/apk/debug/android-app-debug.apk
test -f "$APK"
/usr/bin/shasum -a 256 "$APK"
"$ANDROID_HOME/build-tools/37.0.0/apksigner" verify --print-certs "$APK"
"$ANDROID_HOME/build-tools/37.0.0/aapt" dump badging "$APK"
```

Use the package with ID `dev.sebastiano.remozio.android.debug`. Keep the package ID, version, APK SHA-256 and public signing certificate digest. Do not save the entire badging output when the four fields suffice. Allow **5–20 minutes**. [Android build guide](../android/README.md)

## 2. Install and verify

1. **Seb checks the Mac's installed state before opening Installer.** A fresh supported installation or a matching-build recovery can use the initial package. If a different installed build or retained state makes that path ineligible, stop. Use a clean designated Mac or an independently approved update path. Keep the existing app, keys, journal and enrollment. The initial package cannot test an update or a rollback between releases by itself.
2. Open `.build/notary-76dd4cc8/Remozio-developer.pkg` with Installer on the current startup volume. **Seb authorizes Installer, any allowed local developer package opening, and the macOS setup service consent.** Wait for Installer to report success. Confirm the exact path and independently verify the installed app:

   ```sh
   APP='/Library/Application Support/Remozio/Applications/Remozio.app'
   test -d "$APP"
   test "$(readlink /Applications/Remozio.app)" = "$APP"
   /usr/bin/stat -f '%Su %Sg %Sp' "$APP"
   /usr/bin/codesign --verify --deep --strict "$APP"
   /usr/bin/codesign --display --verbose=4 "$APP" 2>&1 | /usr/bin/awk '/^CDHash=|^TeamIdentifier=/'
   /usr/bin/xcrun stapler validate "$APP"
   /usr/sbin/spctl --assess --type execute --verbose=2 "$APP"
   /usr/bin/open /Applications/Remozio.app
   ```

   Require Root ownership, no group or other write access, a readable shortcut, and the expected signed app and ticket. Compare the installed code fingerprint with the prepared artifact. A failed or uncertain installer result stays visible for diagnosis. Record metadata and the sanitized failure stage.
3. In the Mac app, use the Setup service control. For a new disposable account, choose **Set up command approvals…**, select the intended target UIDs, then **Prepare account…**, **Prepare service accounts…**, **Prepare runtime files…**, and **Start services…**. **Seb approves the account policy, TLS custody disclosure, and native administrator prompts.** Verify the running roles and authenticated Authority status. A saved registration alone is insufficient. Use **Restore services…** only for the matching prepared account.
4. Transfer the exact APK to the Pixel by the approved local file-transfer path. Open it from Files and install through Android Package Installer. **Seb confirms the install and any source permission.** If updating, preserve the data and signing identity. Stop on an incompatible signature. Open the installed Debug app, verify the expected version in App info, and confirm it opens the normal Macs screen. On a fresh debug install the Mac list is empty. If testing an update, compare the prior expected records after launch.

Allow **20–40 minutes** for install, setup and these checks. Retain the package and APK hashes, OS versions, installed app signature/ticket results, Setup stage outcomes, and redacted role health. [Account preparation](../docs/macos-account-preparation.md) · [Installed setup controls](../docs/macos-setup-service-controls.md)

## 3. Ordered attended checks

A row needs both the action and the expected observation. If a listed fixture or authenticated observation is unavailable, record **Blocked** and the missing prerequisite. A timeout with uncertain effects stays **Unknown**. Use disposable accounts and commands throughout. Complete the initial installed approval smoke before disruption, revocation, or recovery tests.

| Check | Action and expected result | Time | Evidence to retain |
| --- | --- | --- | --- |
| **1. Installed pairing v2 and approval smoke** [#847](https://github.com/rock3r/remozio/issues/847), [#1040](https://github.com/rock3r/remozio/issues/1040) | On the approved LAN, open **Pair a phone…** on the Mac and **Pair a Mac** on the Pixel. Verify the protected policy permits the intended v2 path. Import the invitation, compare the entire code, and confirm on both devices. **Seb completes administrator consent and phone biometrics.** Require the actual v2 exchange, its decision-key proof, and one committed receipt on each side. No v1 fallback qualifies. Set routing to **Away** and open Requests. Run the fixture command below three times. Approve the first, decline the second, and let the third expire. Verify output and verified terminal/audit state only for approval. Decline and expiry must not dispatch. | 15–25 min | Source and artifact hashes, v2 and proof confirmed booleans, clock and outcome timings, exit status, no-dispatch proof for decline/expiry. Omit invitation, code and keys. |
| **2. Exporter parity, re-pair recovery and live XPC** [#926](https://github.com/rock3r/remozio/issues/926) | Use the approved parity fixture to compare the 32-byte Mac and Android exporters **on the same real TLS connection**, first direct then approved relay. Preserve only equality, route and length. An available direct route does not establish relay evidence. In the disposable re-pair fixture, lose only the first reply after the old registration is revoked and the replacement attempt is durable. On Pixel choose **Check pairing**. A genuine verified receipt activates the replacement once. A bound signed expiry retires the expired preparation. An unavailable reply preserves it. The stock screen alone cannot force the lost-reply point. Separately run the live XPC command below in Seb's logged-in GUI session. Require all runner cases and confirmed temporary job removal. | 25–45 min | Two parity booleans, transfer route, recovery state and terminal type, live XPC JSON summary and cleanup result. Keep all exporter values and pairing frames private. |
| **3. Request screen protection** [#833](https://github.com/rock3r/remozio/issues/833) | In an owned Pixel test session use the approved benign overlay fixture and a disposable live request. Check overlay suppression, screenshot, recording, and recent-task preview. The live protected inspector must not reveal the command in any capture or permit approval through an obscured surface. The synthetic preview does not prove the live path. | 10–15 min | Four outcome flags, Pixel build, app version and scope. No command capture in shared evidence. |
| **4. Biometric change** [#834](https://github.com/rock3r/remozio/issues/834) | On the designated test Pixel, enroll a biometric through Settings after pairing. **Seb performs the enrollment and enters the device credential privately.** Attempt approval on the old pairing. The invalidated key must refuse the approval, the Mac must not dispatch, and the repair path must require re-pair. Complete it with fresh keys and verify one new approval. If a legacy key migration fixture exists, also verify first-use re-pair for that key. | 15–25 min | Keystore invalidation class or visible repair state, no dispatch, successful re-pair and one fresh approval. Omit biometric details and keys. |
| **5. Installed launchd startup and stop** [#864](https://github.com/rock3r/remozio/issues/864), [#996](https://github.com/rock3r/remozio/pull/996) | Use the installed disposable job fixture to request termination **during startup**, then restore normally. Check each applicable Setup, Authority, Transport and Gateway role. The latched signal must trigger cancellation and drain before escalation. Observe the existing unconditional KeepAlive behavior with the approved `EX_CONFIG` condition. Plain Stop/Restore is useful baseline evidence. It does not prove the startup timing or `EX_CONFIG` case without the fixture. Keep job policy unchanged. | 15–25 min | Job role and exit code, monotonic signal-to-drain and escalation times, relaunch count, owner and lease settlement. Sanitize exact account labels and only retain relevant log lines. |
| **6. Installed replay migration, restart and rollback** [#1064](https://github.com/rock3r/remozio/pull/1064), [#1065](https://github.com/rock3r/remozio/pull/1065) | Use a reviewed disposable format 19 account with settled outcomes, verified legacy state, and both signed reader floors ready for the supported transition. Start the installed pinned build and verify format 20, counters, and stable settled outcomes with the authenticated fixture. Restart. Require verified counters, closed admission until health succeeds, and a normal new approval. On the approved rollback fixture, attempt a signed reader below the committed floor. It must refuse before opening admission while current state remains intact. An install-package refusal alone is insufficient. A fresh format 20 account cannot prove migration from 19. | 15–30 min | Verified before/after format and floor, counts, checkpoint and admission transitions, rollback refusal class, proof of unchanged protected state. No SQLite files or raw request IDs. |
| **7. Revocation and replacement** [#840](https://github.com/rock3r/remozio/issues/840) | From **Paired phones → Revoke** on the Mac, cancel first and verify the old enrollment stays active. Use the approved stale selection fixture, then revoke the exact epoch with administrator consent while the disposable Gateway is offline. Restart the relevant owner. The old phone epoch must refuse locally while delivery is pending. Restore the Gateway and observe its verified result. Choose **Re-pair** for the revoked predecessor and verify fresh keys and one replacement, including the lost-reply recovery if prepared. **Remove from this phone** only changes phone storage. | 20–35 min | Cancellation and stale-selection result, local refusal across restart, eventual Gateway status and one successor enrollment. Use redacted epoch labels. |
| **8. Idle audit retention** [#1056](https://github.com/rock3r/remozio/pull/1056), [#1057](https://github.com/rock3r/remozio/pull/1057) | Use an approved disposable journal prepared at the published threshold. Cache an older signed audit page on the Pixel. Let the installed Authority become idle and observe a bounded maintenance batch. Submit a new legitimate approval and confirm it remains available. Verify the signed retention boundary and gap, and confirm the Pixel still verifies its cached page. A small fresh journal cannot exercise the natural threshold. | 10–20 min after fixture setup | Initial/final counts, idle interval and batch timing, approval result, signed gap and cached-page verification as booleans. |
| **9. Phone-wide Gateway restriction** [#898](https://github.com/rock3r/remozio/issues/898) | With a verified disposable restriction fixture, confirm **Re-pair** cannot reuse the restricted phone ID. On the Pixel choose **Remove from this phone** for the test Mac. On Mac Setup start a new ordinary invitation and complete it. Require a fresh phone identity, continued refusal of the restricted identity, and working approval on the new one. Do not clear a restriction row manually. | 10–20 min | Refusal and new identity booleans, one successful approval, unchanged restriction. No actual phone identifiers. |
| **10. Listener closure and bounded capacity** [#1014](https://github.com/rock3r/remozio/issues/1014) | Close or let expire a normal v2 window and verify that its advertised listener retires. On the isolated approved LAN, run the reviewed 16-client fixture. Require 16 observed allocations, refusal of overflow without allocation, recovery after releasing one client, and one valid pairing before the v2 deadline. Record client-side close separately. The installed case stays open if only the repository's controlled listener test is available. | 10–20 min | Arrivals, allocations, releases, close observation, and next-pair timing. No peer addresses, proof secrets or packet traces. |
| **11. Android pairing comparison protection** [#1051](https://github.com/rock3r/remozio/issues/1051), [#1054](https://github.com/rock3r/remozio/pull/1054) | Pair and re-pair on compact sheet and wide dialog. While the comparison and biometric window are open, check benign overlays, screenshot, recording, casting and task preview. Exercise rotation, resize, background/resume, TalkBack, cancellation and expiry. Verify that a failed protection fixture exposes only a safe close path. After leaving comparison, ordinary capture behavior returns. | 15–25 min | Matrix by window, phase and protection mode, prompt and accessibility outcomes. No actual comparison code or sensitive capture. |
| **12. Pixel transport certificate renewal** [#831](https://github.com/rock3r/remozio/issues/831) | Use an approved enrolled near-expiry leaf fixture with its real hardware transport key. Open that Mac's Requests screen to start channel setup. In the final 30 days Android should issue a new one-year leaf using the same Keystore key. Verify the Mac accepts the same enrolled key. Use the approved expired/unusable fixture to exercise the visible **Pair again** recovery, Mac revoke and **Re-pair**. Do not change the physical Pixel clock or copy out Keystore material. | 10–20 min | Old/new public leaf dates and same-key boolean, successful connection or verified refusal and new pairing. [Transport identity](../android/transport-identity.md) |
| **13. Installed Setup shutdown diagnostic** [#821](https://github.com/rock3r/remozio/issues/821) | In a disposable installed audit-upgrade fixture arrange a retained cleanup failure, request Setup shutdown, and observe the maintenance predicate below. Require visible fixed cause and count, at most one report every 30 s, retained custody while pending, and shutdown after the fixture settles. The ordinary UI does not supply a safe failure injector. Leave this row blocked if the fixture is absent. | 10–15 min | Only the redacted event, sample count, times, settlement and actual shutdown. |
| **14. Installed interrupted restore** [#822](https://github.com/rock3r/remozio/issues/822) | Run the authorized installed restore-race fixture on a disposable account. Resume the interrupted restoration while the exact expected job becomes visible between its inspections. Startup should retain the matching job, verify live identity and authenticated health, and reopen admission without owner recovery. The foreign-job control must remain closed. Normal **Restore services…** without the recorded transition covers only the baseline. | 10–20 min | Phase timings, match/conflict and health flags, restart/admission behavior. No job tokens or account IDs. |
| **15. Installed proven pairing expiry** [#992](https://github.com/rock3r/remozio/issues/992) | Use a disposable first-enrollment fixture and installed app communicating with Root. Verify commit-result version 6. Exercise the controlled expiry between app dispatch and the first Root enrollment write. A bound proven expiry is definite and creates no enrollment. Drop the reply separately. The Mac then keeps the outcome unknown. A normal UI expiry before dispatch does not qualify the Root result. | 10–20 min | Version negotiated, expiry position, record delta zero, definite versus Unknown UI states. No setup ID or digest. |

Smoke command. Run from an ordinary Mac terminal after pairing, using the explicitly configured disposable target UID. Use `0` only when the owner selected root for this harmless fixture.

```sh
"/Library/Application Support/Remozio/Applications/Remozio.app/Contents/Helpers/remozio" \
  run --pipes --uid 0 -- /usr/bin/id < /dev/null
```

Live GUI XPC probe and #821 log observation. Use a new output name for each XPC run. The XPC runner registers a temporary per-user agent and checks cleanup. It does not establish installed Root identity.

```sh
mkdir -p experiment-results
python3 scripts/run-macos-xpc-experiment.py \
  --output experiment-results/xpc-76dd4cc8-attended.json
/usr/bin/log show --last 15m --style compact \
  --predicate 'subsystem == "dev.sebastiano.remozio" AND category == "maintenance"'
```

The first clean install, pairing and three decisions can take **60–90 minutes**. Allocate a separate block for recovery, launchd and migration fixtures. Keep lock, logout, restart outside the targeted rows, Chrome Remote Desktop and Screen Sharing checks last. Keep optional ADB disabled. Keep provider fixtures and platform accessibility qualification separate from component or synthetic tests.

## 4. Optional measurements

| Check | Action and expected result | Time | Evidence to retain |
| --- | --- | --- | --- |
| [#1005 PR 3b](https://github.com/rock3r/remozio/issues/1005) | Use only the separately approved installed test build that exposes the retirement fixture. Scheduling stays disabled on the pinned source. Populate the verified disposable one-million and two-million replay-set fixtures. At each size, time a real signed approval through one retirement batch, using the established idle-owner policy. Every approval must finish within 30 s and every batch must release its lock within 12 s. Retain separate no-batch controls. | 45–90 min after fixtures | Per-sample end-to-end and lock times, counts, exact artifacts and failure/skip labels. |
| [#846](https://github.com/rock3r/remozio/issues/846) and [#852](https://github.com/rock3r/remozio/issues/852) | On the explicitly approved LAN, use the reviewed reference-load and shared-source qualification fixtures for legitimate v2 pairing. Verify each intended phone build. Require at least 99% valid publications and accept-to-candidate p95 at most 2.5 s. Keep the installed and LAN reports separate. | 30–60 min after fixtures | Attempts, valid publications, p95 and fixture shape, phone build and pass/fail. No addresses or pairing materials. |

## 5. Record and stop conditions

Use ignored `experiment-results/` locally. For each row record source SHA, artifact hashes, OS, fixture eligibility, starting and ending state, action, timings, expected and actual outcomes, and cleanup. Publish only sanitized summaries. Omit credentials, biometric data, invitation and comparison material, exporter values, device serials, addresses, private keys, protected-store bytes, and real approval payloads. Record the specific reason for every Blocked, Skipped, or Unknown row. Keep [#1062](https://github.com/rock3r/remozio/issues/1062) and [#926](https://github.com/rock3r/remozio/issues/926) open for unchecked rows. [Existing device handoff](../docs/experiments/interactive-handoff.md)
