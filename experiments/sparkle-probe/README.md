# Sparkle feed experiment

This experiment pins Sparkle 2.10.1 and exercises information-only update checks. It does not enable updates in the product app.

Build and run on an Apple Silicon Mac:

```sh
swift build --package-path experiments/sparkle-probe --disable-keychain --disable-netrc
python3 scripts/run-sparkle-feed-experiment.py
```

The runner creates disposable bundles and fresh in-memory Ed25519 keys. A loopback HTTP server supplies signed, unsigned, tampered, and wrong-key feeds. HTTP is used only inside this isolated fixture; production feeds and archives must use HTTPS.

The probe enables `SURequireSignedFeed` and `SUVerifyUpdateBeforeExtraction`. It sets `SUSignedFeedFailureExpirationInterval` to zero and independently requires a successful feed signature before accepting an item. Each disposable domain starts with a long-expired failure timestamp to test the zero-expiry policy. Automatic checks and downloads are disabled. The only check entry point is `checkForUpdateInformation`; its delegate rejects other check purposes. The runner expects one feed request per case and never serves an archive.

Temporary bundle identifiers use a fresh experiment-specific namespace. The runner removes their preference domains and temporary files. It does not use a Keychain identity, register a service, or install an app. Launching the fixture executable does not launch the Remozio product UI.

## Installation boundary finding

The product cannot rely on `shouldPostponeRelaunchForUpdate` as its quiescence gate. The documented callback is conditional and can be absent when no relaunch occurs. `willInstallUpdateOnQuit` also does not prevent installation when the app terminates, regardless of the delegate's return value.

The 2.10.1 source confirms that a completed download enters extraction immediately. The automatic driver can leave an installer running after its own update cycle ends. The user driver's ready-to-install callback therefore cannot by itself protect other running roles if the GUI quits or crashes.

Keep automatic product installation disabled until integration proves an earlier gate that covers all affected roles, admission races, GUI termination, installer recovery, and on-disk replacement. This is an implementation gate, not a change to the agreed automatic-update UX. Do not freeze admission for an entire download or kill active work to fit Sparkle's callbacks.

## Evidence limits

A successful feed check proves only feed signature validation and selection through the pinned probe API. It does not prove archive verification, Developer ID validation, notarization, protected installation, key rotation, quiescence, or multi-service continuity. Those require separate experiments before product activation.

Pinned upstream references:

- [Probe driver](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Sparkle/SPUProbingUpdateDriver.m)
- [Download-to-extraction path](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Sparkle/SPUCoreBasedUpdateDriver.m)
- [Automatic installation driver](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Sparkle/SPUAutomaticUpdateDriver.m)
- [Feed failure policy](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Sparkle/SUAppcastDriver.m)
- [Delegate contract](https://sparkle-project.org/documentation/api-reference/Protocols/SPUUpdaterDelegate.html)

Local evidence on macOS 27.0.1, Apple Silicon: the valid feed selected version 2 with a successful signature result. All three invalid feeds returned Sparkle-domain error 1000, no selected version, and no successful signature result. The selection guard was never reached for invalid feeds; its separate rejection cannot mask a framework-policy failure. The server observed only the four expected feed requests. This is not validation on macOS 26 or a Developer ID signed product.


## Sparkle 2.10.1 refresh

The 31 October 2026 check used the unchanged probe and feed runner with Sparkle 2.10.1.
ATC built the probe with Xcode on an Apple Silicon Mac that runs macOS 27.0.1.
The runner used that binary through an explicit build-directory substitution.
The valid feed selected version 2 and reported a valid signature.
Unsigned, tampered, and wrong-key feeds each returned Sparkle error 1000 before item selection.
The server received exactly the four feed requests. It received no archive request.
The fixture used disposable keys and removed its temporary bundles and preference domains.

The dependency archive matched the checksum in the upstream 2.10.1 package manifest:

```text
4c2e48a3e50ebcc2c88a58a4c7264a1a99c3c31857ce754357afb9cdb323022a
```

This refresh proves the four feed cases with the new dependency.
It does not repeat the replacement, relaunch, archive, signing, or service experiments.
The replacement-boundary results remain evidence for Sparkle 2.10.0 only.
Product installation stays disabled until the separate activation gates pass.

- [Sparkle 2.10.1 release](https://github.com/sparkle-project/Sparkle/releases/tag/2.10.1)
- [Dependency manifest](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Package.swift)
- [Pinned delegate contract](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Sparkle/SPUUpdaterDelegate.h)
