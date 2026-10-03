# Sparkle feed experiment

This experiment pins Sparkle 2.10.0 and exercises information-only update checks. It does not enable updates in the product app.

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

The pinned source confirms that a completed download enters extraction immediately. The automatic driver can leave an installer running after its own update cycle ends. The user driver's ready-to-install callback therefore cannot by itself protect other running roles if the GUI quits or crashes.

Keep automatic product installation disabled until integration proves an earlier gate that covers all affected roles, admission races, GUI termination, installer recovery, and on-disk replacement. This is an implementation gate, not a change to the agreed automatic-update UX. Do not freeze admission for an entire download or kill active work to fit Sparkle's callbacks.

## Evidence limits

A successful feed check proves only feed signature validation and selection through the pinned probe API. It does not prove archive verification, Developer ID validation, notarization, protected installation, key rotation, quiescence, or multi-service continuity. Those require separate experiments before product activation.

Pinned upstream references:

- [Probe driver](https://github.com/sparkle-project/Sparkle/blob/2.10.0/Sparkle/SPUProbingUpdateDriver.m)
- [Download-to-extraction path](https://github.com/sparkle-project/Sparkle/blob/2.10.0/Sparkle/SPUCoreBasedUpdateDriver.m)
- [Automatic installation driver](https://github.com/sparkle-project/Sparkle/blob/2.10.0/Sparkle/SPUAutomaticUpdateDriver.m)
- [Feed failure policy](https://github.com/sparkle-project/Sparkle/blob/2.10.0/Sparkle/SUAppcastDriver.m)
- [Delegate contract](https://sparkle-project.org/documentation/api-reference/Protocols/SPUUpdaterDelegate.html)

Local evidence on macOS 27.0.1, Apple Silicon: the valid feed selected version 2 with a successful signature result. All three invalid feeds returned error 1000, no selected version, and no successful signature result. The server observed only the four expected feed requests. This is not validation on macOS 26 or a Developer ID signed product.
