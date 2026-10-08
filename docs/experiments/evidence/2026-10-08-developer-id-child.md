# Local Developer ID command child evidence

On 2026-10-08, the existing Developer ID Application key signed a disposable copy of the built Release command child. No vault credential retrieval or UI approval was required.
The signed copy passed a strict Apple Developer ID requirement with its team, command-child identifier, exact code-directory hash, generation 1 and forbidden-entitlement checks. Hardened runtime was present.
The copy refused --execute from the unprivileged caller with exit 77 and no command output. No privileged command, service installation, permission change or device test was performed.
The signing probe omitted the secure timestamp and did not request notarization. It does not prove production protected placement, installed policy correspondence, revocation availability, update signing or release distribution.
The signing identity is available for the integrated build. Notarization and protected installation remain gates.
