# Authority self-validation

Run `python3 scripts/run-macos-self-code-experiment.py` on an Apple Silicon Mac.
The native gate also runs this experiment, including CI on macOS 26.

Every public `AuthorityService` constructor checks the running authority before it constructs the XPC listener.
The requirement comes from the retained, active authority entry in the journal.
It pins the Developer ID identity, CodeDirectory hash, entitlement restrictions, and signed `RemozioSecurityGeneration` value.
The generation must equal the installed generation. Policy construction also enforces the minimum generation.
Missing policy or failed validation prevents startup and releases storage ownership.

The experiment compiles the production `DynamicCodeValidation.swift` source with a small disposable executable.
It uses `SecCodeCopySelf` and `SecCodeCheckValidity`, without resolving a process ID or executable path.
Ad-hoc signatures require no certificate, private key, service installation, or device interaction.

The checks prove these fixture behaviors:

- The matching identifier, hash, and generation pass.
- A different identifier, hash, or generation fails.
- An ad-hoc signature fails an Apple trust requirement.
- A running process cannot satisfy the replacement binary's hash and generation after its launch path changes.

The probe passed locally on macOS 27.0.1. CI supplies separate evidence for the macOS 26 baseline.
This fixture does not prove acceptance of the full Developer ID requirement or a deployed launchd service.
It does not replace protected installation, release validation, or coordinated update activation.
Old code cannot be trusted to enforce a newly added self-check.
External activation must prevent obsolete code from starting and quiesce services before changing their authority policy.
This change validates startup; it does not introduce a policy change protocol for an already running authority.
