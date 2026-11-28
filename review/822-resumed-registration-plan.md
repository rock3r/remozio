# Resume registration after an interrupted restoration

Refs #822. Source reviewed at main 9cc16f10.

## Failure

Automatic startup opens a durable restoring window and checks the expected job. If the job is absent, startup enters the one-shot registration scope. The native entry checks again. An older bootstrap can finish between those checks. The second check sees the expected job and currently returns conflictingPlan. Startup then records needsOwnerRecovery and leaves admission closed. A later start does not resume that terminal row.

The two decisions are in RuntimeMaintenanceStartupRecovery.swift at lines 1530–1536 and RuntimeJobRegistration.swift at lines 131–136. Recovery persists the failure at RuntimeMaintenanceStartupRecovery.swift line 1435.

## Registration match

Use the expected job and metadata from the current custody floor. A match requires all of the following.

- The exact system-domain label and LaunchDaemon registration. Check the expected plist path, executable, arguments, user, group, Mach service set, and required launchd properties with the existing typed observation. An absent PID is not evidence of a healthy process.
- The protected plist resolves to the expected bytes and passes the existing owner and file identity checks. Keep the protected directory and expected Root ownership checks.
- The same machine and account identity, target owner, installed release and authority job cohort, and the exact current restoring row for that window, including its recorded identity and revision. Use the existing floor and held account drain checks to prove this before and after the observation.

A registration match is evidence about the job. The live process still needs the existing PID, code identity, and authenticated health checks before admission can reopen.

## Change boundary

Carry the initial durable restoring row from automatic startup into the registration decision. Allow the matching second observation only when startup opened that exact row and the row is still current while custody holds the one-shot registration scope. Derive this from the startup state and captured row. Do not derive it from a row freshly written in the same attempt or from the launchd result.

Inside the existing registration scope, keep the protected metadata and restoring-row checks. A second observation of the exact job continues without another bootstrap. An absent job follows the existing bootstrap and lost-acknowledgment reconciliation. A different job remains conflictingPlan. Preserve error handling for an unreadable or uncertain observation.

Keep the account drain, process witness, signed health, durable row writes and admission reopening sequence. Fresh restoration, explicit restoration, and ordinary-owner restoration keep their existing absence checks. General registration and reconciliation keep their current behavior. The plan adds no launchd mutation, extra retry, timeout change, or repair path.

## Regression tests

Use the deterministic registration and startup fixtures. Verify both the outcome and the number of registration and persistence operations.

| Scenario | Expected result |
| --- | --- |
| An older bootstrap finishes between the outer and inner inspections | The inner exact match under the inherited restoring row runs no new bootstrap. The owner continues to live and health checks. A fresh row does not get this exception. |
| A different job appears between the inspections | Return conflictingPlan. Do not bootstrap, replace, stop or adopt this job. The existing closed recovery outcome remains. |
| The new bootstrap loses its acknowledgment | Preserve the current result when the final read proves the exact job. Bootstrap runs once. A conflicting or absent final read retains its existing error. |
| Startup stops after accepting the match and starts again | Use the same durable restoring window and fresh custody. A matching job needs no bootstrap. The live and health checks run before reopenPending and restored can be written. |

Reuse RuntimeJobRegistrationTests and RuntimeMaintenanceStartupRecoveryTests. Include the wrong-window and pre-bootstrap scope checks in the selection. A source review and normal-user fixtures can establish the control flow. This plan makes no claim about installed launchd behavior.

## Estimate

Two Swift production files and focused tests. Prepare the exact test selection and forecast from the implementation diff before running its gate.
