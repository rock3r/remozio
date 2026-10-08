# Command admission reply carrier

Date: 2026-10-08. Platform: Apple Silicon, macOS 27.0.1, with a macOS 26 deployment target. These results do not prove macOS 26 runtime behavior.

The initial disposable C probe transferred a pipe fileport and a private reply send right in one message. It obtained the audit trailer, left queued input unread during receipt, delivered a reply, and restored borrowed references. A full-queue timeout also restored those references. Compilation passed with `-Wall -Wextra -Werror`.

The committed Swift tests reproduce the transfer and cleanup with the actual receiver and client. They use disposable ports, temporary fixtures, synthetic invocation bytes, and explicit test identities under the normal user's UID. They do not run the captured command.

Verified cases include current sender validation, retained process-incarnation matching, explicit carrier selection, unread input, malformed descriptor rejection, control limits, duplicate ownership, capture failure, lost acknowledgment, cancellation during a wait, final deadline rejection, and queue-saturation cleanup.

The different-process test uses a disposable signed fixture. It establishes audit-binding comparison. It does not establish Developer ID deployment, a protected Root process, or pre-login service behavior.

All fixture children, descriptors, and owned port references close through their normal cleanup. No service was registered. No credential, approval, input content from the user, or public network endpoint was used.

The control bytes remain opaque. These tests do not establish typed admission-result semantics, no-admission proof, automatic retry, target-policy enforcement, or guarded execution. Those integration gates remain required.
