# Synchronous journal setup preparation

The authorized Root setup host prepares the exact private artifacts and journal files before opening the separate asynchronous initializer. This source layer performs no launch and exposes no administrator endpoint.

```mermaid
flowchart TD
    Scope["Validate the authorized account and retained state"] --> Private["Publish or validate exact private artifacts"]
    Private --> Files["Provision or validate service journal files"]
    Files --> Retain["Retain the immutable initialization intent"]
    Retain --> Async["Separate asynchronous Root operation follows"]
```

A pending retry requires the retained file identities. It cannot recreate missing storage. Completed preparation returns historical progress without touching private files or acquiring the active journal writer.

Twenty-seven focused tests pass, including seven new controls. Owned fixtures cover interrupted stages, changed host scope, stale expected state, pending-file loss and completed retries. The ordinary native caller is refused before filesystem access.

Root ownership transfer, dedicated UID isolation and installed signing remain required supervised checks in issue286. The owner deferred administrator and physical-device tests. No service is installed. The frozen first-flow package is unchanged.
