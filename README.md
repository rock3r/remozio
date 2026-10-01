# Remozio

Approve requests from your Macs through one Android app. The idea covers privileged commands, 1Password, and Little Snitch, with request details and biometrics where needed.

Read the [Remozio specification](https://remozio-plan.seebrock3r.chatgpt.site/) for the proposed architecture, app experience, and open questions.

Remozio is in the experiment phase. There is no production approval implementation yet.

See the [experiment sequence](docs/experiments/README.md) and the [Mac XPC experiment](docs/experiments/macos-xpc.md) for measured results and reproducible checks.

Run `./scripts/check.sh` for the local gate. Pull requests use the repository’s [babysit skill](.agents/skills/babysit-pr/SKILL.md), with Python checks, the Mac build, and Codex review required.
