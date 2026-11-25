# Linux single-owner fixtures

These C fixtures measure the [Linux single-owner design](../../docs/linux-single-owner-design.md)
(issue #988, PR1). They are measurement fixtures, not the product executor. They
do not install a service, approve a real decision or turn on production execution.

- `owner.c` is the owner O. It holds the caller's ptrace stop and starts the
  command through a prepared child K.
- `frontend.c` is the frontend C. It sends a fixed hello and its standard
  descriptors, then blocks.
- `probe.c` is the command. It writes one marker line and reports the state that
  it inherited.

PR2 adds:

- `authority/`, the Swift authority (one `FixtureStore` per request, the durable
  `beginDispatch` before the permit).
- `fdshim.c`, the transient unit's `ExecStart`, which receives O's descriptors and
  replaces itself with O.
- `command2.c`, the PR2 command (`cmd-report`, `cmd-sudo`, `cmd-prompt`, `cmd-hog`).
- `apparmor.in`, O's profile with the `ux` rule for the command.

```sh
python3 scripts/run-linux-single-owner-pr2-experiment.py --build-authority --work-dir "$PWD/.build/linux-swift/single-owner"
sudo python3 scripts/run-linux-single-owner-pr2-experiment.py --authority <the printed path>
python3 -m unittest tests.test_linux_single_owner_pr2_experiment
```

The supervised run needs Root through `sudo` from an ordinary account:

```sh
sudo python3 scripts/run-linux-single-owner-experiment.py [--timeout 15] [--allow-sysctl]
```

The tests need no Root. They compile every build with warnings as errors and run
every case that needs no Root with unprivileged test builds:

```sh
python3 -m unittest tests.test_linux_single_owner_experiment
```

The cases, the stub authority, the cleanup and the report are described in
[the experiment document](../../docs/experiments/linux-single-owner.md). The
report holds booleans, categories and errno names only. It keeps
`strictAdmission` and `productionAdmission` false.
