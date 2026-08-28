# angr/mono

> [!CAUTION]
> **This is an experiment. Do not use it for anything.**
>
> It is a proof of concept for a question — *what would angr look like as one
> repository?* — and nothing here is supported, released, or promised to keep
> working. The real angr lives in the separate repositories under
> [github.com/angr](https://github.com/angr); file issues and pull requests
> there. Nothing in this tree is the source of truth for anything: it is
> re-imported from those repositories wholesale, so a change made here is a
> change that gets thrown away.

## What this is

angr ships as a dozen repositories that only ever move together. A change
that touches an IR lifter, the loader and the analysis on top of it is three
pull requests, three CI runs, and a merge order to get right, and none of the
three is testable on its own until the other two land. [angr/vibr] showed the
components build fine from a single tree. This repository asks the next
question: whether they also *test* fine from one, fast enough that a single
CI run over the whole ecosystem is a normal thing to wait for.

So: every CI-relevant component is a top-level directory, there is one Nix
flake that builds all of them, and one workflow that runs every component's
own existing test suite in parallel.

[angr/vibr]: https://github.com/angr/vibr

## Run it

```shell
nix run github:angr/mono -- --help          # the angr CLI
nix shell github:angr/mono                  # python3 with angr importable
nix build github:angr/mono#angr-management-lib
```

Or as a flake input, using the overlay to get the components into an existing
Python package set:

```nix
{
  inputs.angr-mono.url = "github:angr/mono";
  # ... pkgs = import nixpkgs { overlays = [ angr-mono.overlays.default ]; };
  # then: pkgs.python312Packages.angr, .cle, .claripy, ...
}
```

## Develop in it

```shell
nix develop                # everything: components, test deps, cargo, cmake
ci/link-external.sh        # put the angr/binaries fixtures at ./binaries
ci/run-suite.sh cle        # run one component's suite
ci/run-suite.sh angr --shard 1 --of 10
```

A component's tests are the ones upstream wrote, unmodified, and they find
their fixtures the way they always have — as `../../binaries` relative to the
tests directory, which in this layout is the repository root.

`ci/run-suite.sh` runs each suite from a scratch directory that contains
nothing but a symlink to that suite's tests, and then checks where the import
resolved. Without that, pytest puts the component directory on `sys.path` and
the suite imports `angr/angr/` — a pure-Python tree with no compiled
`rustylib` in it — instead of the package Nix built. It is a quiet failure:
most tests still pass.

## What is in the tree, and what is not

Imported, one directory each. The seven core components:
`archinfo`, `pyvex`, `pypcode`, `claripy`, `cle`, `angr`, `angr-management`.
Then five of the dependents upstream tests every core change against --
`pysoot`, `tracer`, `angr-platforms`, `angrop`, `phuzzer` -- which are here
because two of them gate tests inside angr's own suite: twenty-one tests in
`tests/engines/test_java.py` and `test_cfgfast_soot.py` are behind
`skipUnless(pysoot)`, and eighteen more in `tests/exploration_techniques/`
behind `skipUnless(tracer)`. Without them in the tree those tests do not
fail, which would be honest -- they report as skips.

`ci/import.py` re-snapshots them all from upstream and records what it took
in `mono.json`.

Three things are pinned in `flake.lock` instead of vendored:

| | why |
| --- | --- |
| `angr/vex` | It is a fork of valgrind's IR library with its own cadence; pyvex only ever consumes it as a source drop, and it is the one dependency this experiment deliberately leaves outside. |
| `angr/binaries` | 450 MB of test fixtures. `ci/link-external.sh` puts it at `./binaries`, where every suite already looks. |
| `angr/angr-data` | 200 MB of generated JSON. |

One test is deselected, in `ci/suites.json`, with its reason beside it and
printed on every run of that suite. Nothing else is. That includes the suites
for angr's optional `llm` extra: `pydantic-ai`, `mcp` and `fastmcp` are
packaged in `nix/python-overlay.nix` rather than skipped, because a suite that
is skipped for want of a dependency is a suite that tells you nothing. The
same reasoning packaged `pysoot` -- with a JDK, since jpype needs one -- and
`tracer`, with the prebuilt `shellphish-qemu` wheel it requires: those two
gate thirty-nine of angr's own tests, which reported as skips for as long as
the components sat in the tree unpackaged. What the counts are now is a
question for the last run's summary, for the reason the cost section gives.

Four of the five now run their own suites too -- `pysoot`, `tracer`,
`angr-platforms` and `angrop` -- which is the shape of what upstream's
`ga-build.sh` does: without them a claripy change is tried against angr and
angr-management and nothing else. It is not the whole of it. Upstream's
`repo-list.txt` names twenty-one repositories and tests everything
transitively downstream of the one being changed; five of them are here. See
the table below for what that leaves out.

A component's own `.github/` does not come in: only the workflow at the root
of this repository runs, and seven dead copies of upstream's workflows would
suggest otherwise.

## How CI stays fast

One job builds the whole closure and publishes it as a Nix binary cache; every
other job substitutes from it, so a test job starts its suite instead of
compiling angr's Rust extension for itself. Fourteen test jobs then run at
once.

The cache lands in two places. `actions/cache` is the fast path — same
datacentre, restored in seconds — but it is a 10 GB LRU shared by the whole
repository, and one busy afternoon evicts the entry that fourteen jobs are
about to ask for. So a GitHub release holds the authoritative copy, one asset
per source revision, with no eviction and no budget to share; `ci/nix-cache.sh`
manages both and the jobs fall back from one to the other.

The key is a hash of the git tree hashes of the pins, the Nix expressions and
each component's source, so it changes when a rebuild would be needed and not
otherwise. Editing this README does not invalidate it.

The test matrix is one job per shard, so the stage costs what its slowest
*shard* costs rather than what its slowest suite costs. `ci/suites.json` is
the whole of it: which suites share a job — the five that finish in seconds
are billed for setup, not testing, so they share one — and how many shards
the two that do not get. `pytest-split` does the splitting with the same
`--splits`/`--group` flags upstream angr CI already shards with, against
per-test timings recorded in `ci/durations/`, so a shard here means what a
shard there means.

## What it costs

Whatever the last CI run says. The workflow's summary is a table of tests and
wall time per suite; that is the measurement, and quoting a second one here
would only go stale. angr is the only suite big enough for the shape of the
matrix to matter — it is what the ten shards are dividing. angr-management is
the only other suite that takes minutes rather than seconds.

## The skip ratchet

A skip is not a failure to pytest, so a dependency that stops being importable
turns tests off and leaves the run green. That happened twice here: six
architectures inside a test that reported PASSED, once the fixture symlink was
missing, and thirty-nine tests for as long as `pysoot` and `tracer` sat in the
tree unpackaged. Neither was caught by CI. Both were caught by a person
noticing a count had moved.

So the counts are written down. `ci/skips.json` records what each suite is
allowed to skip in the Nix lane -- the one lane that runs every suite in full,
on one platform, against a pinned closure -- and the summary job fails when a
suite skips more than that. Raising a budget is an edit with a diff on it,
which is the point. It is the same shape as the pylint and pyright ratchets,
and it is there for the same reason.

```shell
ci/summarize.py test-results --baseline ci/skips.json
ci/summarize.py test-results --baseline ci/skips.json --update-baseline
```

## What upstream does that this does not

An experiment is only useful if it is honest about its edges. Each of these
is a thing upstream CI does today and this repository does not.

| | what is missing | why it is not here yet |
| --- | --- | --- |
| The rest of the dependency graph | `ci-settings/ci-image/conf/repo-list.txt` names twenty-one repositories, and `test.py` runs the suite of everything transitively downstream of the one under test. Five are imported here. `rex`, `patcherex`, `heaphopper`, `shellphish/driller` and the three `mechaphish` packages are not, nor is `archr`, which `rex` builds against. | Each is another repository to snapshot and another dependency set to package. The five here were chosen because two of them gate tests inside angr's own suite; the rest are a straightforward extension of the same work, not a different problem. |
| `phuzzer`'s suite | The other four imported dependents run; `phuzzer` does not. | `shellphish-afl` is a prebuilt AFL binary distribution and nixpkgs does not carry it. `phuzzer/phuzzers/afl.py` also refuses to start unless `/proc/sys/kernel/core_pattern` reads `core`; upstream writes it through a `/hostproc` bind mount in a privileged container, which an unprivileged runner cannot do. (It checks the cpufreq governor too, but only where `/sys/.../scaling_governor` exists, which on a virtualised runner it does not -- upstream sets `core_pattern` and nothing else.) |
| Freeze coverage | `angr-management`'s `pyinstaller-build.yml` freezes on `ubuntu-22.04`, `ubuntu-24.04`, `ubuntu-24.04-arm`, `windows-2022` and `macos-15`. | Fixed below: this ran on three of the five, so ARM64 Linux and the older Ubuntu upstream uses as its AppImage baseline were never built at all. |
| Runner images | angr's `installation` job gates on `windows-2025`, `macos-26` and `ubuntu-24.04` py3.14. | The native matrix here uses `windows-2022` and `macos-15` -- two generations behind what upstream currently gates on. Bumping them is a one-line change per entry in `ci/suites.json` and has not been tried. |
| Coverage | `angr/coverage.yml` and `angr-management/coverage.yml` re-run the whole sharded suite under `pytest --cov` and `cargo llvm-cov` and upload to Codecov on every pull request. | Deliberate, for now. It is a second full matrix -- ten more angr shards, three more angr-management -- to catch untested lines, which is not a failure this repository has had. The one it has had twice is a suite quietly skipping, and coverage would not have caught either instance: a test that skips still executes every line up to the `skip()` call. That is what `ci/skips.json` is for. Revisit once a Codecov project exists. |
| Decompiler snapshots | `ci-settings`' `corpus-test` job diffs decompiler output against `angr/dec-snapshots` and uploads the diff. | The corpus job is not ported. It is the decompiler's only regression detector, so this is the largest single omission. |
| Nightly | Ten repositories run a nightly that widens the matrix -- angr's runs the full suite on Windows and macOS, which is `--collect` only here. | A nightly on an experiment is recurring cost on somebody else's account. Deliberate. |
| Release | `angr-release.yml` bumps versions, builds sdists and wheels for six components, verifies them with `--only-binary`, tags and publishes to PyPI. | Only `pypcode` wheels are built here, and nothing is published. Publishing from an experiment is not something to do by accident. |
| Bundles | `angr-management`'s nightly build produces an NSIS installer, an AppImage and a macOS `.app`, and tests each by launching it. | Only the raw PyInstaller freeze is built, and only the Linux one is launched. |
| Cross-repo fixtures | `ci-settings/actions/binaries-ref` reads `angr/binaries#N` out of a pull-request body so a fixture and the code that needs it go green together. | `binaries` is pinned in `flake.lock` with no override. A new fixture therefore needs two rounds here. |

## Regenerating the tree

```shell
ci/import.py                      # every component, at upstream head
ci/import.py --component cle      # just one
```

There is no attempt to preserve per-component history. This is a snapshot with
its provenance written down, not a migration.
