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

Imported, one directory each. The seven components with suites of their own:
`archinfo`, `pyvex`, `pypcode`, `claripy`, `cle`, `angr`, `angr-management`.
Then five of the dependents upstream tests every core change against --
`pysoot`, `tracer`, `angr-platforms`, `angrop`, `phuzzer` -- which are here
because two of them gate tests inside angr's own suite: nineteen tests in
`tests/engines/test_java.py` and `test_cfgfast_soot.py` are behind
`skipUnless(pysoot)`, and the CGC trace helpers in `tests/common.py` are
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
the components sat in the tree unpackaged. angr's suite went from 2491 passed
/ 67 skipped to 2529 passed / 28 skipped.

Their *own* suites, and those of `angr-platforms`, `angrop` and `phuzzer`,
still run in no job. Upstream's `ga-build.sh` runs them, driven by
`ci-settings/ci-image/conf/repo-list.txt`, so that part is a gap and not a
decision -- see below.

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
matrix to matter — it is what the ten shards are dividing, and the other six
put together finish in under a minute.

## What upstream does that this does not

An experiment is only useful if it is honest about its edges. Each of these
is a thing upstream CI does today and this repository does not.

| | what is missing | why it is not here yet |
| --- | --- | --- |
| Dependent suites | All five dependents are imported and no job runs *their* tests. (`pysoot` and `tracer` are now packaged and in the test environment, which is what un-skipped thirty-nine of angr's.) | `angr-platforms`, `angrop` and `phuzzer` need suites of their own; `phuzzer` also needs AFL, which is not packaged here. |
| Coverage | `angr/coverage.yml` and `angr-management/coverage.yml` measure Python, C and Rust coverage and upload to Codecov on every pull request. | Nothing here measures coverage. Codecov also needs a project and a token this repository does not have. |
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
