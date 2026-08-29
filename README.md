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
ci/run-suite.sh cle        # run one component's suite
ci/run-suite.sh angr --shard 1 --of 10
```

A component's tests are the ones upstream wrote, unmodified, and they find
their fixtures the way they always have — as `../../binaries` relative to the
tests directory, which in this layout is the repository root.

## The fixtures are tracked here, and are not in the flake

`binaries/` is `angr/binaries`, vendored: 1824 files and about 460 MB. It is
here because a fixture and the test that needs it belong in one commit.
Upstream needs a whole action — `ci-settings/actions/binaries-ref`, which
parses a fixture pull request's number out of a code pull request's body — to
approximate that across two repositories, and a rollup of a hundred changes
made the cost concrete: 28 of them referenced fixture pull requests that no
pin could resolve, so they could not be green anywhere.

**It is deliberately not a Nix input.** Half a gigabyte in the flake would
land in every closure, every `nix copy` to the release cache, and every
warm-cache key — and a one-line fixture would then rebuild the world. So:

- `flake.nix` has no `binaries` input. The `fauxware-cfg` check needs one
  8.7 KB file and gets exactly that file, content-addressed on its own with
  `builtins.path`, which is also the only fixture path in
  `ci/nix-cache.sh`'s key.
- Nothing else reaches Nix. Adding, changing or deleting a fixture cannot
  invalidate a build or a cached closure.
- The suites read the working tree, not the store, which they can because
  they run in `nix develop` rather than in the sandbox.

Both lanes already put the tree where the `../../binaries` convention looks:
`ci/run-suite.sh` symlinks it beside the scratch run directory and
`ci/run-native.py` does the same under `.ci-run-native`. That link is
load-bearing — `angr/tests/ailment/test_irsb.py` walks up from
`dirname(__file__)` without `realpath`, and without the link it silently
sub-skips six architectures inside a test that still reports as passed.

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
| `angr/angr-data` | 200 MB of generated JSON. |

One test is deselected, in `ci/suites.json`, with its reason beside it and
printed on every run of that suite. Nothing else is. That includes the suites
for angr's optional `llm` extra: `pydantic-ai`, `mcp` and `fastmcp` are
packaged in `nix/python-overlay.nix` rather than skipped, because a suite that
is skipped for want of a dependency is a suite that tells you nothing. The
same reasoning packaged `pysoot` -- with a JDK in the test shell, since
jpype needs one and pysoot's own suite proves it is absent -- and
`tracer`, with the prebuilt `shellphish-qemu` wheel it requires: those two
gate thirty-nine of angr's own tests, which reported as skips for as long as
the components sat in the tree unpackaged. What the counts are now is a
question for the last run's summary, for the reason the cost section gives.

All five now run their own suites, which is the shape of what upstream's
`ga-build.sh` does: without them a claripy change is tried against angr and
angr-management and nothing else. It is not the whole of it. Upstream's
`repo-list.txt` names twenty-two repositories and tests everything
transitively downstream of the one being changed; five of them are here. See
the table below for what that leaves out.

Every one of them also runs where upstream runs it, not only under Nix.
`pysoot` additionally runs its own twelve-cell matrix -- Python 3.10 through
3.13 across ubuntu-22.04, macos-14 and windows-2022 -- because that is what
its own CI does, and `phuzzer` runs on a Linux runner with the kernel tuned
for AFL the way upstream tunes it.

A component's own `.github/` does not come in: only the workflow at the root
of this repository runs, and seven dead copies of upstream's workflows would
suggest otherwise.

## How CI stays fast

One job builds the whole closure and publishes it as a Nix binary cache; every
other job substitutes from it, so a test job starts its suite instead of
compiling angr's Rust extension for itself. Fifteen test jobs then run at
once.

The cache lands in two places. `actions/cache` is the fast path — same
datacentre, restored in seconds — but it is a 10 GB LRU shared by the whole
repository, and one busy afternoon evicts the entry that fourteen jobs are
about to ask for. So a GitHub release holds the authoritative copy, one asset
per source revision, on no shared budget and evicted only by this
repository's own prune, which keeps the newest few; `ci/nix-cache.sh`
manages both and the jobs fall back from one to the other.

The key is a hash of the git tree hashes of the pins, the Nix expressions and
each component's source, so it changes when a rebuild would be needed and not
otherwise. Editing this README does not invalidate it.

The test matrix is one job per shard, so the stage costs what its slowest
*shard* costs rather than what its slowest suite costs. `ci/suites.json` is
the whole of it: which suites share a job — the eight that finish in seconds
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

## When it goes wrong

Two things are worth knowing before they happen.

**A bad cache asset.** The key is a hash of git tree hashes, so it cannot be
busted by editing a file that is not in it, and `ci/nix-cache.sh push` treats
a key it finds published as done. If a closure that should not exist gets
uploaded, recovery is by hand and needs repository write access:

```shell
key=$(ci/nix-cache.sh key)
gh release delete-asset nix-cache "$key.tar.zst" --repo angr/mono
gh cache delete "nix-store-$key" --repo angr/mono   # the fast path in front
```

Both, in that order: an Actions cache entry is immutable per key, so deleting
the release asset alone leaves every job restoring the same bad copy.

**Serialized runs on main.** `cancel-in-progress` is off for `main`, because
the run being cancelled may be the one uploading that asset. So main's runs
queue, the worst case for one of them is around three and a half hours if
`warm` and the test matrix both reach their ceilings, and GitHub keeps only
one run pending behind the one in flight -- a third push during a busy window
supersedes the queued one, and that middle commit gets no CI result at all,
not even a red one.

## What upstream does that this does not

An experiment is only useful if it is honest about its edges. Each of these
is a thing upstream CI does today and this repository does not.

| | what is missing | why it is not here yet |
| --- | --- | --- |
| Coverage gating | Upstream uploads to Codecov, which comments on the pull request and enforces a project threshold. | Measured here -- Python, C and Rust -- and merged, rendered and ratcheted by `ci/coverage-report.py` against `ci/coverage.json`. What is missing is only the Codecov project itself: no PR comment, no hosted history. |
| The rest of the dependency graph | `ci-settings/ci-image/conf/repo-list.txt` names twenty-two repositories, and `test.py` runs the suite of everything transitively downstream of the one under test. Five are imported here. `rex`, `patcherex`, `heaphopper`, `shellphish/driller` and the three `mechaphish` packages are not, nor is `archr`, which `rex` builds against. | Each is another repository to snapshot and another dependency set to package. The five here were chosen because two of them gate tests inside angr's own suite; the rest are a straightforward extension of the same work, not a different problem. |
| Nightly | Ten repositories run a nightly. Its distinctive content was angr's full suite on Windows and macOS, which now runs here on every push instead. What is left is the `NIGHTLY=1` slow-test tier in `ga-test.sh` and the Mailgun failure mail. | No `schedule:` trigger: a nightly on an experiment is recurring cost on somebody else's account, and the part that mattered is no longer nightly-only. |
| Release | `angr-release.yml` bumps versions, builds sdists and wheels for six components, verifies them with `--only-binary`, tags and publishes to PyPI. | Only `pypcode` wheels are built here, and nothing is published. Publishing from an experiment is not something to do by accident. |
| Bundles | `angr-management`'s nightly build produces an NSIS installer, an AppImage and a macOS `.app`, and tests each by launching it. | Only the raw PyInstaller freeze is built, and only the Linux one is launched. |
| Cross-repo fixtures | `ci-settings/actions/binaries-ref` reads `angr/binaries#N` out of a pull-request body so a fixture and the code that needs it go green together. | Not needed: `binaries/` is tracked here, so a fixture and the code that needs it are one commit. |

## Regenerating the tree

```shell
ci/import.py                      # every component, at upstream head
ci/import.py --component cle      # just one
```

There is no attempt to preserve per-component history. This is a snapshot with
its provenance written down, not a migration.
