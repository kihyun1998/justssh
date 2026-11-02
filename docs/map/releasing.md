# Releasing

How the library crates reach crates.io (`.github/workflows/release.yml`), and what to watch when changing it.

## What is published, and in what order

Four crates are published: `justssh-wire`, `justssh`, `justssh-keys` and `justssh-tokio`. `justssh-broker` is `publish = false`.

They go in dependency order: `justssh-wire`, then `justssh`, then `justssh-keys`, which depends on `justssh` as a normal dependency, then `justssh-tokio`. `cargo publish` waits for each crate to appear in the index before the next one resolves it.

crates.io takes no path-only dependency, so the workspace's path dependencies in the root `Cargo.toml` carry a version as well. Each published crate excludes `tests/` and `fuzz/`.

## Cutting a release

1. Raise the version in the root `Cargo.toml`: `[workspace.package]` and the three `[workspace.dependencies]` entries, which must name the same version. Merge it.
2. Tag the merge commit `v<version>` and push the tag. The workflow publishes from the tagged commit.

The workflow file the run uses is the one in the tagged commit, not the one on `main`.

## Trusted Publishing

No crates.io token is stored. The job proves who it is over OIDC (`id-token: write`), and `rust-lang/crates-io-auth-action` exchanges that for a short-lived publish token, which the action's post step revokes when the job ends.

crates.io holds one GitHub configuration per crate, not one per repository, so each of the four has its own:
- owner `kihyun1998`, repository `justssh`, workflow `release.yml`;
- no environment, which means crates.io accepts a run from any environment.

Read on 2026-11-02 with `GET https://crates.io/api/v1/trusted_publishing/github_configs?crate=<name>` and the owner's token.

The job names the environment `crates-io`. GitHub creates an environment a job names on its first run, so it needs no setup. Naming `crates-io` on the four crates.io configurations as well would make crates.io refuse a run from any other environment; that is not done.

A Trusted Publisher is configured on a crate that already exists, so a crate name's first publish cannot go this way. 0.1.0 was published by hand on 2026-10-26, with `cargo login` and `cargo publish` in the order above.

## Skipping what is already published

Before each crate the job asks the crates.io API for that version:
- 200: crates.io has it, and the crate is skipped;
- 404: it is published;
- anything else: the job stops.

So a release that failed partway is run again on the same tag and goes on from the crate that failed, and a tag on a version published by hand runs without publishing. A crate name the job cannot find in the workspace gives an empty version, which the API answers with 404, so `cargo publish` fails on it rather than the job skipping it.

The job asks the API rather than the sparse index (`index.crates.io`). On 0.1.0 the index served a cached 404 for `justssh-wire` for over 80 minutes after the API had it (`X-Cache: HIT`, `Age` climbing, no `Cache-Control`), and `justssh` could not be published until it cleared. Why the 404 was cached was not established.

The API answers 403 to a request with no `User-Agent`, so the job sends one.

## 0.1.0

Each `.crate` records the commit it was packaged from in `.cargo_vcs_info.json`. `justssh`, `justssh-keys` and `justssh-tokio` came from `906d26f`, the merge of #85. `justssh-wire` came from `1eb7a6e`, the head of #85 before the merge, which has the same tree.

## How it is proven

The loop was run locally on 2026-11-02 with `cargo publish` replaced by `echo`:
- at 0.1.0, all four were skipped;
- with the version changed to 0.1.1, all four went to `cargo publish`, in order.

The OIDC exchange and a publish through it have not run yet. The first tagged run proves them.
