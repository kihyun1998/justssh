# justssh

## Agent skills

### Issue tracker

Issues live in GitHub Issues on `kihyun1998/justssh` (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Comments

A comment is one of: a license header; behaviour forced by an outside dependency, platform, vendor or protocol we cannot reshape (Rust's `SAFETY:` on `unsafe` is one); a tool directive; a doc comment on a public API; an issue or RFC link for a constraint the code cannot express. Nothing else: a surprise in our own code is fixed, not explained.

A measured value, an outside constraint and the reason behind a design judgement go to the territory note under `docs/map/`. Where none seems to hold it, search the folder and the code symbol first; only then start a new note, named for what the system does there, not for the file. A workaround's reason goes nowhere: the workaround is fixed. History goes to the commit message. Comments written before this rule may still carry what the map keeps: never delete one whose content the map does not yet hold — move it there first.
