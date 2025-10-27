# Contributing to MIRACL Trust Client JS Library

## Git Commit Policy

> Concise rules for this repository.
> Details: <https://www.conventionalcommits.org/>
### Format

```txt
<type>: <subject>
<body>
<footer>
```

* **type**: use one of:

  * `feat` — new feature or change in behaviour (e.g., `feat: add new feature`)
  * `fix` — bug fix (e.g., `fix: correct validation logic`)
  * `perf` — performance improvement, no behaviour change (e.g., `perf: improve
    response time`)
  * `refactor` — internal code change, no behaviour change. Includes
    formatting-only changes. (e.g., `refactor: reorganise module structure`)
  * `test` — adding missing tests or correcting existing tests (e.g., `test: add
    smoke test`)
  * `docs` — documentation (e.g., `docs: update guide`)
  * `ci` — CI configuration/jobs (e.g., `ci: increase job timeout`)
  * `build` — build system or artefacts (e.g., `build: update dockerfile`)
  * `chore` — maintenance (e.g., `chore: update dependencies`)
  * `revert` — revert (e.g., `revert: rollback previous change`)
* **subject**: imperative, no full stop, does not start with a capital letter,
  **≤ 50 characters (including type)**
* **body**: wrap at **72 characters**; explain **what & why** (not how)
* **footer**: optional notes

### Commit template

A commit template with 50/72 visual guides is provided in
[.gitcommit](/.gitcommit). Set it with:

```sh
git config commit.template .gitcommit
```
