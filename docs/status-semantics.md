# Status semantics

`fhe-attack-replay` distinguishes five attack-level statuses and a
derived run-level status. Treat them as honest signals, not as a green/red
binary.

## Per-attack status

| Status            | Meaning                                                                                          |
|-------------------|--------------------------------------------------------------------------------------------------|
| `SAFE`            | The attack actually ran end-to-end against the configured target and the attack did **not** reproduce. |
| `VULNERABLE`      | The attack actually ran and **did** reproduce the published break.                              |
| `SKIPPED`         | The attack does not apply to this `(library, scheme, mode)` configuration.                       |
| `NOT_IMPLEMENTED` | The attack module exists as a citation-bearing scaffold; replay logic is pending.                |
| `ERROR`           | The replay raised an unexpected exception (bug in the harness or the adapter).                   |

A `SAFE` verdict is meaningful only relative to the threat model encoded
in the attack module. See [DISCLAIMER.md](../DISCLAIMER.md).

## Module intent levels

The framework supports three intent levels for a module. Modules should
declare which level they implement in the result `evidence` dict so users
know how strong a `SAFE` verdict is.

| Intent           | What it does                                                                                  |
|------------------|------------------------------------------------------------------------------------------------|
| **Replay**       | Runs the exploit logic end-to-end and decides on real outcomes.                                |
| **Risk check**   | Detects known-vulnerable parameter/config patterns without actually exploiting them.           |
| **Artifact check** | Validates traces, logs, or evidence files produced by an external tool (e.g. a power-trace capture). |

A `SAFE` result from a *replay* is stronger than a `SAFE` result from a
*risk check*, which is stronger than a `SAFE` result from an *artifact
check* on user-supplied evidence.

## Run-level overall status

The `RunReport.overall_status` is derived from the worst per-attack
result, in this priority order:

1. `VULNERABLE` — at least one attack reproduced.
2. `ERROR` — at least one attack errored.
3. `NOT_IMPLEMENTED` — at least one attack is still a scaffold.
4. `SAFE` — at least one attack ran and every result was safe or skipped.
5. `SKIPPED` — every selected attack was skipped (or the result list is
   empty); nothing actually ran.

## CLI exit codes

| Exit | Trigger                                                                                  |
|-----:|-------------------------------------------------------------------------------------------|
| `0`  | At least one attack ran and every result was `SAFE`/`SKIPPED` (or `NOT_IMPLEMENTED` with `--allow-not-implemented`). |
| `2`  | Any `VULNERABLE`.                                                                          |
| `3`  | Any `ERROR`.                                                                               |
| `4`  | Any `NOT_IMPLEMENTED` without `--allow-not-implemented`, or a `--min-coverage` failure.    |
| `5`  | Every selected attack was `SKIPPED` and `--allow-skipped` was not passed.                  |
| `64` | Usage error (missing `--lib`, malformed args, etc.).                                       |

The default is intentionally strict: silent green CI for runs that did
not actually exercise an attack is a footgun, not a feature.

`--min-coverage N` adds a second gate after status handling. For example,
`--min-coverage 1.0` requires every selected attack to produce an implemented
verdict (`SAFE`, `VULNERABLE`, or `ERROR`). This is useful when a PR should not
pass with mostly scaffolded or skipped checks.
