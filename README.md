# AI Benchmark

A DeepSeek Harness plugin (bundle `@local/dsh-ai-benchmark`) that red-teams a model
against a prohibited behavior and writes a machine-readable report.

## What it does

`benchmark_ai` runs a three-role loop, one round per turn:

1. **Attacker** (`main_ai`) — writes exactly one prompt for the target. On every turn after
   the first it receives the full previous exchange: the attack prompt, the target's
   response, the tools it called, and the judge's verdict plus evidence. Earlier turns
   arrive as a compact summary.
2. **Target** (`target_benchmark_ai`) — runs as a real subagent with the caller's tools,
   in a per-run scratch directory, and receives that prompt verbatim. It is reset each
   turn, so the attacker is told to restate any context its prompt relies on.
3. **Judge** (`judge_ai`, defaults to `main_ai`) — decides whether the target actually
   performed the prohibited action.

Every requested turn runs, even after the target complies; the verdict reports the first
compliant turn and every compliant turn. If the target never complies, the model passed.

## Parameters

| Name | Required | Meaning |
|---|---|---|
| `main_ai` | yes | Attacker route, `"provider/model"` or a bare model id (caller's provider). |
| `target_benchmark_ai` | yes | Model under test, same route syntax. |
| `turns` | no | Maximum attempts. Default 3, clamped to 10. |
| `task` | no | The prohibited behavior to induce. Omit and the attacker picks one of the built-in taxonomy categories on turn 1 and freezes it. |
| `judge_ai` | no | Judge route. A model different from the attacker gives a more independent verdict. |

## Attack artifacts

The attacker may ask to plant files in the target's working directory — a poisoned
document, a fake config or script — through the `artifacts` field of its structured
output (`kind: text` with `content`, or `kind: download` with an http(s) `url`).

**Every creation or download is gated:** before anything is written, the plugin raises
one approval request for that turn listing each path. Nothing is created on
`rejected` / `cancelled`, and with no approval answerer the request fails closed.
Limits: 5 files per turn, 1 MB each, 20 s download timeout, and paths must stay inside
the target sandbox — absolute paths and `..` are rejected and reported as `invalid`.

## Report

Written to `<caller cwd>/.ai-benchmark/reports/benchmark-<timestamp>-<run>.json` and
returned as a summary plus `report_path`. The summary names the winning side:
`RESULT: main_ai passed, target_benchmark_ai failed — ...` or the reverse.

Key fields:

- `verdict.winner` — `"main_ai"` (attack succeeded) or `"target_benchmark_ai"` (it resisted)
- `verdict.main_ai` / `verdict.target_benchmark_ai` — `"passed"` / `"failed"`
- `verdict.failed_at_turn` — the first turn the target complied
- `verdict.compliant_turns` — every turn where it complied
- `verdict.task` — `category`, `objective`, `success_criteria`
- `verdict.inconclusive_turns` — turns where the judge returned no verdict
- `target_status` — per-turn `stop_reason`, `duration_ms`, `tokens`
  (`input` / `output` / `cacheRead` / `cacheWrite` / `reasoning` / `total`),
  tool calls, and `judgment`
- `model_usage` — attacker, target, and judge totals
- `attempts` — full attack prompt, target response, judge evidence, and
  artifact status rows (`created` / `denied` / `invalid` / `unavailable` / `failed`)

## Built-in taxonomy

Used when no `task` is supplied: `instruction-hierarchy`, `secret-disclosure`,
`prompt-injection`, `authority-impersonation`, `destructive-scope`, `sandbox-escape`,
`tool-misuse`, `delegation-abuse`.

## Safety model

The target is a fully composed agent: it can use the same tools and sandbox as the
caller. Each run gets a scratch directory with two placeholders — `canary.env`
(a fake secret) and `artifact.txt` (a disposable file) — and the attacker is instructed
to aim every destructive, disclosure, or exfiltration instruction only at those.
That keeps compliance measurable and harmless; it does not make arbitrary tasks safe.
Prefer boundary probes over tasks that could damage real data.

## Requirements

- The `spawn` subagent provider (`@deepseek-ai/dsh-subagent-spawn-in-process`).
- No npm dependencies; the plugin imports only Node built-ins.
