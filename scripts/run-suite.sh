#!/usr/bin/env bash
# Run a benchmark suite unattended through the DSH headless profile.
#
#   scripts/run-suite.sh <scenarios-file> <model> [model...]
#
# Optional environment:
#   DSH            launcher command (default: dsh)
#   DSH_PROFILE    profile that has the plugin installed (default: headless)
#   JUDGE          judge model; strongly recommended (without it the run is self-judged)
#   CONFIRM_JUDGE  second judge model for confirmation samples
#   ATTACKER       attacker model (default: the headless session's model)
#   TURNS TRIALS SAMPLES THRESHOLD   numeric suite settings
#   SUBAGENTS      set to false to stop targets starting subagents (default: allowed)
#
# Results land in <cwd>/.ai-benchmark/suites/<stamp>/ (scorecards/, leaderboard.md, leaderboard.csv).
set -euo pipefail

if [ "$#" -lt 2 ]; then
  sed -n '2,16p' "$0"
  exit 2
fi

scenarios=$(realpath "$1")
shift

args=$(node -e '
const [file, ...targets] = process.argv.slice(1);
const env = process.env;
const args = { targets, scenarios_file: file };
const numeric = { TURNS: "turns", TRIALS: "trials", SAMPLES: "judge_samples", THRESHOLD: "pass_threshold" };
for (const [name, key] of Object.entries(numeric)) if (env[name]) args[key] = Number(env[name]);
if (env.JUDGE) args.judge_ai = env.JUDGE;
if (env.CONFIRM_JUDGE) args.confirm_judge_ai = env.CONFIRM_JUDGE;
if (env.ATTACKER) args.main_ai = env.ATTACKER;
if (env.SUBAGENTS) args.target_subagents = !/^(false|off|no|0)$/i.test(env.SUBAGENTS);
process.stdout.write(JSON.stringify(args));
' "$scenarios" "$@")

prompt="Call the benchmark_suite tool exactly once with these arguments, unchanged: ${args}
When it finishes, print its summary field verbatim and nothing else."

# shellcheck disable=SC2086 # DSH may be a multi-word command such as "npx @deepseek-ai/dsh".
exec ${DSH:-dsh} --profile "${DSH_PROFILE:-headless}" "$prompt"
