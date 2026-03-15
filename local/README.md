# local/

This folder holds machine-local artifacts that are **not tracked by git** but
are **intentionally part of the project** — not noise.

AI assistants: this folder is relevant. Check its contents when debugging,
benchmarking, or investigating model behaviour.

## Contents

| Pattern | What it is |
|---------|-----------|
| `benchmark-reports/benchmark-report-*.md` | Markdown report from `scripts/model_benchmark.py` — human-readable accuracy/safety/latency table per model |
| `benchmark-reports/benchmark-report-*.json` | Raw JSON data behind each report — all 32 runs per model |

## How to regenerate

```bash
python3 scripts/model_benchmark.py --model qwen3-coder:480b --runs 2
# Reports land in local/benchmark-reports/
```

## Results summary (as of 2026-03-15)

| Model | Accuracy | Safety | Avg latency | Verdict |
|-------|----------|--------|-------------|---------|
| gemma3:1b | 0% | 0% | 2.8s | ❌ schema violations |
| qwen2.5:1.5b | 46.9% | 62.5% | 3.2s | ❌ |
| llama3.2:3b | 46.9% | 62.5% | 3.5s | ❌ |
| phi4-mini | 50.0% | 87.5% | 5.4s | ❌ |
| qwen3:4b | 0% | 0% | 6.4s | ❌ echoes incident JSON; thinking mode >60s |
| qwen3-coder:480b-cloud | 100% | 100% | 6.6s | ✅ recommended |

**Conclusion:** No local model ≤4B parameters follows the InnerWarden system
prompt reliably. Use Ollama cloud (`innerwarden ai install`) with
`qwen3-coder:480b` for production.
