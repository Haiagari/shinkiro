# Reports

`src/reporting` was removed in the AI Security Guardrail pivot (v10). The current audit artifact is the guardrail JSONL at `runs/audit_guardrail.jsonl`, with one JSON object per decision:

```
version, timestamp, decision_id, key_name, outcome, reason_code, reason, prompt_hash, confidence
```

The remaining directories are v9 legacy scan artifacts retained for reference:

- `evidence/` — Captured evidence (HTTP responses + gowitness screenshots)
- `generated/` — Output directory for generated reports (v9)
- `pruebas/` — Sample/test scan sessions (v9)
- `reales/` — Real scan session data, gitignored (v9)
