# Professional Daily Workflow

## Fast daily loop

```bash
python ozy.py doctor
python ozy.py scope list
python ozy.py flow dominio-autorizado.com
python ozy.py diff dominio-autorizado.com
```

## 1) Validate the environment

Run `doctor` before starting the day.

```bash
python ozy.py doctor
```

Check:
- Python OK
- tools OK
- dependencies OK
- database OK

## 2) Maintain scope / authorization

Use `scope` to keep `config/scope.yaml` current and avoid manual edits.

```bash
python ozy.py scope list
python ozy.py scope add dominio-autorizado.com
python ozy.py scope import targets.txt
```

Check:
- allowed domains
- forbidden patterns
- target present in `config/scope.yaml`

## 3) Run analysis

Use `flow` for the full staged run.

```bash
python ozy.py flow dominio-autorizado.com
```

What you should see:
- preflight
- scope validation
- adaptive hunt
- data summary
- report generation
- diff summary

## 4) Read the output

The flow output should answer:

- Is the environment healthy?
- Is the target in scope?
- What changed in this scan?
- Where are the artifacts?

Watch for:
- `Flow Results` → session folder, report status, report path
- `Data Summary` → live hosts, open ports, critical services, high-value hosts
- `Attack surface changes detected` → compare with previous baseline

## 5) Review results on disk

Look in:

- `runs/<session_id>/` — traces, analysis, evidence
- `reports/reales/` — final reports
- `exports/siem/` — export outputs when applicable

## 6) Compare sessions

```bash
python ozy.py diff dominio-autorizado.com
```

Check:
- new assets
- service changes
- drift against prior sessions

## Multi-target workflow

```bash
python ozy.py scope import targets.txt
python ozy.py flow target1.com
python ozy.py flow target2.com
python ozy.py diff target1.com
python ozy.py diff target2.com
```

## Rules of thumb

- `doctor` first
- `scope` for authorization
- `flow` for execution
- `diff` for comparison
- `runs/` and `reports/` for evidence

## What not to worry about

- Notification integrations are silent when unconfigured.
- Placeholder credentials are treated as disabled.
- `try-ozyrecon.sh` is for local onboarding, not daily professional use.

## Optional periodic operations

```bash
python ozy.py schedule
python ozy.py serve
```
