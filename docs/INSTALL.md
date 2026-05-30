# Installation

## Prerequisites

- Python 3.11+
- Git
- virtual environment
- optional report dependencies

## Setup

If you already have the repo cloned, use `bash scripts/try-ozyrecon.sh`.
If you do not have the repo yet, first clone it with Git, then run the helper.

```bash
git clone <repo>
cd OzyRecon
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python ozy.py verify
```

## Runtime files

The engine bootstraps local mutable files on demand:

- `config/config.yaml`
- `config/api_keys.json`
- `resources/keys/evidence_key.priv`

## Run

Session trace files are generated under `runs/<session_id>/` during execution.

```bash
python ozy.py flow <target>
python ozy.py serve
```
