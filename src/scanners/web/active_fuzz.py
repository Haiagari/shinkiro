"""
Active Fuzzing Module — ffuf Integration
Descubrimiento de superficie no indexada mediante fuzzing activo.
"""

from pathlib import Path
from src.utils import log, run_cmd, load_config
from .rate_limiter import wait_if_needed

ROOT_DIR = Path(__file__).resolve().parents[2]

def run_active_fuzz(target: str, out_dir: Path, threads: int = 20) -> dict:
    """Ejecuta fuzzing activo sistemático con ffuf."""
    out_dir.mkdir(parents=True, exist_ok=True)
    config = load_config()
    
    wordlist = config.get("wordlists", {}).get("directories", str(ROOT_DIR / "resources" / "wordlists" / "common.txt"))
    if not Path(wordlist).exists():
        log(f"Wordlist no encontrada: {wordlist}. Saltando ffuf.", "warn")
        return {"status": "skipped"}

    log(f"Iniciando fuzzing activo con ffuf sobre {target}...", "info")
    output_file = out_dir / "ffuf_results.json"
    
    # OPSEC: ffuf también debe respetar un poco el ritmo
    cmd = (
        f"ffuf -u {target}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 "
        f"-o {output_file} -json -t {threads} -timeout 5 -s"
    )
    
    try:
        run_cmd(cmd, timeout=900)
        log(f"ffuf completado. Resultados en {output_file}", "success")
        return {"status": "success", "output": str(output_file)}
    except Exception as e:
        log(f"Error en ffuf: {e}", "error")
        return {"status": "error", "error": str(e)}
