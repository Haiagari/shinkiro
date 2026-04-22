#!/usr/bin/env python3
"""
OzyRecon OPSEC Guard - Pre-commit Hook
Detecta dominios, IPs y secretos en archivos antes de permitir el commit.
"""

import sys
import subprocess
import re

import yaml
from pathlib import Path

# Configuración por defecto (si no hay archivo yaml)
DEFAULT_PATTERNS = [
    r'(?<!Chrome/)(?<!rv:)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', # IPs genéricas
]

def load_filters():
    """Carga patrones desde el archivo de configuración."""
    config_path = Path(__file__).resolve().parents[1] / "config" / "opsec_filters.yaml"
    patterns = DEFAULT_PATTERNS.copy()
    allowed_files = []
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)
                patterns.extend(data.get('blocked_patterns', []))
                allowed_files = data.get('allowed_files', [])
        except Exception as e:
            print(f"⚠️ Warning: Could not load OPSEC config: {e}")
    
    return patterns, allowed_files

def get_staged_files():
    """Obtiene la lista de archivos en staging."""
    result = subprocess.run(['git', 'diff', '--cached', '--name-only'], capture_output=True, text=True)
    files = result.stdout.strip().split('\n')
    return [f for f in files if f]

def check_file(filepath, patterns, allowed_files):
    """Escanea un archivo en busca de patrones prohibidos."""
    if not filepath or filepath == '': return False
    
    # Ignorar este mismo script, el archivo de filtros y los permitidos
    if 'opsec_check.py' in filepath or 'opsec_filters.yaml' in filepath or filepath in allowed_files:
        return False

    try:
        content = subprocess.run(['git', 'show', f':{filepath}'], capture_output=True, text=True).stdout
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                val = match.group()
                # --- EXCEPCIONES PARA INFRAESTRUCTURA LOCAL ---
                if val in ['0.0.0.0', '127.0.0.1', '8.8.8.8', '1.1.1.1']:
                    continue
                
                print(f"❌ OPSEC ALERT: Pattern '{pattern}' found in '{filepath}' (Value: {val})")
                return True
    except Exception:

        pass
    return False

def main():
    patterns, allowed_files = load_filters()
    files = get_staged_files()
    failed = False
    for f in files:
        if check_file(f, patterns, allowed_files):
            failed = True
    
    if failed:
        print("\n🛑 COMMIT RECHAZADO: Se detectó información sensible del target.")
        print("💡 Anonimiza los datos o asegúrate de que los archivos estén en .gitignore.")
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main()
