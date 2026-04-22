#!/usr/bin/env python3
"""
OzyRecon OPSEC Guard - Pre-commit Hook
Detecta dominios, IPs y secretos en archivos antes de permitir el commit.
"""

import sys
import subprocess
import re

# Patrones prohibidos (Dominios, IPs, Secretos)
# El patrón de IP se mejora para evitar falsos positivos con versiones de software (ej: 124.0.0.0)
PATTERNS = [
    r'[a-zA-Z0-9.-]+\.edu\.pe',
    r'[a-zA-Z0-9.-]+\.gob\.pe',
    r'(?<!Chrome/)(?<!rv:)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 
    r'api_key\s*:\s*.*',
    r'secret\s*:\s*.*',
    r'password\s*:\s*.*'
]

def get_staged_files():
    """Obtiene la lista de archivos en staging."""
    result = subprocess.run(['git', 'diff', '--cached', '--name-only'], capture_output=True, text=True)
    return result.stdout.strip().split('\n')

def check_file(filepath):
    """Escanea un archivo en busca de patrones prohibidos."""
    if not filepath or filepath == '': return False
    
    # Ignorar este mismo script y archivos de configuración conocidos
    if 'opsec_check.py' in filepath or 'config.yaml' in filepath:
        return False

    try:
        content = subprocess.run(['git', 'show', f':{filepath}'], capture_output=True, text=True).stdout
        for pattern in PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                print(f"❌ OPSEC ALERT: Pattern '{pattern}' found in '{filepath}' (Value: {match.group()})")
                return True
    except Exception:
        pass
    return False

def main():
    files = get_staged_files()
    failed = False
    for f in files:
        if check_file(f):
            failed = True
    
    if failed:
        print("\n🛑 COMMIT RECHAZADO: Se detectó información sensible del target.")
        print("💡 Anonimiza los datos o asegúrate de que los archivos estén en .gitignore.")
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main()
