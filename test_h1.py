import requests
from requests.auth import HTTPBasicAuth
import yaml

def test_h1():
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    
    api_key = config.get("bugbounty", {}).get("hackerone_api_key")
    username = config.get("bugbounty", {}).get("hackerone_username")
    
    print(f"[*] Probando con Usuario: {username}")
    
    # Endpoint específico para hackers
    url = "https://api.hackerone.com/v1/hacker/programs"
    auth = HTTPBasicAuth(username, api_key)
    
    try:
        r = requests.get(url, auth=auth)
        if r.status_code == 200:
            print("[+] ¡AUTENTICACIÓN EXITOSA! 🚀")
            print(f"[+] Sos: {r.json().get('data', {}).get('attributes', {}).get('username')}")
        else:
            print(f"[-] ERROR: Status {r.status_code}")
            print(f"[-] Respuesta: {r.text}")
    except Exception as e:
        print(f"[-] ERROR DE CONEXIÓN: {e}")

if __name__ == "__main__":
    test_h1()
