.PHONY: install wordlists tools check clean help

PYTHON := python3
PIP    := pip3

help:
	@echo ""
	@echo "  BugBounty Framework — Comandos disponibles"
	@echo "  ─────────────────────────────────────────"
	@echo "  make install    Instalar dependencias Python"
	@echo "  make tools      Instalar herramientas Go (requiere Go instalado)"
	@echo "  make wordlists  Descargar wordlists de SecLists"
	@echo "  make check      Verificar herramientas instaladas"
	@echo "  make clean      Limpiar output/"
	@echo ""
	@echo "  Uso rápido:"
	@echo "  python main.py -t target.com --full"
	@echo "  python main.py -t target.com --recon"
	@echo "  python main.py -t target.com --vulns"
	@echo ""

install:
	@echo "[*] Instalando dependencias Python..."
	$(PIP) install -r requirements.txt
	@echo "[+] Listo."

tools:
	@echo "[*] Instalando herramientas Go..."
	@which go > /dev/null || (echo "[-] Go no encontrado. Instala desde https://go.dev/dl/" && exit 1)
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
	go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	go install github.com/projectdiscovery/katana/cmd/katana@latest
	go install github.com/tomnomnom/assetfinder@latest
	go install github.com/tomnomnom/waybackurls@latest
	go install github.com/lc/gau/v2/cmd/gau@latest
	go install github.com/hakluke/hakrawler@latest
	go install github.com/hahwul/dalfox/v2@latest
	go install github.com/ffuf/ffuf/v2@latest
	@echo "[+] Herramientas instaladas. Asegúrate de tener ~/go/bin en tu PATH."
	@echo "    Agrega a tu ~/.bashrc o ~/.zshrc:"
	@echo "    export PATH=\$$PATH:\$$HOME/go/bin"

wordlists:
	@echo "[*] Descargando wordlists de SecLists..."
	@mkdir -p wordlists
	curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
		-o wordlists/common.txt
	curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
		-o wordlists/subdomains.txt
	curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" \
		-o wordlists/params.txt
	curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" \
		-o wordlists/lfi.txt
	@echo "[+] Wordlists descargadas en wordlists/"
	@wc -l wordlists/*.txt

check:
	@echo ""
	@echo "[*] Verificando herramientas..."
	@echo ""
	@for tool in subfinder amass assetfinder dnsx httpx naabu nmap nuclei katana hakrawler waybackurls gau dalfox sqlmap ffuf curl jq python3; do \
		if command -v $$tool > /dev/null 2>&1; then \
			echo "  [+] $$tool"; \
		else \
			echo "  [-] $$tool  (no encontrado)"; \
		fi; \
	done
	@echo ""

clean:
	@echo "[*] Limpiando output/..."
	@find output/ -type f -not -name ".gitkeep" -delete 2>/dev/null; true
	@echo "[+] Listo."
