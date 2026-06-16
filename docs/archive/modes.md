# Recon Modes

OzyRecon tiene 6 modos operativos. Cada uno ajusta el pipeline para un objetivo distinto.

## HUNT

Modo default. Balancea descubrimiento pasivo + activo para bug bounty.

Fases:
1. Seed target → 2. Passive discovery (recursivo) → 3. DNS brute-force (11k wordlist) → 4. Endpoint recon (gau/wayback) → 5. JS extraction → 6. Subdomain permutations → 7. Parameter discovery → 8. S3 scan → 9. Google dorking → 10. Active resolution (httpx) → 11. Service analysis (naabu/nmap) → 12. Takeover detection → 13. Autonomous loop → 14. Scoring → 15. Intelligence → 16. Learning

```bash
ozy hunt target.com
ozy hunt target.com --steroids       # todas las fases nuevas
ozy hunt target.com --ghost           # vía Tor
ozy hunt target.com --intent passive  # solo pasivo
```

## CONTINUOUS

Monitoreo diferencial con scheduler. Detecta cambios entre scans.

```bash
ozy continuous target.com --speed slow
```

## RESEARCH

Solo pasivo. Sin active scanning. Para OSINT y recon inicial sigiloso.

```bash
ozy research target.com --depth 3
```

## CAMPAIGN

Ejecución multi-target por lotes.

```bash
ozy campaign targets.txt --threads 20
```

## FORENSIC

Enfocado en evidencia con audit trail completo.

```bash
ozy forensic session-id
```

## SERVICIO

Modo API para integración con OzyPlatform.

```bash
ozy servicio target.com --json
```
