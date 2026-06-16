
import json
from src.intelligence.core.classifier import semantic_classifier

# Simulamos 100 subdominios de ruido (la mayoría basura o CDNs)
raw_assets = [f"asset-{i}.target.com" for i in range(100)]
# Agregamos 2 activos que realmente importan
raw_assets.append("admin.target.com")
raw_assets.append("api-v1.target.com")

print(f"Raw Inputs from Tools: {len(raw_assets)}")

# El motor filtra y clasifica
findings = []
for asset in raw_assets:
    analysis = semantic_classifier.classify_asset({"domain": asset})
    # Solo consideramos findings lo que tenga impacto HIGH o CRITICAL
    if analysis["impact"] in ["HIGH", "CRITICAL"]:
        findings.append({"asset": asset, "impact": analysis["impact"]})

print(f"Intelligent Findings: {len(findings)}")
reduction = len(raw_assets) / len(findings) if findings else 0
print(f"Noise Reduction Factor: {reduction:.1f}x")

print("\n--- Critical Assets Identified ---")
for f in findings:
    print(f" - {f['asset']} [{f['impact']}]")
