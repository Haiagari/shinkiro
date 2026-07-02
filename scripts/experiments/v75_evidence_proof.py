
import json
from src.intelligence.core.classifier import semantic_classifier
from src.utils.crypto import evidence_signer
from src.intelligence.export.exporter import siem_exporter

# 1. Mock de un activo altamente sensible (Shadow IT + Admin Panel)
mock_asset = {
    "domain": "dev-admin.internal.promptwall.test",
    "title": "Control Panel - Restricted Access",
    "technologies": ["WordPress", "PHP"],
    "headers": {"X-Powered-By": "WP Engine", "Server": "Apache"}
}

print("=== [1] CLASIFICACIÓN SEMÁNTICA (INFERENCE TRACE) ===")
# Ejecutamos el clasificador formal v7.5
analysis = semantic_classifier.classify_asset(mock_asset)

# Mostramos la evidencia del razonamiento (Explainability)
print(f"Asset: {mock_asset['domain']}")
print(f"Labels: {analysis['labels']}")
print(f"Impact: {analysis['impact']}")
print(f"Confidence: {analysis['confidence']}")
print("\n--- Reasoning Trace (EXPLAINABILITY) ---")
for step in analysis['trace']:
    print(f" - [{step['type'].upper()}] Rule: {step['rule'] if 'rule' in step else step['pattern']} -> Match: {step.get('match') or step.get('pattern')} (Contribution: +{step['contribution']})")

print("\n=== [2] INTEGRIDAD DE EVIDENCIA (DIGITAL SIGNATURE) ===")
# Firmamos el hallazgo digitalmente
signature = evidence_signer.sign_data(analysis)
print(f"Digital Signature (Ed25519): {signature[:64]}...")

# Verificamos la firma para demostrar que es inmutable
is_valid = evidence_signer.verify_data(analysis, signature)
print(f"Signature Verification: {'✅ VALID' if is_valid else '❌ INVALID'}")

print("\n=== [3] EXPORTACIÓN EMPRESARIAL (CEF FORMAT) ===")
# Generamos la línea para el SIEM
finding_for_siem = {**mock_asset, **analysis, "evidence_signature": signature}
cef_line = siem_exporter.export_to_cef(finding_for_siem)
print(f"CEF Export Line:\n{cef_line}")
