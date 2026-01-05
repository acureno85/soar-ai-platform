#!/usr/bin/env python3
"""
GRC API - Endpoint para consultas de cumplimiento
Integra con el flujo SOAR existente
"""

from flask import Flask, request, jsonify
import requests
from datetime import datetime

app = Flask(__name__)

QDRANT_URL = "http://localhost:6333"
OLLAMA_URL = "http://localhost:11434"
COLLECTION_NAME = "grc_controls"
EMBED_MODEL = "nomic-embed-text"
LLM_MODEL = "llama3.2:3b"


def get_embedding(text: str) -> list:
    """Genera embedding usando Ollama"""
    response = requests.post(
        f"{OLLAMA_URL}/api/embeddings",
        json={"model": EMBED_MODEL, "prompt": text}
    )
    return response.json()["embedding"]


def search_grc_controls(query: str, limit: int = 5) -> list:
    """Busca controles GRC relevantes"""
    embedding = get_embedding(query)
    
    response = requests.post(
        f"{QDRANT_URL}/collections/{COLLECTION_NAME}/points/search",
        json={
            "vector": embedding,
            "limit": limit,
            "with_payload": True
        }
    )
    
    return response.json().get("result", [])


def generate_compliance_report(alert_data: dict, controls: list) -> str:
    """Genera reporte de cumplimiento usando LLM"""
    
    controls_text = "\n".join([
        f"- {c['payload']['id']}: {c['payload']['name']} (Relevancia: {c['score']:.2f})"
        for c in controls
    ])
    
    prompt = f"""Eres un experto en GRC (Governance, Risk & Compliance).

Analiza esta alerta de seguridad y su relación con los controles de cumplimiento identificados.

## ALERTA DE SEGURIDAD:
- Regla: {alert_data.get('rule_description', 'N/A')}
- Nivel: {alert_data.get('rule_level', 'N/A')}
- Agente: {alert_data.get('agent_name', 'N/A')}
- MITRE: {alert_data.get('mitre_id', 'N/A')}

## CONTROLES DE CUMPLIMIENTO RELACIONADOS:
{controls_text}

## GENERA UN REPORTE CON:
1. **Impacto en Cumplimiento**: Qué frameworks se ven afectados
2. **Controles Relevantes**: Top 3 controles más importantes
3. **Riesgo de No-Cumplimiento**: Consecuencias potenciales
4. **Acciones Recomendadas**: Para mantener/restaurar cumplimiento
5. **Evidencia Requerida**: Documentación necesaria

Responde en formato estructurado y conciso.
"""

    response = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": LLM_MODEL,
            "prompt": prompt,
            "stream": False
        }
    )
    
    return response.json().get("response", "Error generando reporte")


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "GRC API"})


@app.route('/api/grc/search', methods=['POST'])
def search_controls():
    """
    Busca controles de cumplimiento por consulta
    
    Body: {"query": "brute force attack", "limit": 5}
    """
    data = request.json
    query = data.get('query', '')
    limit = data.get('limit', 5)
    
    if not query:
        return jsonify({"error": "Query requerida"}), 400
    
    results = search_grc_controls(query, limit)
    
    # Formatear resultados
    controls = []
    for r in results:
        control = r['payload']
        controls.append({
            "id": control['id'],
            "framework": control['framework'],
            "name": control['name'],
            "description": control['description'],
            "relevance_score": round(r['score'] * 100, 2),
            "mitre_mapping": control.get('mitre_mapping', []),
            "implementation_guidance": control.get('implementation_guidance', '')
        })
    
    return jsonify({
        "query": query,
        "total_results": len(controls),
        "controls": controls
    })


@app.route('/api/grc/map-alert', methods=['POST'])
def map_alert_to_controls():
    """
    Mapea una alerta de seguridad a controles de cumplimiento
    
    Body: {
        "rule_description": "SSH brute force attack",
        "rule_level": 10,
        "agent_name": "server-01",
        "mitre_id": "T1110",
        "mitre_tactic": "Credential Access"
    }
    """
    alert_data = request.json
    
    if not alert_data:
        return jsonify({"error": "Datos de alerta requeridos"}), 400
    
    # Construir query de búsqueda
    search_query = f"""
    {alert_data.get('rule_description', '')}
    {alert_data.get('mitre_id', '')}
    {alert_data.get('mitre_tactic', '')}
    """
    
    # Buscar controles relacionados
    results = search_grc_controls(search_query, limit=10)
    
    # Separar por framework
    iso_controls = []
    nist_controls = []
    
    for r in results:
        control = r['payload']
        control_info = {
            "id": control['id'],
            "name": control['name'],
            "relevance": round(r['score'] * 100, 2),
            "implementation_guidance": control.get('implementation_guidance', '')
        }
        
        if control['framework'] == "ISO 27001:2022":
            iso_controls.append(control_info)
        else:
            nist_controls.append(control_info)
    
    # Generar reporte con IA
    compliance_report = generate_compliance_report(alert_data, results[:5])
    
    return jsonify({
        "alert": {
            "description": alert_data.get('rule_description'),
            "level": alert_data.get('rule_level'),
            "mitre_id": alert_data.get('mitre_id')
        },
        "compliance_mapping": {
            "iso_27001": iso_controls[:5],
            "nist_800_53": nist_controls[:5]
        },
        "ai_analysis": compliance_report,
        "timestamp": datetime.now().isoformat()
    })


@app.route('/api/grc/gap-analysis', methods=['POST'])
def gap_analysis():
    """
    Realiza análisis de brechas
    
    Body: {
        "implemented_controls": ["ISO-A.5.1", "ISO-A.8.5", "NIST-AC-2"]
    }
    """
    data = request.json
    implemented = set(data.get('implemented_controls', []))
    
    # Obtener todos los controles de la colección
    response = requests.post(
        f"{QDRANT_URL}/collections/{COLLECTION_NAME}/points/scroll",
        json={"limit": 100, "with_payload": True}
    )
    
    all_controls = response.json().get("result", {}).get("points", [])
    all_control_ids = set([c['payload']['id'] for c in all_controls])
    
    # Calcular gaps
    gaps = all_control_ids - implemented
    covered = all_control_ids & implemented
    
    # Categorizar gaps por prioridad
    critical_gaps = [g for g in gaps if any(x in g for x in ['AC-', 'IA-', 'A.8.5', 'A.5.15'])]
    
    return jsonify({
        "summary": {
            "total_controls": len(all_control_ids),
            "implemented": len(covered),
            "gaps": len(gaps),
            "compliance_percentage": round(len(covered) / len(all_control_ids) * 100, 2) if all_control_ids else 0
        },
        "implemented_controls": list(covered),
        "missing_controls": list(gaps),
        "critical_gaps": critical_gaps[:10],
        "recommendation": "Priorizar implementación de controles de Access Control e Identity Management"
    })


if __name__ == '__main__':
    print("=" * 60)
    print("🏛️  GRC API Server - ISO 27001 & NIST 800-53")
    print("=" * 60)
    print(f"⏰ Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("📍 Endpoints disponibles:")
    print("   GET  /health              - Health check")
    print("   POST /api/grc/search      - Buscar controles")
    print("   POST /api/grc/map-alert   - Mapear alerta → controles")
    print("   POST /api/grc/gap-analysis - Análisis de brechas")
    print()
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
