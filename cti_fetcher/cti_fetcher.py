#!/usr/bin/env python3
"""
=============================================================================
CYBER THREAT INTELLIGENCE (CTI) FETCHER
=============================================================================
Servicio que descarga automáticamente feeds de inteligencia de amenazas
y los almacena en Qdrant para consultas RAG.

Feeds incluidos:
- MITRE ATT&CK (TTPs tradicionales)
- MITRE ATLAS (Ataques contra IA/ML)
- NVD/CVE (Vulnerabilidades)
- Abuse.ch (Malware feeds)

Autor: Abraham Cureno - SOAR-AI Platform
=============================================================================
"""

import os
import json
import time
import hashlib
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# Configuración
QDRANT_HOST = os.getenv('QDRANT_HOST', 'localhost')
QDRANT_PORT = int(os.getenv('QDRANT_PORT', 6333))
OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'localhost')
OLLAMA_PORT = int(os.getenv('OLLAMA_PORT', 11434))
UPDATE_INTERVAL = int(os.getenv('UPDATE_INTERVAL_HOURS', 6)) * 3600
EMBEDDING_MODEL = 'nomic-embed-text'
COLLECTION_NAME = 'threat_intelligence'
VECTOR_SIZE = 768

print("=" * 60)
print("CTI FETCHER - SOAR-AI Platform")
print("=" * 60)

class QdrantClient:
    """Cliente para interactuar con Qdrant"""
    
    def __init__(self, host: str, port: int):
        self.base_url = f"http://{host}:{port}"
    
    def health_check(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"[ERROR] Qdrant health check failed: {e}")
            return False
    
    def create_collection(self, name: str, vector_size: int) -> bool:
        try:
            # Verificar si existe
            response = requests.get(f"{self.base_url}/collections/{name}")
            if response.status_code == 200:
                print(f"[OK] Collection '{name}' already exists")
                return True
            
            # Crear colección
            payload = {
                "vectors": {
                    "size": vector_size,
                    "distance": "Cosine"
                }
            }
            response = requests.put(
                f"{self.base_url}/collections/{name}",
                json=payload
            )
            if response.status_code in [200, 201]:
                print(f"[OK] Collection '{name}' created")
                return True
            return False
        except Exception as e:
            print(f"[ERROR] Creating collection: {e}")
            return False
    
    def upsert_points(self, collection: str, points: List[Dict]) -> bool:
        try:
            payload = {"points": points}
            response = requests.put(
                f"{self.base_url}/collections/{collection}/points",
                json=payload
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[ERROR] Upserting points: {e}")
            return False


class OllamaClient:
    """Cliente para interactuar con Ollama"""
    
    def __init__(self, host: str, port: int):
        self.base_url = f"http://{host}:{port}"
    
    def health_check(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"[ERROR] Ollama health check failed: {e}")
            return False
    
    def get_embedding(self, text: str) -> Optional[List[float]]:
        try:
            response = requests.post(
                f"{self.base_url}/api/embeddings",
                json={"model": EMBEDDING_MODEL, "prompt": text[:2000]},
                timeout=60
            )
            if response.status_code == 200:
                return response.json().get('embedding')
            return None
        except Exception as e:
            print(f"[ERROR] Getting embedding: {e}")
            return None

def fetch_mitre_attack() -> List[Dict]:

    """Descarga MITRE ATT&CK"""
    docs = []
    try:
        print("[INFO] Fetching MITRE ATT&CK...")
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        response = requests.get(url, timeout=120)
        data = response.json()
        
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                technique_id = ''
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id', '')
                        break
                
                name = obj.get('name', 'Unknown')
                description = obj.get('description', '')[:500]
                tactics = [p.get('phase_name', '') for p in obj.get('kill_chain_phases', []) 
                          if p.get('kill_chain_name') == 'mitre-attack']
                
                content = f"MITRE ATT&CK {technique_id}: {name}. Tactics: {', '.join(tactics)}. {description}"
                
                docs.append({
                    'id': hashlib.md5(f"attack_{technique_id}".encode()).hexdigest(),
                    'source': 'mitre_attack',
                    'title': f"{technique_id}: {name}",
                    'content': content,
                    'metadata': {'technique_id': technique_id, 'tactics': tactics}
                })
        
        print(f"[OK] Fetched {len(docs)} ATT&CK techniques")
    except Exception as e:
        print(f"[ERROR] Fetching MITRE ATT&CK: {e}")
    return docs


def fetch_mitre_atlas() -> List[Dict]:
    """Descarga MITRE ATLAS (ataques contra IA)"""
    docs = []
    try:
        print("[INFO] Fetching MITRE ATLAS...")
        url = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/schemas/atlas-attack-enterprise/atlas-attack-enterprise.json"
        response = requests.get(url, timeout=120)
        data = response.json()
        
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                name = obj.get('name', '')
                description = obj.get('description', '')[:500]
                
                content = f"MITRE ATLAS AI Attack {technique_id}: {name}. This technique targets AI/ML systems. {description}"
                
                docs.append({
                    'id': hashlib.md5(f"atlas_{technique_id}".encode()).hexdigest(),
                    'source': 'mitre_atlas',
                    'title': f"ATLAS {technique_id}: {name}",
                    'content': content,
                    'metadata': {'technique_id': technique_id, 'ai_specific': True}
                })
        
        print(f"[OK] Fetched {len(docs)} ATLAS techniques")
    except Exception as e:
        print(f"[ERROR] Fetching MITRE ATLAS: {e}")
    return docs

def fetch_nvd_cves() -> List[Dict]:

    """Descarga CVEs recientes del NVD"""
    docs = []
    try:
        print("[INFO] Fetching NVD CVEs (last 7 days)...")
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date.strftime('%Y-%m-%dT00:00:00.000')}&pubEndDate={end_date.strftime('%Y-%m-%dT23:59:59.999')}"
        
        response = requests.get(url, timeout=120)
        data = response.json()
        
        for vuln in data.get('vulnerabilities', [])[:50]:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', '')
            
            description = ''
            for desc in cve.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')[:500]
                    break
            
            cvss_score = 'N/A'
            severity = 'UNKNOWN'
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            content = f"CVE Vulnerability {cve_id}. CVSS: {cvss_score} ({severity}). {description}"
            
            docs.append({
                'id': hashlib.md5(f"cve_{cve_id}".encode()).hexdigest(),
                'source': 'nvd',
                'title': f"{cve_id} - {severity}",
                'content': content,
                'metadata': {'cve_id': cve_id, 'cvss': cvss_score, 'severity': severity}
            })
        
        print(f"[OK] Fetched {len(docs)} CVEs")
    except Exception as e:
        print(f"[ERROR] Fetching NVD CVEs: {e}")
    return docs


def fetch_abuse_ch() -> List[Dict]:
    """Descarga malware samples de Abuse.ch"""
    docs = []
    try:
        print("[INFO] Fetching Abuse.ch malware...")
        url = "https://bazaar.abuse.ch/export/json/recent/"
        response = requests.get(url, timeout=60)
        data = response.json()
        
        count = 0
        for sample in data.values():
            if isinstance(sample, dict) and count < 30:
                sha256 = sample.get('sha256_hash', '')
                signature = sample.get('signature', 'Unknown')
                file_type = sample.get('file_type', 'Unknown')
                tags = sample.get('tags', [])
                
                content = f"Malware {signature} ({file_type}). SHA256: {sha256}. Tags: {', '.join(tags) if tags else 'None'}. Block this hash at endpoint level."
                
                docs.append({
                    'id': hashlib.md5(f"malware_{sha256}".encode()).hexdigest(),
                    'source': 'abuse_ch',
                    'title': f"Malware: {signature}",
                    'content': content,
                    'metadata': {'sha256': sha256, 'signature': signature, 'file_type': file_type}
                })
                count += 1
        
        print(f"[OK] Fetched {len(docs)} malware samples")
    except Exception as e:
        print(f"[ERROR] Fetching Abuse.ch: {e}")
    return docs

def process_and_store(qdrant: QdrantClient, ollama: OllamaClient, documents: List[Dict]) -> int:

    """Procesa documentos y los almacena en Qdrant"""
    stored = 0
    points = []
    
    for i, doc in enumerate(documents):
        embedding = ollama.get_embedding(doc['content'])
        if embedding:
            points.append({
                "id": doc['id'],
                "vector": embedding,
                "payload": {
                    "source": doc['source'],
                    "title": doc['title'],
                    "content": doc['content'],
                    "metadata": doc['metadata'],
                    "timestamp": datetime.utcnow().isoformat()
                }
            })
            
            # Insertar en lotes de 20
            if len(points) >= 20:
                if qdrant.upsert_points(COLLECTION_NAME, points):
                    stored += len(points)
                    print(f"[INFO] Stored {stored}/{len(documents)} documents...")
                points = []
    
    # Insertar restantes
    if points:
        if qdrant.upsert_points(COLLECTION_NAME, points):
            stored += len(points)
    
    return stored


def run_update_cycle(qdrant: QdrantClient, ollama: OllamaClient):
    """Ejecuta un ciclo de actualización"""
    print("\n" + "=" * 60)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting CTI update cycle")
    print("=" * 60)
    
    all_docs = []
    all_docs.extend(fetch_mitre_attack())
    all_docs.extend(fetch_mitre_atlas())
    all_docs.extend(fetch_nvd_cves())
    all_docs.extend(fetch_abuse_ch())
    
    print(f"\n[INFO] Total documents to process: {len(all_docs)}")
    
    stored = process_and_store(qdrant, ollama, all_docs)
    
    print(f"\n[OK] Successfully stored {stored} documents in Qdrant")
    print("=" * 60)


def main():
    """Función principal"""
    print(f"[INFO] Connecting to Qdrant at {QDRANT_HOST}:{QDRANT_PORT}")
    print(f"[INFO] Connecting to Ollama at {OLLAMA_HOST}:{OLLAMA_PORT}")
    
    qdrant = QdrantClient(QDRANT_HOST, QDRANT_PORT)
    ollama = OllamaClient(OLLAMA_HOST, OLLAMA_PORT)
    
    # Esperar servicios
    print("[INFO] Waiting for services...")
    for _ in range(30):
        if qdrant.health_check() and ollama.health_check():
            print("[OK] All services ready!")
            break
        time.sleep(5)
    else:
        print("[ERROR] Services not available. Exiting.")
        return
    
    # Crear colección
    qdrant.create_collection(COLLECTION_NAME, VECTOR_SIZE)
    
    # Primer ciclo
    run_update_cycle(qdrant, ollama)
    
    # Loop de actualización
    while True:
        print(f"\n[INFO] Next update in {UPDATE_INTERVAL // 3600} hours...")
        time.sleep(UPDATE_INTERVAL)
        run_update_cycle(qdrant, ollama)


if __name__ == "__main__":
    main()
