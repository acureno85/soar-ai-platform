🛡️  SOAR-AI Platform
Plataforma de Orquestación de Seguridad con Inteligencia Artificial

License: MIT
Docker
Wazuh
n8n
Ollama
🎯 Descripción

Plataforma SOAR (Security Orchestration, Automation and Response) que integra detección de amenazas con análisis automatizado mediante Inteligencia Artificial.

Características principales:

    Detección de amenazas en tiempo real
    Análisis automático con IA local (sin enviar datos a la nube)
    Mapeo automático a MITRE ATT&CK
    Cumplimiento normativo (GDPR, HIPAA, NIST, PCI-DSS)

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOAR-AI PLATFORM                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────────────────┐    │
│   │  Wazuh   │───▶│   n8n    │───▶│  Ollama  │───▶│  Análisis con IA   │    │
│   │   SIEM   │    │   SOAR   │    │   LLM    │    │  (SOC + GRC)       │    │
│   └──────────┘    └────┬─────┘    └──────────┘    └────────────────────┘    │
│                        │                                                    │
│                        │          ┌──────────┐                              │
│                        └─────────▶│  Qdrant  │◀─── MITRE ATT&CK (100)       │
│                                   │ VectorDB │◀─── GRC Controls (80)        │
│                                   └──────────┘                              │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                        GRC API (Flask :5000)                        │   │
│   │  • /api/grc/search      - Buscar controles                          │   │
│   │  • /api/grc/map-alert   - Mapear alertas a cumplimiento             │   │
│   │  • /api/grc/gap-analysis - Análisis de brechas                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

✨ Características

    ✅ Detección de amenazas en tiempo real (Wazuh SIEM)
    ✅ Análisis automático de alertas con IA (Ollama)
    ✅ Automatización y orquestación de respuestas (n8n)
    ✅ Mapeo automático de técnicas y tácticas MITRE ATT&CK
    ✅ 100% Open Source sin costos de licencias
    ✅ Despliegue con Docker en minutos
    ✅ Privacidad - IA local, datos nunca salen de tu infraestructura

📊 Evidencia de Funcionamiento
Detección de Ataque Brute Force

Brute Force Detection
Análisis de IA

AI Analysis
Workflow n8n

n8n Workflow

Ver más detalles en evidence/DEMO_RESULTS.md
🚀 Instalación Rápida

Prerrequisitos

text

Docker y Docker Compose
Python 3.11+
8GB RAM mínimo (16GB recomendado)
20GB espacio en disco

Pasos
1. Clonar repositorio

git clone https://github.com/acureno85/soar-ai-platform.git
cd soar-ai-platform/docker
2. Generar certificados

docker-compose -f generate-indexer-certs.yml run --rm generator
3. Iniciar servicios

docker-compose up -d
docker-compose -f docker-compose.soar.yml up -d
4. Descargar modelo de IA

docker exec -it soar_ollama ollama pull llama3.2:3b
5. Verificar servicios

docker ps
6. Indexar bases de conocimiento

bash
MITRE ATT&CK

python3 scripts/index_mitre.py
GRC Controls

python3 grc/scripts/index_grc_controls.py
7. Iniciar API GRC

bash

python3 grc/scripts/grc_api.py
8. Importar workflow en n8n

text

Acceder a http://localhost:5678
Importar docs/workflows/soar-grc-workflow.json

📦 Componentes
Stack Tecnológico
| Componente | Versión | Puerto | Función |
|------------|---------|--------|---------|
| Wazuh | 4.9.2 | 443, 9200 | SIEM - Detección de amenazas |
| n8n | Latest | 5678 | SOAR - Orquestación |
| Ollama | Latest | 11434 | LLM - Análisis con IA |
| Qdrant | Latest | 6333 | Vector DB - RAG |
| GRC API | 1.0 | 5000 | API de cumplimiento |

Bases de Conocimiento
| Colección | Registros | Descripción |
|-----------|-----------|-------------|
| mitre_attack | 100 | Técnicas MITRE ATT&CK |
| grc_controls | 80 | Controles ISO 27001 + NIST 800-53 |

🔄 Flujo de Trabajo

    [Alerta Wazuh]
    → Detecta intento de brute force SSH (Nivel 10)

    [n8n Webhook]
    → Recibe alerta automáticamente

    [Ollama IA - Análisis SOC]
    → Clasifica severidad
    → Identifica técnica MITRE
    → Genera recomendaciones

    [GRC API - Mapeo Cumplimiento]
    → Busca controles ISO 27001 relevantes
    → Busca controles NIST 800-53 relevantes
    → Genera análisis de impacto

    [Reporte Integrado]
    → Combina análisis SOC + GRC
    → Timestamp y trazabilidad

📊 Ejemplo de Reporte
{
"report": {
"timestamp": "2026-01-05T12:47:00.396-06:00",
"alert": {
"rule": {
"description": "sshd: Attempt to login using a non-existent user",
"level": 10
}
},
"ai_soc_analysis": "SEVERIDAD: Alta\nTÉCNICA MITRE: T1110 (Brute Force)...",
"grc_compliance": {
"iso_27001": [
{"id": "ISO-A.5.17", "name": "Authentication information", "relevance": 53.23},
{"id": "ISO-A.8.5", "name": "Secure authentication", "relevance": 52.87}
],
"nist_800_53": [
{"id": "NIST-IA-2", "name": "Identification and Authentication", "relevance": 62.46},
{"id": "NIST-AC-7", "name": "Unsuccessful Logon Attempts", "relevance": 54.46}
]
}
}
}

🗂️  Estructura del Proyecto
soar-ai-platform/
├── docker-compose.yml # Configuración de servicios
├── README.md # Este archivo
├── grc/
│ ├── scripts/
│ │ ├── index_grc_controls.py # Indexador de controles
│ │ └── grc_api.py # API Flask
│ ├── data/ # Datos adicionales
│ └── reports/ # Reportes generados
├── scripts/
│ └── index_mitre.py # Indexador MITRE ATT&CK
├── docs/
│ ├── workflows/ # Workflows n8n exportados
│ └── images/ # Diagramas y screenshots
└── config/
└── wazuh/ # Configuración Wazuh

🔌 API Endpoints
GRC API (Puerto 5000)
Método Endpoint Descripción
GET /health Health check
POST /api/grc/search Buscar controles por texto
POST /api/grc/map-alert Mapear alerta a controles
POST /api/grc/gap-analysis Análisis de brechas

Ejemplo de uso
curl -X POST http://localhost:5000/api/grc/map-alert
-H "Content-Type: application/json"
-d '{
"rule_description": "SSH brute force attack",
"rule_level": 10,
"mitre_id": "T1110"
}'

🛡️  Controles de Cumplimiento Soportados
ISO 27001:2022 (47 controles)

text

A.5 - Controles Organizacionales
A.6 - Controles de Personas
A.7 - Controles Físicos
A.8 - Controles Tecnológicos

NIST 800-53 Rev5 (33 controles)

text

AC - Access Control
AU - Audit and Accountability
AT - Awareness and Training
CA - Assessment and Authorization
CM - Configuration Management
IA - Identification and Authentication
IR - Incident Response
RA - Risk Assessment
SC - System and Communications Protection
SI - System and Information Integrity

🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

text

Fork el repositorio
Crea una rama (git checkout -b feature/nueva-funcionalidad)
Commit cambios (git commit -am 'Agrega nueva funcionalidad')
Push a la rama (git push origin feature/nueva-funcionalidad)
Abre un Pull Request

🔗 URLs de Acceso
| Servicio | URL | Credenciales |
|----------|-----|--------------|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword |
| n8n SOAR | http://localhost:5678 | Crear cuenta |
| Qdrant API | http://localhost:6333 | - |
| Ollama API | http://localhost:11434 | - |
| GRC API | http://localhost:5000 | - |

📖 Documentación

text

Guía de Instalación
Configuración
Uso y Ejemplos
API Reference
Evidencias de Pruebas

🔧 Stack Tecnológico
Componente Tecnología Función
SIEM Wazuh 4.9.2 Detección de amenazas
SOAR n8n Orquestación y automatización
LLM Ollama (Llama 3.2) Análisis con IA
Vector DB Qdrant Base de conocimiento (RAG)
Contenedores Docker Despliegue

📜 Licencia
MIT License - Ver LICENSE

🏢 Versión Enterprise
Para funcionalidades avanzadas (RAG, Threat Intelligence automatizado, GRC), contactar: [abraham.cureno@gmail.com]

text

RAG con Threat Intelligence - Actualización automática de amenazas
Integraciones Enterprise - Splunk, ServiceNow, Jira
GRC Automatizado - ISO 27001, NIST, SOC2
Soporte dedicado

👤 Autor
Abraham Cureno

text

GitHub: @acureno85
LinkedIn: [https://www.linkedin.com/in/abrahamcureno/]

🙏 Agradecimientos

text

Wazuh - SIEM Open Source
n8n - Automatización de workflows
Ollama - LLM local
Qdrant - Vector Database
MITRE ATT&CK - Framework de amenazas
