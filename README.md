<p align="center">
  <img src="docs/images/logo.png" alt="SOAR-AI Platform" width="200"/>
</p>

<h1 align="center">🛡️ SOAR-AI Platform</h1>

<p align="center">
  <strong>Plataforma de Orquestación de Seguridad con Inteligencia Artificial</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="#"><img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white" alt="Docker"></a>
  <a href="#"><img src="https://img.shields.io/badge/Wazuh-4.9.2-3CBCBC?logo=wazuh&logoColor=white" alt="Wazuh"></a>
  <a href="#"><img src="https://img.shields.io/badge/n8n-Latest-EA4B71?logo=n8n&logoColor=white" alt="n8n"></a>
  <a href="#"><img src="https://img.shields.io/badge/Ollama-Local_AI-000000?logo=ollama&logoColor=white" alt="Ollama"></a>
  <a href="#"><img src="https://img.shields.io/badge/100%25-Open_Source-brightgreen" alt="Open Source"></a>
</p>

<p align="center">
  <a href="#-características">Características</a> •
  <a href="#-instalación-rápida">Instalación</a> •
  <a href="#-arquitectura">Arquitectura</a> •
  <a href="#-documentación">Documentación</a> •
  <a href="#-licencia">Licencia</a>
</p>

---

## 🎯 Descripción

**SOAR-AI Platform** es una solución integral de seguridad que combina detección de amenazas en tiempo real con análisis automatizado mediante Inteligencia Artificial local. Diseñada para equipos de seguridad que buscan automatizar su respuesta a incidentes mientras mantienen el control total de sus datos.

### ¿Por qué SOAR-AI?

| Problema | Solución SOAR-AI |
|----------|------------------|
| Alertas sin contexto | Análisis automático con IA que clasifica y prioriza |
| Mapeo manual a frameworks | Mapeo automático a MITRE ATT&CK |
| Cumplimiento fragmentado | Integración GRC (ISO 27001, NIST 800-53) |
| Dependencia de servicios cloud | IA 100% local - tus datos nunca salen |
| Costos de licencias elevados | 100% Open Source |

---

## ✨ Características

<table>
<tr>
<td width="50%">

### 🔍 Detección & Análisis
- ✅ Detección de amenazas en tiempo real
- ✅ Análisis automático con IA local (Ollama)
- ✅ Clasificación de severidad inteligente
- ✅ Mapeo automático MITRE ATT&CK

</td>
<td width="50%">

### 📋 Cumplimiento & GRC
- ✅ 47 controles ISO 27001:2022
- ✅ 33 controles NIST 800-53 Rev5
- ✅ Análisis de brechas automatizado
- ✅ Reportes de cumplimiento

</td>
</tr>
<tr>
<td width="50%">

### ⚡ Automatización
- ✅ Orquestación con n8n (visual)
- ✅ Workflows personalizables
- ✅ Respuesta automática a incidentes
- ✅ Notificaciones multi-canal

</td>
<td width="50%">

### 🔒 Privacidad & Control
- ✅ IA ejecutándose localmente
- ✅ Datos nunca salen de tu red
- ✅ Sin dependencias cloud
- ✅ Control total del stack

</td>
</tr>
</table>

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOAR-AI PLATFORM                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────────────────┐   │
│   │  Wazuh   │───▶│   n8n    │───▶│  Ollama  │───▶│  Análisis con IA   │   │
│   │   SIEM   │    │   SOAR   │    │   LLM    │    │  (SOC + GRC)       │   │
│   └──────────┘    └────┬─────┘    └──────────┘    └────────────────────┘   │
│                        │                                                    │
│                        │          ┌──────────┐                              │
│                        └─────────▶│  Qdrant  │◀─── MITRE ATT&CK (100)      │
│                                   │ VectorDB │◀─── GRC Controls (80)       │
│                                   └──────────┘                              │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                        GRC API (Flask :5000)                        │  │
│   │  • /api/grc/search      - Buscar controles                          │  │
│   │  • /api/grc/map-alert   - Mapear alertas a cumplimiento             │  │
│   │  • /api/grc/gap-analysis - Análisis de brechas                      │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Stack Tecnológico

| Componente | Versión | Puerto | Función |
|:-----------|:-------:|:------:|:--------|
| **Wazuh** | 4.9.2 | 443, 9200 | SIEM - Detección de amenazas |
| **n8n** | Latest | 5678 | SOAR - Orquestación |
| **Ollama** | Latest | 11434 | LLM - Análisis con IA |
| **Qdrant** | Latest | 6333 | Vector DB - RAG |
| **GRC API** | 1.0 | 5000 | API de cumplimiento |

### Bases de Conocimiento

| Colección | Registros | Descripción |
|:----------|:---------:|:------------|
| `mitre_attack` | 100 | Técnicas MITRE ATT&CK |
| `grc_controls` | 80 | Controles ISO 27001 + NIST 800-53 |

---

## 🚀 Instalación Rápida

### Prerrequisitos

- Docker y Docker Compose
- Python 3.11+
- 8GB RAM mínimo (16GB recomendado)
- 20GB espacio en disco

### Pasos de Instalación

```bash
# 1. Clonar repositorio
git clone https://github.com/acureno85/soar-ai-platform.git
cd soar-ai-platform/docker

# 2. Generar certificados
docker-compose -f generate-indexer-certs.yml run --rm generator

# 3. Iniciar servicios principales
docker-compose up -d

# 4. Iniciar servicios SOAR
docker-compose -f docker-compose.soar.yml up -d

# 5. Descargar modelo de IA
docker exec -it soar_ollama ollama pull llama3.2:3b

# 6. Verificar servicios
docker ps
```

### Configuración de Bases de Conocimiento

```bash
# Indexar MITRE ATT&CK
python3 scripts/index_mitre.py

# Indexar controles GRC
python3 grc/scripts/index_grc_controls.py

# Iniciar API GRC
python3 grc/scripts/grc_api.py
```

### Importar Workflow en n8n

1. Acceder a `http://localhost:5678`
2. Crear cuenta de usuario
3. Importar `docs/workflows/soar-grc-workflow.json`

---

## 🔄 Flujo de Trabajo

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  1. DETECCIÓN   │────▶│  2. ANÁLISIS    │────▶│  3. RESPUESTA   │
│                 │     │                 │     │                 │
│  Wazuh detecta  │     │  IA clasifica   │     │  Acciones       │
│  amenaza SSH    │     │  severidad y    │     │  automáticas    │
│  brute force    │     │  técnica MITRE  │     │  + notificación │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │  4. CUMPLIMIENTO (GRC)  │
                  │                         │
                  │  Mapeo a ISO 27001 y    │
                  │  NIST 800-53 + reporte  │
                  └─────────────────────────┘
```

---

## 📊 Ejemplo de Reporte

<details>
<summary><b>Ver ejemplo de reporte JSON completo</b></summary>

```json
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
```

</details>

---

## 🔌 API Endpoints

### GRC API (Puerto 5000)

| Método | Endpoint | Descripción |
|:------:|:---------|:------------|
| `GET` | `/health` | Health check |
| `POST` | `/api/grc/search` | Buscar controles por texto |
| `POST` | `/api/grc/map-alert` | Mapear alerta a controles |
| `POST` | `/api/grc/gap-analysis` | Análisis de brechas |

### Ejemplo de Uso

```bash
curl -X POST http://localhost:5000/api/grc/map-alert \
  -H "Content-Type: application/json" \
  -d '{
    "rule_description": "SSH brute force attack",
    "rule_level": 10,
    "mitre_id": "T1110"
  }'
```

---

## 🛡️ Controles de Cumplimiento

<details>
<summary><b>ISO 27001:2022 (47 controles)</b></summary>

- **A.5** - Controles Organizacionales
- **A.6** - Controles de Personas
- **A.7** - Controles Físicos
- **A.8** - Controles Tecnológicos

</details>

<details>
<summary><b>NIST 800-53 Rev5 (33 controles)</b></summary>

- **AC** - Access Control
- **AU** - Audit and Accountability
- **AT** - Awareness and Training
- **CA** - Assessment and Authorization
- **CM** - Configuration Management
- **IA** - Identification and Authentication
- **IR** - Incident Response
- **RA** - Risk Assessment
- **SC** - System and Communications Protection
- **SI** - System and Information Integrity

</details>

---

## 🔗 URLs de Acceso

| Servicio | URL | Credenciales |
|:---------|:----|:-------------|
| Wazuh Dashboard | `https://localhost:443` | admin / SecretPassword |
| n8n SOAR | `http://localhost:5678` | Crear cuenta |
| Qdrant API | `http://localhost:6333` | - |
| Ollama API | `http://localhost:11434` | - |
| GRC API | `http://localhost:5000` | - |

---

## 🗂️ Estructura del Proyecto

```
soar-ai-platform/
├── 📁 docker/
│   ├── docker-compose.yml
│   └── docker-compose.soar.yml
├── 📁 grc/
│   ├── 📁 scripts/
│   │   ├── index_grc_controls.py
│   │   └── grc_api.py
│   ├── 📁 data/
│   └── 📁 reports/
├── 📁 scripts/
│   └── index_mitre.py
├── 📁 docs/
│   ├── 📁 workflows/
│   └── 📁 images/
├── 📁 config/
│   └── 📁 wazuh/
├── 📄 README.md
└── 📄 LICENSE
```

---

## 📸 Evidencias

<details>
<summary><b>Detección de Ataque Brute Force</b></summary>

![Brute Force Detection](docs/images/brute-force-detection.png)

</details>

<details>
<summary><b>Análisis de IA</b></summary>

![AI Analysis](docs/images/ai-analysis.png)

</details>

<details>
<summary><b>Workflow n8n</b></summary>

![n8n Workflow](docs/images/n8n-workflow.png)

</details>

> 📄 Ver más detalles en [evidence/DEMO_RESULTS.md](evidence/DEMO_RESULTS.md)

---

## 🏢 Versión Enterprise

Para funcionalidades avanzadas, contactar: **abraham.cureno@gmail.com**

| Característica | Community | Enterprise |
|:---------------|:--------:|:----------:|
| Detección básica | ✅ | ✅ |
| Análisis IA | ✅ | ✅ |
| MITRE ATT&CK | ✅ | ✅ |
| GRC Básico | ✅ | ✅ |
| RAG con Threat Intelligence | ❌ | ✅ |
| Integraciones (Splunk, ServiceNow) | ❌ | ✅ |
| Soporte dedicado | ❌ | ✅ |

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agrega nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

---

## 📜 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

---

## 👤 Autor

<p align="center">
  <b>Abraham Cureno</b><br>
  Security Engineer | SOAR Specialist
</p>

<p align="center">
  <a href="https://github.com/acureno85"><img src="https://img.shields.io/badge/GitHub-acureno85-181717?style=flat&logo=github" alt="GitHub"></a>
  <a href="https://www.linkedin.com/in/abrahamcureno/"><img src="https://img.shields.io/badge/LinkedIn-abrahamcureno-0A66C2?style=flat&logo=linkedin" alt="LinkedIn"></a>
  <a href="mailto:abraham.cureno@gmail.com"><img src="https://img.shields.io/badge/Email-abraham.cureno@gmail.com-EA4335?style=flat&logo=gmail" alt="Email"></a>
</p>

---

## 🙏 Agradecimientos

- [Wazuh](https://wazuh.com/) - SIEM Open Source
- [n8n](https://n8n.io/) - Automatización de workflows
- [Ollama](https://ollama.ai/) - LLM local
- [Qdrant](https://qdrant.tech/) - Vector Database
- [MITRE ATT&CK](https://attack.mitre.org/) - Framework de amenazas

---

<p align="center">
  <b>🛡️ Detecta. Analiza. Responde. Automáticamente. 🛡️</b>
</p>

<p align="center">
  ⭐ Si este proyecto te resulta útil, considera darle una estrella en GitHub ⭐
</p>
