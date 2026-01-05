#!/usr/bin/env python3
"""
GRC Controls Indexer - ISO 27001:2022 & NIST 800-53 Rev5
Indexa controles de cumplimiento en Qdrant para RAG
"""

import requests
import json
from datetime import datetime

QDRANT_URL = "http://localhost:6333"
OLLAMA_URL = "http://localhost:11434"
COLLECTION_NAME = "grc_controls"
EMBED_MODEL = "nomic-embed-text"

# ═══════════════════════════════════════════════════════════════
# ISO 27001:2022 - 93 Controles (4 categorías)
# ═══════════════════════════════════════════════════════════════

ISO_27001_CONTROLS = [
    # ─────────────────────────────────────────────────────────────
    # A.5 - Controles Organizacionales (37 controles)
    # ─────────────────────────────────────────────────────────────
    {
        "id": "ISO-A.5.1",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Policies for information security",
        "description": "Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals and if significant changes occur.",
        "implementation_guidance": "Establish a hierarchical policy structure with master security policy and supporting topic policies. Review annually or after significant changes.",
        "evidence_required": ["Security policy document", "Approval records", "Communication logs", "Acknowledgment records"],
        "mitre_mapping": ["T1078", "T1136"],
        "nist_mapping": ["PL-1", "PL-2"]
    },
    {
        "id": "ISO-A.5.2",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Information security roles and responsibilities",
        "description": "Information security roles and responsibilities shall be defined and allocated according to the organization needs.",
        "implementation_guidance": "Define RACI matrix for security functions. Assign security champions in each department.",
        "evidence_required": ["RACI matrix", "Job descriptions", "Organization chart"],
        "mitre_mapping": ["T1078"],
        "nist_mapping": ["PS-1", "PS-2"]
    },
    {
        "id": "ISO-A.5.3",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Segregation of duties",
        "description": "Conflicting duties and conflicting areas of responsibility shall be segregated.",
        "implementation_guidance": "Implement separation between development and production. No single person should control all aspects of critical transactions.",
        "evidence_required": ["Access control matrix", "Role definitions", "Process workflows"],
        "mitre_mapping": ["T1078.004"],
        "nist_mapping": ["AC-5"]
    },
    {
        "id": "ISO-A.5.4",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Management responsibilities",
        "description": "Management shall require all personnel to apply information security in accordance with the established information security policy, topic-specific policies and procedures of the organization.",
        "implementation_guidance": "Include security responsibilities in job descriptions and performance reviews.",
        "evidence_required": ["Performance review templates", "Training records", "Security briefings"],
        "mitre_mapping": [],
        "nist_mapping": ["PM-1", "PM-2"]
    },
    {
        "id": "ISO-A.5.5",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Contact with authorities",
        "description": "The organization shall establish and maintain contact with relevant authorities.",
        "implementation_guidance": "Maintain contact list for CERT, law enforcement, regulators. Define escalation procedures.",
        "evidence_required": ["Contact directory", "Communication procedures", "Incident response plan"],
        "mitre_mapping": [],
        "nist_mapping": ["IR-6", "PM-15"]
    },
    {
        "id": "ISO-A.5.6",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Contact with special interest groups",
        "description": "The organization shall establish and maintain contact with special interest groups or other specialist security forums and professional associations.",
        "implementation_guidance": "Join ISACs, security forums, professional associations. Subscribe to threat intelligence feeds.",
        "evidence_required": ["Membership records", "Meeting minutes", "Intelligence subscriptions"],
        "mitre_mapping": [],
        "nist_mapping": ["PM-15", "PM-16"]
    },
    {
        "id": "ISO-A.5.7",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Threat intelligence",
        "description": "Information relating to information security threats shall be collected and analysed to produce threat intelligence.",
        "implementation_guidance": "Implement threat intelligence platform. Correlate with MITRE ATT&CK framework. Feed into SIEM.",
        "evidence_required": ["TI platform logs", "Analysis reports", "MITRE mappings"],
        "mitre_mapping": ["T1595", "T1592"],
        "nist_mapping": ["PM-16", "RA-3", "SI-5"]
    },
    {
        "id": "ISO-A.5.8",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Information security in project management",
        "description": "Information security shall be integrated into project management.",
        "implementation_guidance": "Include security gates in SDLC. Conduct security reviews at each project phase.",
        "evidence_required": ["Project security checklists", "Security gate approvals", "Risk assessments"],
        "mitre_mapping": [],
        "nist_mapping": ["SA-3", "SA-15"]
    },
    {
        "id": "ISO-A.5.15",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Access control",
        "description": "Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.",
        "implementation_guidance": "Implement RBAC/ABAC. Define access control policy. Review access quarterly.",
        "evidence_required": ["Access control policy", "Access reviews", "RBAC documentation"],
        "mitre_mapping": ["T1078", "T1110"],
        "nist_mapping": ["AC-1", "AC-2", "AC-3"]
    },
    {
        "id": "ISO-A.5.16",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Identity management",
        "description": "The full lifecycle of identities shall be managed.",
        "implementation_guidance": "Implement IAM solution. Automate provisioning/deprovisioning. Unique identifiers required.",
        "evidence_required": ["IAM procedures", "Provisioning workflows", "Identity lifecycle documentation"],
        "mitre_mapping": ["T1078", "T1136"],
        "nist_mapping": ["IA-1", "IA-2", "IA-4"]
    },
    {
        "id": "ISO-A.5.17",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Authentication information",
        "description": "Allocation and management of authentication information shall be controlled by a management process, including advising personnel on appropriate handling of authentication information.",
        "implementation_guidance": "Implement password policy. Consider MFA. Secure credential storage.",
        "evidence_required": ["Password policy", "MFA deployment records", "User awareness materials"],
        "mitre_mapping": ["T1110", "T1552"],
        "nist_mapping": ["IA-5", "IA-6"]
    },
    {
        "id": "ISO-A.5.23",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Information security for use of cloud services",
        "description": "Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization's information security requirements.",
        "implementation_guidance": "Define cloud security policy. Implement CASB. Review shared responsibility model.",
        "evidence_required": ["Cloud security policy", "Provider assessments", "SLAs", "Exit procedures"],
        "mitre_mapping": ["T1078.004", "T1530"],
        "nist_mapping": ["SA-9", "SC-7"]
    },
    {
        "id": "ISO-A.5.24",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Information security incident management planning and preparation",
        "description": "The organization shall plan and prepare for managing information security incidents by defining, establishing and communicating information security incident management processes, roles and responsibilities.",
        "implementation_guidance": "Develop incident response plan. Define severity levels. Establish CSIRT.",
        "evidence_required": ["IR plan", "CSIRT charter", "Communication templates", "Playbooks"],
        "mitre_mapping": [],
        "nist_mapping": ["IR-1", "IR-2", "IR-8"]
    },
    {
        "id": "ISO-A.5.25",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Assessment and decision on information security events",
        "description": "The organization shall assess information security events and decide if they are to be categorized as information security incidents.",
        "implementation_guidance": "Define event triage criteria. Implement SIEM correlation. Document decision process.",
        "evidence_required": ["Triage procedures", "SIEM rules", "Event classification matrix"],
        "mitre_mapping": [],
        "nist_mapping": ["IR-4", "IR-5"]
    },
    {
        "id": "ISO-A.5.26",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Response to information security incidents",
        "description": "Information security incidents shall be responded to in accordance with the documented procedures.",
        "implementation_guidance": "Execute playbooks. Document actions. Preserve evidence. Coordinate response.",
        "evidence_required": ["Incident tickets", "Response logs", "Forensic reports", "Post-incident reviews"],
        "mitre_mapping": [],
        "nist_mapping": ["IR-4", "IR-6"]
    },
    {
        "id": "ISO-A.5.27",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Learning from information security incidents",
        "description": "Knowledge gained from information security incidents shall be used to strengthen and improve the information security controls.",
        "implementation_guidance": "Conduct post-incident reviews. Update playbooks. Share lessons learned.",
        "evidence_required": ["PIR reports", "Updated procedures", "Lessons learned database"],
        "mitre_mapping": [],
        "nist_mapping": ["IR-4", "IR-8"]
    },
    {
        "id": "ISO-A.5.28",
        "framework": "ISO 27001:2022",
        "category": "Organizational",
        "name": "Collection of evidence",
        "description": "The organization shall establish and implement procedures for the identification, collection, acquisition and preservation of evidence related to information security events.",
        "implementation_guidance": "Define chain of custody. Use forensic tools. Train responders on evidence handling.",
        "evidence_required": ["Evidence handling procedures", "Chain of custody forms", "Forensic tool inventory"],
        "mitre_mapping": [],
        "nist_mapping": ["AU-9", "IR-4"]
    },
    # ─────────────────────────────────────────────────────────────
    # A.6 - Controles de Personas (8 controles)
    # ─────────────────────────────────────────────────────────────
    {
        "id": "ISO-A.6.1",
        "framework": "ISO 27001:2022",
        "category": "People",
        "name": "Screening",
        "description": "Background verification checks on all candidates to become personnel shall be carried out prior to joining the organization and on an ongoing basis taking into consideration applicable laws, regulations and ethics and be proportional to the business requirements, the classification of the information to be accessed and the perceived risks.",
        "implementation_guidance": "Define screening levels based on role sensitivity. Conduct criminal, employment, education verification.",
        "evidence_required": ["Background check policy", "Verification records", "Consent forms"],
        "mitre_mapping": ["T1078"],
        "nist_mapping": ["PS-3"]
    },
    {
        "id": "ISO-A.6.2",
        "framework": "ISO 27001:2022",
        "category": "People",
        "name": "Terms and conditions of employment",
        "description": "The employment contractual agreements shall state the personnel's and the organization's responsibilities for information security.",
        "implementation_guidance": "Include confidentiality, acceptable use, IP protection in contracts.",
        "evidence_required": ["Employment contracts", "NDA templates", "Policy acknowledgments"],
        "mitre_mapping": [],
        "nist_mapping": ["PS-4", "PS-6"]
    },
    {
        "id": "ISO-A.6.3",
        "framework": "ISO 27001:2022",
        "category": "People",
        "name": "Information security awareness, education and training",
        "description": "Personnel of the organization and relevant interested parties shall receive appropriate information security awareness, education and training and regular updates of the organization's information security policy, topic-specific policies and procedures, as relevant for their job function.",
        "implementation_guidance": "Implement security awareness program. Conduct phishing simulations. Role-specific training.",
        "evidence_required": ["Training curriculum", "Completion records", "Phishing test results", "Quiz scores"],
        "mitre_mapping": ["T1566", "T1204"],
        "nist_mapping": ["AT-1", "AT-2", "AT-3"]
    },
    {
        "id": "ISO-A.6.4",
        "framework": "ISO 27001:2022",
        "category": "People",
        "name": "Disciplinary process",
        "description": "A disciplinary process shall be formalized and communicated to take actions against personnel and other relevant interested parties who have committed an information security policy violation.",
        "implementation_guidance": "Define graduated sanctions. Align with HR policies. Document all incidents.",
        "evidence_required": ["Disciplinary policy", "Violation records", "Sanction documentation"],
        "mitre_mapping": [],
        "nist_mapping": ["PS-8"]
    },
    {
        "id": "ISO-A.6.5",
        "framework": "ISO 27001:2022",
        "category": "People",
        "name": "Responsibilities after termination or change of employment",
        "description": "Information security responsibilities and duties that remain valid after termination or change of employment shall be defined, enforced and communicated to relevant personnel and other interested parties.",
        "implementation_guidance": "Include post-employment obligations in contracts. Conduct exit interviews. Retain NDA effectiveness.",
        "evidence_required": ["Exit procedures", "NDA duration clauses", "Exit interview records"],
        "mitre_mapping": ["T1078"],
        "nist_mapping": ["PS-4", "PS-5"]
    },
    # ─────────────────────────────────────────────────────────────
    # A.7 - Controles Físicos (14 controles)
    # ─────────────────────────────────────────────────────────────
    {
        "id": "ISO-A.7.1",
        "framework": "ISO 27001:2022",
        "category": "Physical",
        "name": "Physical security perimeters",
        "description": "Security perimeters shall be defined and used to protect areas that contain information and other associated assets.",
        "implementation_guidance": "Define security zones. Implement physical barriers. Control entry points.",
        "evidence_required": ["Floor plans", "Zone definitions", "Physical security assessment"],
        "mitre_mapping": ["T1200"],
        "nist_mapping": ["PE-1", "PE-3"]
    },
    {
        "id": "ISO-A.7.2",
        "framework": "ISO 27001:2022",
        "category": "Physical",
        "name": "Physical entry",
        "description": "Secure areas shall be protected by appropriate entry controls and access points.",
        "implementation_guidance": "Implement badge access. Visitor management. CCTV surveillance.",
        "evidence_required": ["Access logs", "Visitor logs", "CCTV footage retention policy"],
        "mitre_mapping": ["T1200"],
        "nist_mapping": ["PE-2", "PE-3", "PE-6"]
    },
    {
        "id": "ISO-A.7.4",
        "framework": "ISO 27001:2022",
        "category": "Physical",
        "name": "Physical security monitoring",
        "description": "Premises shall be continuously monitored for unauthorized physical access.",
        "implementation_guidance": "Deploy CCTV, motion sensors, alarms. 24/7 monitoring for critical areas.",
        "evidence_required": ["Monitoring procedures", "Alert logs", "Camera placement diagrams"],
        "mitre_mapping": ["T1200"],
        "nist_mapping": ["PE-6"]
    },
    {
        "id": "ISO-A.7.9",
        "framework": "ISO 27001:2022",
        "category": "Physical",
        "name": "Security of assets off-premises",
        "description": "Off-site assets shall be protected.",
        "implementation_guidance": "Encrypt laptops. MDM for mobile devices. Clear desk policy for remote workers.",
        "evidence_required": ["Asset tracking", "Encryption status", "Remote work policy"],
        "mitre_mapping": ["T1052", "T1200"],
        "nist_mapping": ["MP-5", "PE-17"]
    },
    {
        "id": "ISO-A.7.10",
        "framework": "ISO 27001:2022",
        "category": "Physical",
        "name": "Storage media",
        "description": "Storage media shall be managed through their life cycle of acquisition, use, transportation and disposal in accordance with the organization's classification scheme and handling requirements.",
        "implementation_guidance": "Encrypt media. Secure disposal. Track removable media.",
        "evidence_required": ["Media inventory", "Disposal certificates", "Encryption records"],
        "mitre_mapping": ["T1052", "T1091"],
        "nist_mapping": ["MP-1", "MP-2", "MP-6"]
    },
    # ─────────────────────────────────────────────────────────────
    # A.8 - Controles Tecnológicos (34 controles)
    # ─────────────────────────────────────────────────────────────
    {
        "id": "ISO-A.8.1",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "User endpoint devices",
        "description": "Information stored on, processed by or accessible via user endpoint devices shall be protected.",
        "implementation_guidance": "Deploy EDR. Enforce encryption. Implement MDM. Patch management.",
        "evidence_required": ["EDR deployment status", "Encryption compliance", "Patch status reports"],
        "mitre_mapping": ["T1059", "T1053", "T1547"],
        "nist_mapping": ["SC-28", "CM-3", "SI-3"]
    },
    {
        "id": "ISO-A.8.2",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Privileged access rights",
        "description": "The allocation and use of privileged access rights shall be restricted and managed.",
        "implementation_guidance": "Implement PAM. Just-in-time access. Monitor privileged sessions.",
        "evidence_required": ["PAM logs", "Privilege inventory", "Access reviews"],
        "mitre_mapping": ["T1078.002", "T1078.003"],
        "nist_mapping": ["AC-6", "AC-2"]
    },
    {
        "id": "ISO-A.8.3",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Information access restriction",
        "description": "Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.",
        "implementation_guidance": "Implement least privilege. Data classification. DLP controls.",
        "evidence_required": ["Access control lists", "DLP reports", "Classification labels"],
        "mitre_mapping": ["T1078"],
        "nist_mapping": ["AC-3", "AC-4"]
    },
    {
        "id": "ISO-A.8.5",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Secure authentication",
        "description": "Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control.",
        "implementation_guidance": "Implement MFA. Strong password requirements. Certificate-based auth for systems.",
        "evidence_required": ["MFA enrollment", "Authentication logs", "Failed login reports"],
        "mitre_mapping": ["T1110", "T1078"],
        "nist_mapping": ["IA-2", "IA-5", "IA-8"]
    },
    {
        "id": "ISO-A.8.7",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Protection against malware",
        "description": "Protection against malware shall be implemented and supported by appropriate user awareness.",
        "implementation_guidance": "Deploy AV/EDR. Email filtering. User awareness on malware threats.",
        "evidence_required": ["AV deployment status", "Malware detection logs", "Quarantine reports"],
        "mitre_mapping": ["T1059", "T1204", "T1566"],
        "nist_mapping": ["SI-3", "SI-8"]
    },
    {
        "id": "ISO-A.8.8",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Management of technical vulnerabilities",
        "description": "Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated and appropriate measures shall be taken.",
        "implementation_guidance": "Regular vulnerability scans. Patch management process. Risk-based prioritization.",
        "evidence_required": ["Scan reports", "Patch compliance", "Remediation tracking"],
        "mitre_mapping": ["T1190", "T1210"],
        "nist_mapping": ["RA-5", "SI-2"]
    },
    {
        "id": "ISO-A.8.9",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Configuration management",
        "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
        "implementation_guidance": "Establish baselines. Use configuration management tools. Monitor drift.",
        "evidence_required": ["Baseline documents", "Configuration scans", "Change records"],
        "mitre_mapping": ["T1562"],
        "nist_mapping": ["CM-2", "CM-3", "CM-6"]
    },
    {
        "id": "ISO-A.8.15",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Logging",
        "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
        "implementation_guidance": "Centralize logs in SIEM. Define retention. Protect log integrity.",
        "evidence_required": ["SIEM configuration", "Log sources inventory", "Retention policy"],
        "mitre_mapping": ["T1070"],
        "nist_mapping": ["AU-2", "AU-3", "AU-6"]
    },
    {
        "id": "ISO-A.8.16",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Monitoring activities",
        "description": "Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.",
        "implementation_guidance": "Implement SIEM correlation. Define alerting thresholds. 24/7 SOC coverage.",
        "evidence_required": ["SIEM alerts", "SOC procedures", "Incident tickets"],
        "mitre_mapping": ["T1046", "T1040"],
        "nist_mapping": ["SI-4", "IR-4"]
    },
    {
        "id": "ISO-A.8.20",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Networks security",
        "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
        "implementation_guidance": "Network segmentation. Firewall rules. IDS/IPS. Regular reviews.",
        "evidence_required": ["Network diagrams", "Firewall rules", "IDS alerts", "Penetration tests"],
        "mitre_mapping": ["T1046", "T1595"],
        "nist_mapping": ["SC-7", "SC-8"]
    },
    {
        "id": "ISO-A.8.21",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Security of network services",
        "description": "Security mechanisms, service levels and service requirements of network services shall be identified, implemented and monitored.",
        "implementation_guidance": "SLAs with providers. Security requirements in contracts. Regular assessments.",
        "evidence_required": ["Service contracts", "SLA monitoring", "Provider assessments"],
        "mitre_mapping": [],
        "nist_mapping": ["SA-9", "SC-7"]
    },
    {
        "id": "ISO-A.8.22",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Segregation of networks",
        "description": "Groups of information services, users and information systems shall be segregated in the organization's networks.",
        "implementation_guidance": "VLAN segmentation. Zero trust architecture. Microsegmentation for critical assets.",
        "evidence_required": ["Network segmentation design", "VLAN inventory", "Firewall rules between segments"],
        "mitre_mapping": ["T1021"],
        "nist_mapping": ["SC-7", "AC-4"]
    },
    {
        "id": "ISO-A.8.23",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Web filtering",
        "description": "Access to external websites shall be managed to reduce exposure to malicious content.",
        "implementation_guidance": "Deploy web proxy. URL categorization. Block malicious categories.",
        "evidence_required": ["Web filter policy", "Blocked category list", "Access logs"],
        "mitre_mapping": ["T1566.002", "T1189"],
        "nist_mapping": ["SC-7", "SI-3"]
    },
    {
        "id": "ISO-A.8.24",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Use of cryptography",
        "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
        "implementation_guidance": "Define crypto standards. Key management procedures. Certificate lifecycle.",
        "evidence_required": ["Crypto policy", "Key inventory", "Certificate management procedures"],
        "mitre_mapping": ["T1552.004"],
        "nist_mapping": ["SC-12", "SC-13"]
    },
    {
        "id": "ISO-A.8.25",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Secure development life cycle",
        "description": "Rules for the secure development of software and systems shall be established and applied.",
        "implementation_guidance": "SAST/DAST in CI/CD. Security training for developers. Code review requirements.",
        "evidence_required": ["SDLC policy", "SAST/DAST reports", "Code review records"],
        "mitre_mapping": ["T1195.002"],
        "nist_mapping": ["SA-3", "SA-11", "SA-15"]
    },
    {
        "id": "ISO-A.8.28",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Secure coding",
        "description": "Secure coding principles shall be applied to software development.",
        "implementation_guidance": "OWASP guidelines. Input validation. Output encoding. Parameterized queries.",
        "evidence_required": ["Coding standards", "SAST findings", "Developer training records"],
        "mitre_mapping": ["T1190"],
        "nist_mapping": ["SA-11", "SI-10"]
    },
    {
        "id": "ISO-A.8.29",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Security testing in development and acceptance",
        "description": "Security testing processes shall be defined and implemented in the development life cycle.",
        "implementation_guidance": "Unit security tests. Integration security testing. Acceptance criteria include security.",
        "evidence_required": ["Test plans", "Security test results", "Acceptance criteria"],
        "mitre_mapping": [],
        "nist_mapping": ["SA-11", "CA-2"]
    },
    {
        "id": "ISO-A.8.31",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Separation of development, test and production environments",
        "description": "Development, testing and production environments shall be separated and secured.",
        "implementation_guidance": "Separate infrastructure. No production data in dev. Access controls per environment.",
        "evidence_required": ["Environment inventory", "Access controls", "Data handling procedures"],
        "mitre_mapping": ["T1199"],
        "nist_mapping": ["CM-4", "SA-11"]
    },
    {
        "id": "ISO-A.8.32",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Change management",
        "description": "Changes to information processing facilities and information systems shall be subject to change management procedures.",
        "implementation_guidance": "CAB approval process. Testing requirements. Rollback procedures.",
        "evidence_required": ["Change requests", "CAB minutes", "Test results", "Rollback procedures"],
        "mitre_mapping": [],
        "nist_mapping": ["CM-3", "CM-4"]
    },
    {
        "id": "ISO-A.8.34",
        "framework": "ISO 27001:2022",
        "category": "Technological",
        "name": "Protection of information systems during audit testing",
        "description": "Audit tests and other assurance activities involving assessment of operational systems shall be planned and agreed between the tester and appropriate management.",
        "implementation_guidance": "Scope agreements. Testing windows. Impact assessment. Data protection.",
        "evidence_required": ["Audit scope documents", "Test agreements", "Risk assessments"],
        "mitre_mapping": [],
        "nist_mapping": ["CA-2", "CA-7"]
    }
]

# ═══════════════════════════════════════════════════════════════
# NIST 800-53 Rev5 - Controles Seleccionados (más relevantes)
# ═══════════════════════════════════════════════════════════════

NIST_800_53_CONTROLS = [
    # ─────────────────────────────────────────────────────────────
    # AC - Access Control Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-AC-1",
        "framework": "NIST 800-53 Rev5",
        "family": "Access Control",
        "name": "Policy and Procedures",
        "description": "Develop, document, and disseminate access control policy and procedures.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Document access control policy addressing purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.",
        "assessment_procedures": ["Examine access control policy", "Interview responsible personnel", "Test policy implementation"],
        "mitre_mapping": ["T1078"],
        "iso_mapping": ["A.5.15"]
    },
    {
        "id": "NIST-AC-2",
        "framework": "NIST 800-53 Rev5",
        "family": "Access Control",
        "name": "Account Management",
        "description": "Define and manage system account types, establish conditions for group membership, assign account managers, require approvals for requests, create/enable/modify/disable/remove accounts, monitor account use, and notify account managers of account changes.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Implement automated account management. Review accounts periodically. Remove inactive accounts.",
        "assessment_procedures": ["Examine account management procedures", "Interview system administrators", "Test account lifecycle"],
        "mitre_mapping": ["T1078", "T1136"],
        "iso_mapping": ["A.5.16", "A.5.17"]
    },
    {
        "id": "NIST-AC-3",
        "framework": "NIST 800-53 Rev5",
        "family": "Access Control",
        "name": "Access Enforcement",
        "description": "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Implement access control lists, RBAC, or ABAC. Enforce least privilege.",
        "assessment_procedures": ["Examine access enforcement mechanisms", "Test access control implementation", "Interview security personnel"],
        "mitre_mapping": ["T1078"],
        "iso_mapping": ["A.5.15", "A.8.3"]
    },
    {
        "id": "NIST-AC-5",
        "framework": "NIST 800-53 Rev5",
        "family": "Access Control",
        "name": "Separation of Duties",
        "description": "Separate duties of individuals to prevent malevolent activity. Define system access authorizations to support separation of duties.",
        "baseline": ["Moderate", "High"],
        "implementation_guidance": "Identify critical functions requiring separation. Document in access control policy.",
        "assessment_procedures": ["Examine separation of duties policy", "Interview personnel", "Test separation enforcement"],
        "mitre_mapping": ["T1078"],
        "iso_mapping": ["A.5.3"]
    },
    {
        "id": "NIST-AC-6",
        "framework": "NIST 800-53 Rev5",
        "family": "Access Control",
        "name": "Least Privilege",
        "description": "Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Review and restrict privileges. Implement PAM. Just-in-time access.",
        "assessment_procedures": ["Examine privilege assignments", "Interview system administrators", "Test privilege restrictions"],
        "mitre_mapping": ["T1078.002", "T1078.003"],
        "iso_mapping": ["A.8.2"]
    },
    {
        "id": "NIST-AC-7",
        "framework": "NIST 800-53 Rev5",
        "family": "Access Control",
        "name": "Unsuccessful Logon Attempts",
        "description": "Enforce a limit of consecutive invalid logon attempts by a user during a time period and automatically lock account or delay next logon prompt.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Configure account lockout after X failed attempts. Implement progressive delays.",
        "assessment_procedures": ["Test lockout mechanisms", "Review lockout configurations", "Examine unlock procedures"],
        "mitre_mapping": ["T1110"],
        "iso_mapping": ["A.8.5"]
    },
    # ─────────────────────────────────────────────────────────────
    # AU - Audit and Accountability Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-AU-2",
        "framework": "NIST 800-53 Rev5",
        "family": "Audit and Accountability",
        "name": "Event Logging",
        "description": "Identify the types of events that the system is capable of logging in support of the audit function. Coordinate event logging with other organizational entities.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Define auditable events. Include successful/failed logons, privilege use, object access.",
        "assessment_procedures": ["Examine audit policy", "Review event logging configuration", "Test log generation"],
        "mitre_mapping": ["T1070"],
        "iso_mapping": ["A.8.15"]
    },
    {
        "id": "NIST-AU-3",
        "framework": "NIST 800-53 Rev5",
        "family": "Audit and Accountability",
        "name": "Content of Audit Records",
        "description": "Ensure that audit records contain information that establishes the following: what type of event occurred, when the event occurred, where the event occurred, the source of the event, the outcome of the event, and the identity of any individuals, subjects, or objects/entities associated with the event.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Configure logs to capture timestamp, user ID, event type, success/failure, affected resources.",
        "assessment_procedures": ["Examine sample audit records", "Verify required fields", "Test log completeness"],
        "mitre_mapping": [],
        "iso_mapping": ["A.8.15"]
    },
    {
        "id": "NIST-AU-6",
        "framework": "NIST 800-53 Rev5",
        "family": "Audit and Accountability",
        "name": "Audit Record Review, Analysis, and Reporting",
        "description": "Review and analyze system audit records for indications of inappropriate or unusual activity and report findings.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Implement SIEM. Define correlation rules. Establish review frequency.",
        "assessment_procedures": ["Interview security analysts", "Examine review procedures", "Test analysis capabilities"],
        "mitre_mapping": [],
        "iso_mapping": ["A.8.15", "A.8.16"]
    },
    {
        "id": "NIST-AU-9",
        "framework": "NIST 800-53 Rev5",
        "family": "Audit and Accountability",
        "name": "Protection of Audit Information",
        "description": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Restrict log access. Implement log integrity controls. Offsite log storage.",
        "assessment_procedures": ["Examine log protection mechanisms", "Test access controls", "Verify integrity mechanisms"],
        "mitre_mapping": ["T1070"],
        "iso_mapping": ["A.8.15"]
    },
    # ─────────────────────────────────────────────────────────────
    # AT - Awareness and Training Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-AT-2",
        "framework": "NIST 800-53 Rev5",
        "family": "Awareness and Training",
        "name": "Literacy Training and Awareness",
        "description": "Provide security and privacy literacy training to system users. Include practical exercises that simulate events and incidents.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Annual awareness training. Phishing simulations. Role-specific training.",
        "assessment_procedures": ["Examine training materials", "Review completion records", "Test user knowledge"],
        "mitre_mapping": ["T1566", "T1204"],
        "iso_mapping": ["A.6.3"]
    },
    {
        "id": "NIST-AT-3",
        "framework": "NIST 800-53 Rev5",
        "family": "Awareness and Training",
        "name": "Role-Based Training",
        "description": "Provide role-based security and privacy training to personnel with assigned security and privacy roles and responsibilities before authorizing access or performing duties, when required by system changes, and periodically thereafter.",
        "baseline": ["Moderate", "High"],
        "implementation_guidance": "Define training requirements per role. Track completion. Update for technology changes.",
        "assessment_procedures": ["Examine role-based training program", "Review training records", "Interview trained personnel"],
        "mitre_mapping": [],
        "iso_mapping": ["A.6.3"]
    },
    # ─────────────────────────────────────────────────────────────
    # CA - Assessment, Authorization, and Monitoring Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-CA-2",
        "framework": "NIST 800-53 Rev5",
        "family": "Assessment, Authorization, and Monitoring",
        "name": "Control Assessments",
        "description": "Develop a control assessment plan. Assess the controls in the system to determine the extent to which the controls are implemented correctly, operating as intended, and producing the desired outcome.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Annual security assessments. Penetration testing. Vulnerability assessments.",
        "assessment_procedures": ["Examine assessment plans", "Review assessment reports", "Verify remediation tracking"],
        "mitre_mapping": [],
        "iso_mapping": ["A.8.34"]
    },
    {
        "id": "NIST-CA-7",
        "framework": "NIST 800-53 Rev5",
        "family": "Assessment, Authorization, and Monitoring",
        "name": "Continuous Monitoring",
        "description": "Develop a system-level continuous monitoring strategy and implement continuous monitoring.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Implement security monitoring tools. Define metrics. Automate where possible.",
        "assessment_procedures": ["Examine monitoring strategy", "Review monitoring tools", "Test alert capabilities"],
        "mitre_mapping": [],
        "iso_mapping": ["A.8.16"]
    },
    # ─────────────────────────────────────────────────────────────
    # CM - Configuration Management Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-CM-2",
        "framework": "NIST 800-53 Rev5",
        "family": "Configuration Management",
        "name": "Baseline Configuration",
        "description": "Develop, document, and maintain a current baseline configuration of the system.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Document secure configurations. Use configuration management tools. Version control.",
        "assessment_procedures": ["Examine baseline documentation", "Compare current vs baseline", "Test configuration compliance"],
        "mitre_mapping": ["T1562"],
        "iso_mapping": ["A.8.9"]
    },
    {
        "id": "NIST-CM-3",
        "framework": "NIST 800-53 Rev5",
        "family": "Configuration Management",
        "name": "Configuration Change Control",
        "description": "Determine and document the types of changes to the system that are configuration-controlled. Review proposed configuration-controlled changes. Approve/disapprove configuration-controlled changes.",
        "baseline": ["Moderate", "High"],
        "implementation_guidance": "Change advisory board. Testing requirements. Rollback procedures.",
        "assessment_procedures": ["Examine change control procedures", "Review change records", "Test change process"],
        "mitre_mapping": [],
        "iso_mapping": ["A.8.32"]
    },
    {
        "id": "NIST-CM-6",
        "framework": "NIST 800-53 Rev5",
        "family": "Configuration Management",
        "name": "Configuration Settings",
        "description": "Establish and document configuration settings for system components that reflect the most restrictive mode consistent with operational requirements.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Use hardening guides (CIS, DISA STIG). Monitor configuration drift.",
        "assessment_procedures": ["Examine configuration standards", "Scan for compliance", "Review deviation approvals"],
        "mitre_mapping": ["T1562"],
        "iso_mapping": ["A.8.9"]
    },
    # ─────────────────────────────────────────────────────────────
    # IA - Identification and Authentication Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-IA-2",
        "framework": "NIST 800-53 Rev5",
        "family": "Identification and Authentication",
        "name": "Identification and Authentication (Organizational Users)",
        "description": "Uniquely identify and authenticate organizational users and associate that unique identification with processes acting on behalf of those users.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Unique user IDs. Strong authentication. MFA for privileged and remote access.",
        "assessment_procedures": ["Examine identification policy", "Test authentication mechanisms", "Verify unique IDs"],
        "mitre_mapping": ["T1078", "T1110"],
        "iso_mapping": ["A.5.16", "A.8.5"]
    },
    {
        "id": "NIST-IA-5",
        "framework": "NIST 800-53 Rev5",
        "family": "Identification and Authentication",
        "name": "Authenticator Management",
        "description": "Manage system authenticators by verifying identity before distributing authenticators, establishing initial authenticator content, ensuring authenticators have sufficient strength, establishing procedures for initial and lost/compromised authenticators, changing default authenticators, protecting authenticators from unauthorized use, and refreshing authenticators.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Password complexity requirements. Secure password storage. MFA tokens.",
        "assessment_procedures": ["Examine authenticator policy", "Test password requirements", "Verify MFA implementation"],
        "mitre_mapping": ["T1110", "T1552"],
        "iso_mapping": ["A.5.17"]
    },
    # ─────────────────────────────────────────────────────────────
    # IR - Incident Response Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-IR-1",
        "framework": "NIST 800-53 Rev5",
        "family": "Incident Response",
        "name": "Policy and Procedures",
        "description": "Develop, document, and disseminate incident response policy and procedures.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Document IR policy. Define roles and responsibilities. Communication procedures.",
        "assessment_procedures": ["Examine IR policy", "Interview IR team", "Review procedures"],
        "mitre_mapping": [],
        "iso_mapping": ["A.5.24"]
    },
    {
        "id": "NIST-IR-4",
        "framework": "NIST 800-53 Rev5",
        "family": "Incident Response",
        "name": "Incident Handling",
        "description": "Implement an incident handling capability that includes preparation, detection and analysis, containment, eradication, and recovery.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Develop playbooks. Train IR team. Test procedures regularly.",
        "assessment_procedures": ["Examine incident handling procedures", "Review incident records", "Test response capabilities"],
        "mitre_mapping": [],
        "iso_mapping": ["A.5.25", "A.5.26"]
    },
    {
        "id": "NIST-IR-6",
        "framework": "NIST 800-53 Rev5",
        "family": "Incident Response",
        "name": "Incident Reporting",
        "description": "Require personnel to report suspected incidents to the organizational incident response capability. Report incidents to authorities.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Define reporting channels. Timelines for reporting. External notification requirements.",
        "assessment_procedures": ["Examine reporting procedures", "Interview personnel", "Review incident reports"],
        "mitre_mapping": [],
        "iso_mapping": ["A.5.5", "A.5.26"]
    },
    {
        "id": "NIST-IR-8",
        "framework": "NIST 800-53 Rev5",
        "family": "Incident Response",
        "name": "Incident Response Plan",
        "description": "Develop an incident response plan that provides the organization with a roadmap for implementing its incident response capability.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Comprehensive IR plan. Review and update annually. Distribute to stakeholders.",
        "assessment_procedures": ["Examine IR plan", "Verify distribution", "Test plan execution"],
        "mitre_mapping": [],
        "iso_mapping": ["A.5.24", "A.5.27"]
    },
    # ─────────────────────────────────────────────────────────────
    # RA - Risk Assessment Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-RA-3",
        "framework": "NIST 800-53 Rev5",
        "family": "Risk Assessment",
        "name": "Risk Assessment",
        "description": "Conduct a risk assessment to identify threats to and vulnerabilities of the system, determine the likelihood and magnitude of harm, and prioritize risks.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Annual risk assessments. Threat modeling. Risk register.",
        "assessment_procedures": ["Examine risk assessment methodology", "Review risk register", "Verify risk treatment"],
        "mitre_mapping": ["T1595", "T1592"],
        "iso_mapping": ["A.5.7"]
    },
    {
        "id": "NIST-RA-5",
        "framework": "NIST 800-53 Rev5",
        "family": "Risk Assessment",
        "name": "Vulnerability Monitoring and Scanning",
        "description": "Monitor and scan for vulnerabilities in the system and hosted applications. Analyze vulnerability scan reports and remediate vulnerabilities.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Regular vulnerability scans. Prioritize by CVSS. Track remediation.",
        "assessment_procedures": ["Examine scanning procedures", "Review scan reports", "Verify remediation"],
        "mitre_mapping": ["T1190", "T1210"],
        "iso_mapping": ["A.8.8"]
    },
    # ─────────────────────────────────────────────────────────────
    # SA - System and Services Acquisition Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-SA-11",
        "framework": "NIST 800-53 Rev5",
        "family": "System and Services Acquisition",
        "name": "Developer Testing and Evaluation",
        "description": "Require the developer of the system to create a test plan, implement the plan, document results, and provide evidence of security testing.",
        "baseline": ["Moderate", "High"],
        "implementation_guidance": "Security testing in SDLC. SAST/DAST. Code review.",
        "assessment_procedures": ["Examine test plans", "Review test results", "Verify coverage"],
        "mitre_mapping": ["T1195.002"],
        "iso_mapping": ["A.8.25", "A.8.29"]
    },
    # ─────────────────────────────────────────────────────────────
    # SC - System and Communications Protection Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-SC-7",
        "framework": "NIST 800-53 Rev5",
        "family": "System and Communications Protection",
        "name": "Boundary Protection",
        "description": "Monitor and control communications at the external managed interfaces and key internal boundaries. Implement subnetworks for publicly accessible system components.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Firewalls at boundaries. DMZ for public services. Monitor traffic.",
        "assessment_procedures": ["Examine network diagrams", "Review firewall rules", "Test boundary controls"],
        "mitre_mapping": ["T1046", "T1595"],
        "iso_mapping": ["A.8.20", "A.8.22"]
    },
    {
        "id": "NIST-SC-12",
        "framework": "NIST 800-53 Rev5",
        "family": "System and Communications Protection",
        "name": "Cryptographic Key Establishment and Management",
        "description": "Establish and manage cryptographic keys when cryptography is employed within the system.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Key management procedures. Secure key storage. Key rotation.",
        "assessment_procedures": ["Examine key management procedures", "Review key inventory", "Test key protection"],
        "mitre_mapping": ["T1552.004"],
        "iso_mapping": ["A.8.24"]
    },
    {
        "id": "NIST-SC-28",
        "framework": "NIST 800-53 Rev5",
        "family": "System and Communications Protection",
        "name": "Protection of Information at Rest",
        "description": "Protect the confidentiality and/or integrity of information at rest.",
        "baseline": ["Moderate", "High"],
        "implementation_guidance": "Encrypt sensitive data at rest. Full disk encryption. Database encryption.",
        "assessment_procedures": ["Examine encryption implementation", "Verify coverage", "Test encryption effectiveness"],
        "mitre_mapping": ["T1005"],
        "iso_mapping": ["A.8.24"]
    },
    # ─────────────────────────────────────────────────────────────
    # SI - System and Information Integrity Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-SI-2",
        "framework": "NIST 800-53 Rev5",
        "family": "System and Information Integrity",
        "name": "Flaw Remediation",
        "description": "Identify, report, and correct system flaws. Test software and firmware updates before installation. Install security-relevant updates within defined timeframes.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Patch management process. Test patches. Emergency patching procedures.",
        "assessment_procedures": ["Examine patching policy", "Review patch status", "Test patch process"],
        "mitre_mapping": ["T1190", "T1210"],
        "iso_mapping": ["A.8.8"]
    },
    {
        "id": "NIST-SI-3",
        "framework": "NIST 800-53 Rev5",
        "family": "System and Information Integrity",
        "name": "Malicious Code Protection",
        "description": "Implement malicious code protection mechanisms at system entry and exit points. Update malicious code protection mechanisms when new releases are available.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Deploy AV/EDR. Email filtering. Web filtering. Regular updates.",
        "assessment_procedures": ["Examine malware protection", "Verify deployment", "Test detection capabilities"],
        "mitre_mapping": ["T1059", "T1204", "T1566"],
        "iso_mapping": ["A.8.7"]
    },
    {
        "id": "NIST-SI-4",
        "framework": "NIST 800-53 Rev5",
        "family": "System and Information Integrity",
        "name": "System Monitoring",
        "description": "Monitor the system to detect attacks and indicators of potential attacks, unauthorized local/network/remote connections.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Implement SIEM. Network monitoring. Endpoint monitoring. Alert on anomalies.",
        "assessment_procedures": ["Examine monitoring strategy", "Review alerts", "Test detection capabilities"],
        "mitre_mapping": ["T1046", "T1040"],
        "iso_mapping": ["A.8.16"]
    },
    # ─────────────────────────────────────────────────────────────
    # PS - Personnel Security Family
    # ─────────────────────────────────────────────────────────────
    {
        "id": "NIST-PS-3",
        "framework": "NIST 800-53 Rev5",
        "family": "Personnel Security",
        "name": "Personnel Screening",
        "description": "Screen individuals prior to authorizing access to the system. Rescreen individuals per defined conditions.",
        "baseline": ["Low", "Moderate", "High"],
        "implementation_guidance": "Background checks. Periodic rescreening for sensitive positions.",
        "assessment_procedures": ["Examine screening policy", "Review screening records", "Verify compliance"],
        "mitre_mapping": ["T1078"],
        "iso_mapping": ["A.6.1"]
    }
]


def get_embedding(text: str) -> list:
    """Genera embedding usando Ollama"""
    response = requests.post(
        f"{OLLAMA_URL}/api/embeddings",
        json={"model": EMBED_MODEL, "prompt": text}
    )
    return response.json()["embedding"]


def create_collection():
    """Crea la colección GRC en Qdrant"""
    # Verificar si existe
    response = requests.get(f"{QDRANT_URL}/collections/{COLLECTION_NAME}")
    if response.status_code == 200:
        print(f"⚠️  Colección {COLLECTION_NAME} ya existe. Eliminando...")
        requests.delete(f"{QDRANT_URL}/collections/{COLLECTION_NAME}")
    
    # Crear nueva colección
    requests.put(
        f"{QDRANT_URL}/collections/{COLLECTION_NAME}",
        json={
            "vectors": {
                "size": 768,  # nomic-embed-text dimension
                "distance": "Cosine"
            }
        }
    )
    print(f"✅ Colección {COLLECTION_NAME} creada")


def index_controls(controls: list, framework: str):
    """Indexa controles en Qdrant"""
    points = []
    
    for i, control in enumerate(controls):
        # Crear texto para embedding
        if framework == "ISO":
            text = f"""
            Control: {control['id']} - {control['name']}
            Framework: {control['framework']}
            Category: {control['category']}
            Description: {control['description']}
            Implementation Guidance: {control['implementation_guidance']}
            Evidence Required: {', '.join(control['evidence_required'])}
            MITRE Mapping: {', '.join(control['mitre_mapping']) if control['mitre_mapping'] else 'N/A'}
            NIST Mapping: {', '.join(control['nist_mapping'])}
            """
        else:
            text = f"""
            Control: {control['id']} - {control['name']}
            Framework: {control['framework']}
            Family: {control['family']}
            Description: {control['description']}
            Baselines: {', '.join(control['baseline'])}
            Implementation Guidance: {control['implementation_guidance']}
            Assessment Procedures: {', '.join(control['assessment_procedures'])}
            MITRE Mapping: {', '.join(control['mitre_mapping']) if control['mitre_mapping'] else 'N/A'}
            ISO Mapping: {', '.join(control['iso_mapping'])}
            """
        
        embedding = get_embedding(text)

        # Preparar payload para Qdrant
        point_id = hash(control['id']) % (2**63)  # ID único
        
        points.append({
            "id": abs(point_id) + i,
            "vector": embedding,
            "payload": control
        })
        
        print(f"  ✓ {control['id']} - {control['name']}")
    
    # Insertar en Qdrant
    response = requests.put(
        f"{QDRANT_URL}/collections/{COLLECTION_NAME}/points",
        json={"points": points}
    )
    
    if response.status_code == 200:
        print(f"✅ {len(points)} controles {framework} indexados")
    else:
        print(f"❌ Error indexando: {response.text}")


def search_controls(query: str, limit: int = 5) -> list:
    """Busca controles relevantes por consulta semántica"""
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


def get_compliance_mapping(alert_description: str) -> dict:
    """Mapea una alerta de seguridad a controles de cumplimiento"""
    results = search_controls(alert_description, limit=10)
    
    iso_controls = []
    nist_controls = []
    
    for result in results:
        control = result['payload']
        score = result['score']
        
        if control['framework'] == "ISO 27001:2022":
            iso_controls.append({
                "id": control['id'],
                "name": control['name'],
                "relevance": round(score * 100, 2)
            })
        else:
            nist_controls.append({
                "id": control['id'],
                "name": control['name'],
                "relevance": round(score * 100, 2)
            })
    
    return {
        "iso_27001": iso_controls[:5],
        "nist_800_53": nist_controls[:5]
    }


def generate_gap_analysis(organization_controls: list) -> dict:
    """Genera análisis de brechas comparando controles implementados vs requeridos"""
    all_controls = ISO_27001_CONTROLS + NIST_800_53_CONTROLS
    
    implemented = set(organization_controls)
    required = set([c['id'] for c in all_controls])
    
    gaps = required - implemented
    covered = required & implemented
    
    return {
        "total_controls": len(required),
        "implemented": len(covered),
        "gaps": len(gaps),
        "compliance_percentage": round(len(covered) / len(required) * 100, 2),
        "missing_controls": list(gaps)[:20]  # Primeros 20
    }


def main():
    """Función principal"""
    print("=" * 60)
    print("🏛️  GRC CONTROLS INDEXER - ISO 27001 & NIST 800-53")
    print("=" * 60)
    print(f"⏰ Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Crear colección
    print("📦 Creando colección en Qdrant...")
    create_collection()
    print()
    
    # Indexar ISO 27001
    print(f"📋 Indexando {len(ISO_27001_CONTROLS)} controles ISO 27001:2022...")
    index_controls(ISO_27001_CONTROLS, "ISO")
    print()
    
    # Indexar NIST 800-53
    print(f"📋 Indexando {len(NIST_800_53_CONTROLS)} controles NIST 800-53...")
    index_controls(NIST_800_53_CONTROLS, "NIST")
    print()
    
    # Test de búsqueda
    print("🔍 Probando búsqueda semántica...")
    test_queries = [
        "brute force authentication attack",
        "incident response procedures",
        "network segmentation firewall"
    ]
    
    for query in test_queries:
        print(f"\n  Query: '{query}'")
        results = search_controls(query, limit=3)
        for r in results:
            print(f"    → {r['payload']['id']}: {r['payload']['name']} (Score: {r['score']:.3f})")
    
    print()
    print("=" * 60)
    print("✅ INDEXACIÓN GRC COMPLETADA")
    print(f"📊 Total: {len(ISO_27001_CONTROLS) + len(NIST_800_53_CONTROLS)} controles")
    print(f"⏰ Fin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
