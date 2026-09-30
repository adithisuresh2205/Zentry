# SentinelGate (Zentry) — Secure Software Engineering Documentation
## Course: 20CYS401 – Secure Software Engineering

This directory contains the complete, rigorous, and synchronized Secure Software Engineering artifacts demonstrating Course Outcomes CO1, CO2, CO3, and CO4.

Every document in this repository is derived sequentially from the previous phase, establishing complete end-to-end consistency across requirements, system modeling, threat modeling, security architecture, containerization, CI/CD, DevSecOps testing, and governance.

---

## Documentation Structure & Course Outcome Mapping

| Folder | Section / Artifact | Course Outcome | Description |
| :--- | :--- | :--- | :--- |
| [`01_problem_statement/`](./01_problem_statement/) | Problem Statement & Objectives | **CO1** | High-level problem statement, project objectives, and operational scope. |
| [`02_srs/`](./02_srs/) | Software Requirements Specification (SRS) | **CO1** | IEEE 830 / ISO/IEC/IEEE 29148 compliant specification. |
| [`03_requirements/`](./03_requirements/) | Detailed Functional, Non-Functional & Security Requirements | **CO1** | Traceable requirements matrix (FR, NFR, SR). |
| [`04_use_cases/`](./04_use_cases/) | Use Case Diagrams & Specifications | **CO1** | UML Use Case diagrams and structured use case specifications. |
| [`05_analysis_model/`](./05_analysis_model/) | System Analysis Model | **CO1** | Boundary-Control-Entity (BCE) models and domain analysis. |
| [`06_erd/`](./06_erd/) | Entity-Relationship (ER) Diagram & Data Dictionary | **CO1** | Relational schema, normalization (3NF), and entities. |
| [`07_dfd/`](./07_dfd/) | Data Flow Diagrams (DFD Level 0 & Level 1) | **CO1** | Context and decomposition DFDs with trust boundaries. |
| [`08_architecture/`](./08_architecture/) | Secure Architecture, UML Class, Sequence & Activity Diagrams | **CO1 / CO2** | System topology, component interactions, and execution flow. |
| [`09_threat_model/`](./09_threat_model/) | Threat Model, Asset Identification & CIA Analysis | **CO2** | Assets, CIA impact analysis, and trust boundary mapping. |
| [`10_stride/`](./10_stride/) | STRIDE Threat Analysis Matrix | **CO2** | Exhaustive STRIDE threat evaluation across DFD elements. |
| [`11_information_flow/`](./11_information_flow/) | Information Flow Analysis | **CO2** | Data in transit, token handling, and log security paths. |
| [`12_vulnerability_analysis/`](./12_vulnerability_analysis/) | Vulnerability Analysis & Catalog | **CO2** | Comprehensive vulnerability analysis with verification. |
| [`13_risk_analysis/`](./13_risk_analysis/) | Risk Analysis, Risk Matrix & Security Controls | **CO2 / CO4** | Quantitative and qualitative risk registers and controls. |
| [`14_attack_tree/`](./14_attack_tree/) | Attack Trees & Threat Paths | **CO2** | Hierarchical attack trees with AND/OR logic and mitigations. |
| [`15_ui_design/`](./15_ui_design/) | UI Design & Tactical SOC Specifications | **CO1** | Wireframes, component specifications, and user flows. |
| [`16_product_backlog/`](./16_product_backlog/) | Agile Product Backlog | **CO1** | Epics, user stories, acceptance criteria, and story points. |
| [`17_jira_scrum/`](./17_jira_scrum/) | Jira/Scrum Structure, Sprints & Metrics | **CO1** | Sprint 1 & 2 planning, boards, burndown, and defect tracking. |
| [`18_docker/`](./18_docker/) | Containerization & Hardening | **CO3** | Dockerfiles, Docker Compose, non-root audit, and security options. |
| [`19_kubernetes/`](./19_kubernetes/) | Kubernetes Deployment & Manifests | **CO3** | K8s deployments, services, network policies, and configs. |
| [`20_cicd/`](./20_cicd/) | CI/CD Pipeline (GitHub Actions) | **CO3 / CO4** | Automated multi-stage build, test, and security gate pipeline. |
| [`21_sonarqube/`](./21_sonarqube/) | SAST: SonarQube / SonarCloud Integration | **CO4** | Static code analysis, Quality Gate configuration, and findings. |
| [`22_snyk/`](./22_snyk/) | SCA: Snyk Dependency & Container Security | **CO4** | Software Composition Analysis, CVE remediation records. |
| [`23_owasp_zap/`](./23_owasp_zap/) | DAST: OWASP ZAP Dynamic Application Security Testing | **CO4** | Automated DAST scanning, vulnerability alerts, and verification. |
| [`24_testing/`](./24_testing/) | Unit, Integration & System Penetration Testing | **CO4** | PyTest test execution, code coverage, and attack simulations. |
| [`25_fuzzing/`](./25_fuzzing/) | Fuzz Testing Harness & Vulnerability Detection | **CO4** | Mutation-based and grammar fuzzer, crash reports, fixes. |
| [`26_logging_monitoring/`](./26_logging_monitoring/) | Security Logging, HMAC Sealing & Monitoring | **CO4** | Structured audit logging, HMAC-SHA256 chain, telemetry metrics. |
| [`27_governance/`](./27_governance/) | Security Governance & Organizational Policies | **CO4** | Access control, password, data protection, and incident response. |
| [`28_compliance/`](./28_compliance/) | Regulatory & Standard Compliance Mapping | **CO4** | OWASP Top 10 2021, NIST SP 800-207 Zero Trust, ISO 27001 mapping. |
| [`29_final_report/`](./29_final_report/) | Final Project Report & Evidence Checklist | **CO1-CO4** | Comprehensive final evaluation report and syllabus audit matrix. |
