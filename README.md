╔════════════════════════════╗
║       AEGIS PLATFORM       ║
║    DevSecOps CLI Toolkit   ║
╚════════════════════════════╝

# 🚀 AEGIS CYBER SCANNER CLI MAIN 1

## 📌 Overview
Este software foi detectado como sendo do tipo [Serviço Backend, Web App ou API]. Ele compreende um total de 150 arquivos/módulos mapeados fisicamente, permitindo auditoria detalhada, integrações eficientes e implantação facilitada.

## 🧠 What this project does
- Análise estruturada do projeto Cyber Scanner Cli Main(1) importado e auditado via ZIP de forma automatizada.

## 🏗 Architecture
O subsistema é desenhado seguindo práticas rígidas de engenharia defensiva:
- **CLI Layer**: Camada de terminal unificada operando sob o padrão de design system Aegis CLI.
- **Backend Logic**: Lógica funcional síncrona com mitigadores integrados contra exaustão de cotas.

## 📁 Project Structure
```text
├── README.md
├── cyber-scanner-cli-main/.emergent/cron/applied.hash
├── cyber-scanner-cli-main/.emergent/cron/dispatch_webhook.sh
├── cyber-scanner-cli-main/.emergent/cron/watch_crons.sh
├── cyber-scanner-cli-main/.emergent/cron/webhook-crons
├── cyber-scanner-cli-main/.emergent/cron/webhook_crond.sh
├── cyber-scanner-cli-main/.emergent/emergent.yml
├── cyber-scanner-cli-main/.emergent/system_deps.txt
├── cyber-scanner-cli-main/.gitconfig
├── cyber-scanner-cli-main/.gitignore
├── cyber-scanner-cli-main/README.md
├── cyber-scanner-cli-main/backend/auth.py
├── cyber-scanner-cli-main/backend/db.py
├── cyber-scanner-cli-main/backend/llm_analyzer.py
├── cyber-scanner-cli-main/backend/pytest.ini
├── cyber-scanner-cli-main/backend/reports.py
├── cyber-scanner-cli-main/backend/requirements.txt
├── cyber-scanner-cli-main/backend/scanners.py
├── cyber-scanner-cli-main/backend/server.py
├── cyber-scanner-cli-main/backend/terminal.py
├── cyber-scanner-cli-main/backend/tests/__init__.py
├── cyber-scanner-cli-main/backend/tests/test_vulnscan_backend.py
├── cyber-scanner-cli-main/design_guidelines.json
├── cyber-scanner-cli-main/frontend/.gitignore
├── cyber-scanner-cli-main/frontend/README.md
├── cyber-scanner-cli-main/frontend/components.json
├── cyber-scanner-cli-main/frontend/craco.config.js
├── cyber-scanner-cli-main/frontend/jsconfig.json
├── cyber-scanner-cli-main/frontend/package.json
├── cyber-scanner-cli-main/frontend/plugins/health-check/health-endpoints.js
├── cyber-scanner-cli-main/frontend/plugins/health-check/webpack-health-plugin.js
├── cyber-scanner-cli-main/frontend/postcss.config.js
├── cyber-scanner-cli-main/frontend/public/index.html
├── cyber-scanner-cli-main/frontend/src/App.css
├── cyber-scanner-cli-main/frontend/src/App.js
├── cyber-scanner-cli-main/frontend/src/components/ScanTerminal.jsx
├── cyber-scanner-cli-main/frontend/src/components/Shell.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/accordion.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/alert-dialog.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/alert.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/aspect-ratio.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/avatar.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/badge.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/breadcrumb.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/button.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/calendar.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/card.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/carousel.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/checkbox.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/collapsible.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/command.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/context-menu.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/dialog.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/drawer.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/dropdown-menu.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/form.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/hover-card.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/input-otp.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/input.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/label.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/menubar.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/navigation-menu.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/pagination.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/popover.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/progress.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/radio-group.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/resizable.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/scroll-area.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/select.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/separator.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/sheet.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/skeleton.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/slider.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/sonner.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/switch.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/table.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/tabs.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/textarea.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/toast.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/toaster.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/toggle-group.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/toggle.jsx
├── cyber-scanner-cli-main/frontend/src/components/ui/tooltip.jsx
├── cyber-scanner-cli-main/frontend/src/constants/testIds/auth.js
├── cyber-scanner-cli-main/frontend/src/constants/testIds/home.js
├── cyber-scanner-cli-main/frontend/src/constants/testIds/index.js
├── cyber-scanner-cli-main/frontend/src/hooks/use-toast.js
├── cyber-scanner-cli-main/frontend/src/index.css
├── cyber-scanner-cli-main/frontend/src/index.js
├── cyber-scanner-cli-main/frontend/src/lib/api.js
├── cyber-scanner-cli-main/frontend/src/lib/auth.js
├── cyber-scanner-cli-main/frontend/src/lib/utils.js
├── cyber-scanner-cli-main/frontend/src/pages/AuthPage.jsx
├── cyber-scanner-cli-main/frontend/src/pages/Dashboard.jsx
├── cyber-scanner-cli-main/frontend/src/pages/LandingPage.jsx
├── cyber-scanner-cli-main/frontend/src/pages/NewScan.jsx
├── cyber-scanner-cli-main/frontend/src/pages/ScanDetail.jsx
├── cyber-scanner-cli-main/frontend/src/testIds.js
├── cyber-scanner-cli-main/frontend/tailwind.config.js
├── cyber-scanner-cli-main/memory/.gitkeep
├── cyber-scanner-cli-main/memory/PRD.md
├── cyber-scanner-cli-main/test_reports/.gitkeep
├── cyber-scanner-cli-main/test_reports/iteration_1.json
├── cyber-scanner-cli-main/test_reports/pytest/.gitkeep
├── cyber-scanner-cli-main/test_reports/pytest/pytest_results.xml
├── cyber-scanner-cli-main/test_result.md
├── cyber-scanner-cli-main/tests/__init__.py
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/.gitignore
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/README.md
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/cwe22-academy/CWE22_Remediation_Guide.md
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/cwe22-academy/backend/app/routes/labs.py
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/cwe22-academy/frontend/src/components/CWE22Academy.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/cyber_engine_json.py
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/cyber_hunter_lab_cli.py
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/index.html
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/metadata.json
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/package-lock.json
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/package.json
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/App.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/AgenticPipeline.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/AnalysisDashboard.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/ApiKeySetup.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/CWE22Academy.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/CodeInput.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/LandingPage.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/LoginPage.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/MethodologyCard.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/OSSVRPScopeGenerator.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/OSVSchemaModule.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/ReverseArchEngine.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/UniversalReportGenerator.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/VRPResourceHub.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/VulnScanSaaSModule.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/components/ui/Badge.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/index.css
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/lib/apiKey.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/lib/utils.ts
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/main.tsx
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/services/gemini.ts
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/src/types.ts
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/tsconfig.json
├── cyber-scanner-cli-main/workspace/1a647709-b29d-4da0-9523-fb4cf0e1f001/src/vite.config.ts
├── cyber-scanner-cli-main/workspace/28d333f6-d3d3-45f8-bac7-fa5b814cc84e/src/vuln_sample/app.py
├── cyber-scanner-cli-main/workspace/28d333f6-d3d3-45f8-bac7-fa5b814cc84e/src/vuln_sample/deploy.yaml
├── cyber-scanner-cli-main/workspace/28d333f6-d3d3-45f8-bac7-fa5b814cc84e/src/vuln_sample/requirements.txt
├── cyber-scanner-cli-main/workspace/4482577c-41a6-4288-8a4f-9cd62540d95a/src/vuln_sample/app.py
├── cyber-scanner-cli-main/workspace/4482577c-41a6-4288-8a4f-9cd62540d95a/src/vuln_sample/deploy.yaml
├── cyber-scanner-cli-main/workspace/4482577c-41a6-4288-8a4f-9cd62540d95a/src/vuln_sample/requirements.txt
├── cyber-scanner-cli-main/workspace/506e79cb-4e54-4b1f-af45-3acbd14d3b46/src/app.py
├── cyber-scanner-cli-main/workspace/506e79cb-4e54-4b1f-af45-3acbd14d3b46/src/k8s/pod.yaml
├── cyber-scanner-cli-main/workspace/506e79cb-4e54-4b1f-af45-3acbd14d3b46/src/requirements.txt
└── README.md
```

## ⚙️ Installation & Termux Setup
Instalação direta e compatível nativamente com ambientes Linux, Kali Linux e Termux:

```bash
# 1. Clonar repositório e acessar diretório
git clone <repo_url>
cd aegis-cyber-scanner-cli-main-1

npm install
```

## ▶️ Usage & Execution
Para inicializar e interagir com o subsistema de 30 Agentes de Auditoria de Segurança:

```bash
npm start
```

### ⚡ Comando Completo em Uma Linha (QuickStart)
```bash
source ~/crewai-env/bin/activate && ollama serve > /dev/null 2>&1 & && sleep 3 && python main_ollama_pro.py --target https://example.com --model llama3.2:latest --verbose
```

## 🔐 Security Model & Zero-Trust Audit
- **Classification**: CRÍTICO / ISOLADO
- **Higiene Digital**: Modelo Zero-Trust com filtros de higienização de payload síncronos e prevenção de vazamentos.

## 🧩 Dependencies & Requirements
- **Plataforma/Runtime**: TypeScript / JavaScript (Node.js)

---
*Generated by AEGIS DevSecOps Security Orchestrator System*
