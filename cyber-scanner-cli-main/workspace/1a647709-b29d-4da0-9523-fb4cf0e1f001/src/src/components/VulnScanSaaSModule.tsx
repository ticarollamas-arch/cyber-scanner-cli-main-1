import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldCheck, 
  Server, 
  Database, 
  Layers, 
  Cpu, 
  FileText, 
  UploadCloud, 
  CheckCircle2, 
  AlertTriangle, 
  Lock, 
  Code2, 
  Copy, 
  Check, 
  Download, 
  Zap, 
  Activity, 
  DollarSign, 
  Scale, 
  Terminal, 
  BookOpen, 
  FileCode2,
  RefreshCw,
  Search,
  ChevronRight,
  ExternalLink,
  ShieldAlert,
  Sliders,
  Sparkles,
  ListOrdered
} from 'lucide-react';
import { Badge } from './ui/Badge';
import { cn } from '../lib/utils';

export function VulnScanSaaSModule() {
  const [activeTab, setActiveTab] = useState<'simulator' | 'architecture' | 'schema' | 'security' | 'finops' | 'blueprint'>('simulator');

  // Simulator State
  const [selectedSample, setSelectedSample] = useState<string>('node_backend');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanStep, setScanStep] = useState<number>(0); // 0: Idle, 1: Upload, 2: Unzip & Virus, 3: SAST, 4: SCA, 5: AI-Config, 6: Complete
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [activeReportFormat, setActiveReportFormat] = useState<'markdown' | 'pdf' | 'docx'>('markdown');
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  // Selected Architecture ADR
  const [selectedAdr, setSelectedAdr] = useState<string>('adr-001');

  // Copier helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const sampleProjects = [
    {
      id: 'node_backend',
      name: 'express-auth-microservice.zip',
      size: '4.2 MB',
      lang: 'TypeScript / Node.js',
      description: 'Microserviço de autenticação com Express, JWT e rotas de download de relatórios.',
      vulnsCount: 4,
      critical: 1,
      high: 2,
      medium: 1
    },
    {
      id: 'go_k8s_app',
      name: 'cloud-payment-gateway-v2.zip',
      size: '12.8 MB',
      lang: 'Go / Kubernetes / Terraform',
      description: 'API em Go com manifestos K8s, deployments com HostPath e roles IAM.',
      vulnsCount: 5,
      critical: 2,
      high: 2,
      medium: 1
    },
    {
      id: 'python_flask_api',
      name: 'ml-inference-pipeline.zip',
      size: '8.5 MB',
      lang: 'Python / Flask / Docker',
      description: 'Pipeline de inferência ML com YAML de Dockerfile, dependências de pacotes PyPI antigos.',
      vulnsCount: 3,
      critical: 1,
      high: 1,
      medium: 1
    }
  ];

  const simulatedVulnerabilities = [
    {
      id: 'VULN-P0-01',
      severity: 'P0',
      title: 'BOLA & Subpath Traversal sem isolamento de Resolver',
      filePath: 'backend/pkg/resolver/file_downloader.go',
      line: 84,
      scanner: 'SAST',
      cwe: 'CWE-22 / OWASP A01:2021-Broken Access Control',
      impact: 'Elevação de privilégios e leitura de arquivos sensíveis do sistema (/etc/shadow, tokens k8s).',
      codeSnippet: `func ResolveFilePath(userReq string, baseDir string) (string, error) {\n  // FALHA ARQUITETURAL: Falta contrato de segurança no Resolver\n  targetPath := filepath.Join(baseDir, userReq)\n  return targetPath, nil // Retorna caminho sem sanitização nem validação de prefixo estrito\n}`,
      poc: `curl -X POST https://api.target.com/v1/download -H "Authorization: Bearer <token>" -d '{"path": "../../../../../etc/passwd"}'`,
      recommendation: `1. Implementar sanitização com filepath.Clean e validação estrita de prefixo:\n   if !strings.HasPrefix(cleanPath, baseDir + string(filepath.Separator)) {\n       return "", errors.New("boundary violation")\n   }`
    },
    {
      id: 'VULN-P1-02',
      severity: 'P1',
      title: 'Uso de Volume HostPath com Privilégios no Kubernetes',
      filePath: 'infrastructure/kubernetes/backend-deployment.yaml',
      line: 62,
      scanner: 'AI_CONFIG',
      cwe: 'CWE-250 / Pod Security Standard Violation',
      impact: 'Fuga de contêiner e acesso direto ao sistema de arquivos do nó hospedeiro.',
      codeSnippet: `volumes:\n- name: host-root-access\n  hostPath:\n    path: /var/run/docker.sock\n    type: File`,
      poc: `kubectl exec -it <pod-name> -- ls -la /var/run/docker.sock`,
      recommendation: `Evitar montagem de hostPath e socket do Docker. Usar volumes persistentes isolados (PVC) e aplicar Pod Security Admission Rules.`
    },
    {
      id: 'VULN-P1-03',
      severity: 'P1',
      title: 'Dependência Crítica com Vulnerabilidade Conhecida (lodash < 4.17.21)',
      filePath: 'frontend/package.json',
      line: 38,
      scanner: 'SCA',
      cwe: 'CVE-2021-23336 / Prototype Pollution',
      impact: 'Injeção de propriedades globais levando a RCE ou negação de serviço.',
      codeSnippet: `"dependencies": {\n  "lodash": "^4.17.20"\n}`,
      poc: `npm audit --json | grep -A 10 CVE-2021-23336`,
      recommendation: `Atualizar lodash para ^4.17.21 no package.json e rodar 'npm audit fix'.`
    },
    {
      id: 'VULN-P2-04',
      severity: 'P2',
      title: 'JWT Secret Hardcoded em Configurações de Fallback',
      filePath: 'backend/pkg/auth/jwt.go',
      line: 29,
      scanner: 'SAST',
      cwe: 'CWE-798 / Use of Hard-coded Credentials',
      impact: 'Assinatura arbitrária de tokens JWT por atacantes para bypass de autenticação.',
      codeSnippet: `func GetJWTSecret() []byte {\n  secret := os.Getenv("JWT_SECRET")\n  if secret == "" {\n    return []byte("super_secret_default_key_change_me") // FALHA DE SEGURANÇA\n  }\n  return []byte(secret)\n}`,
      poc: `jwt.sign({ sub: "admin", role: "admin" }, "super_secret_default_key_change_me")`,
      recommendation: `Remover o fallback hardcoded. Exigir que a aplicação aborte no boot se JWT_SECRET não for injetado via Secret Manager.`
    }
  ];

  const handleStartSimulatedScan = () => {
    setIsScanning(true);
    setScanStep(1);
    setScanProgress(15);

    setTimeout(() => {
      setScanStep(2);
      setScanProgress(35);
    }, 1200);

    setTimeout(() => {
      setScanStep(3);
      setScanProgress(60);
    }, 2500);

    setTimeout(() => {
      setScanStep(4);
      setScanProgress(80);
    }, 3800);

    setTimeout(() => {
      setScanStep(5);
      setScanProgress(95);
    }, 5000);

    setTimeout(() => {
      setScanStep(6);
      setScanProgress(100);
      setIsScanning(false);
    }, 6200);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* Top Banner & Title */}
      <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 md:p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Badge variant="info">Arquitetura SaaS Enterprise Zero-Trust</Badge>
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest bg-zinc-900/80 px-2.5 py-1 rounded-full border border-zinc-800">
                Spec v1.0 • Multi-Tenant
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-mono font-bold text-white tracking-tight">
              VulnScan AI <span className="text-blue-500 font-normal">SaaS Platform</span>
            </h1>
            <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl leading-relaxed">
              Plataforma automatizada de varredura de vulnerabilidades em projetos de código (ZIP). 
              Análise Híbrida Inteligente integrando SAST, SCA e auditoria de IaC baseada em IA/ML com relatórios acionáveis (Markdown, PDF e DOCX).
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-3 text-center min-w-[110px]">
              <span className="text-xs font-mono text-zinc-500 block uppercase">Motor Core</span>
              <span className="text-sm font-mono font-bold text-emerald-400">Go + Python</span>
            </div>
            <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-3 text-center min-w-[110px]">
              <span className="text-xs font-mono text-zinc-500 block uppercase">Relatórios</span>
              <span className="text-sm font-mono font-bold text-blue-400">PDF / DOCX</span>
            </div>
            <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-3 text-center min-w-[110px]">
              <span className="text-xs font-mono text-zinc-500 block uppercase">Isolamento</span>
              <span className="text-sm font-mono font-bold text-amber-400">Zero-Trust</span>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="mt-8 pt-6 border-t border-zinc-800/80 flex items-center gap-2 overflow-x-auto no-scrollbar">
          {[
            { id: 'simulator', label: 'Simulador SaaS Scanner', icon: <UploadCloud size={14} /> },
            { id: 'architecture', label: 'Matriz Arquitetural (ADRs)', icon: <Layers size={14} /> },
            { id: 'schema', label: 'Schema PostgreSQL', icon: <Database size={14} /> },
            { id: 'security', label: 'Segurança & Zero-Trust', icon: <Lock size={14} /> },
            { id: 'finops', label: 'FinOps & Observabilidade', icon: <DollarSign size={14} /> },
            { id: 'blueprint', label: 'Código Fonte Blueprint', icon: <FileCode2 size={14} /> },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold uppercase tracking-wider transition-all whitespace-nowrap",
                activeTab === tab.id 
                  ? "bg-blue-600/10 border border-blue-500/30 text-blue-400 shadow-lg shadow-blue-500/5" 
                  : "bg-zinc-900/50 border border-zinc-800/50 text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900"
              )}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* TAB 1: SIMULATOR */}
      {activeTab === 'simulator' && (
        <div className="space-y-8 animate-in fade-in duration-300">
          {/* Sample ZIP Selection & Upload Area */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-[#121212] border border-zinc-800 rounded-2xl p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <UploadCloud className="text-blue-500" size={18} /> Upload do Pacote de Código (.ZIP)
                  </h2>
                  <p className="text-xs text-zinc-400 mt-1">
                    Selecione uma amostra de teste ou simule o envio de um arquivo de código para análise em sandbox isolada.
                  </p>
                </div>
                <Badge variant="neutral">Sandbox Efêmero</Badge>
              </div>

              {/* Sample Selector */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {sampleProjects.map(sample => (
                  <button
                    key={sample.id}
                    onClick={() => setSelectedSample(sample.id)}
                    className={cn(
                      "p-4 rounded-xl border text-left transition-all space-y-2 flex flex-col justify-between",
                      selectedSample === sample.id 
                        ? "bg-blue-500/10 border-blue-500/40 text-white" 
                        : "bg-zinc-900/50 border-zinc-800 text-zinc-400 hover:border-zinc-700"
                    )}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono font-bold text-blue-400 truncate">{sample.name}</span>
                        <span className="text-[10px] font-mono text-zinc-500">{sample.size}</span>
                      </div>
                      <p className="text-[10px] text-zinc-400 line-clamp-2">{sample.description}</p>
                    </div>
                    <div className="flex items-center justify-between pt-2 border-t border-zinc-800/50 text-[10px] font-mono">
                      <span className="text-zinc-500">{sample.lang}</span>
                      <span className="text-red-400 font-bold">{sample.vulnsCount} falhas</span>
                    </div>
                  </button>
                ))}
              </div>

              {/* Simulated Upload Drag & Drop Area */}
              <div className="border-2 border-dashed border-zinc-800 hover:border-blue-500/50 rounded-xl p-8 text-center bg-zinc-900/20 transition-all space-y-4">
                <div className="w-12 h-12 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 mx-auto flex items-center justify-center">
                  <UploadCloud size={24} />
                </div>
                <div>
                  <p className="text-xs font-mono font-bold text-zinc-200">
                    Arraste o arquivo ZIP do seu projeto aqui ou clique para selecionar
                  </p>
                  <p className="text-[10px] font-mono text-zinc-500 mt-1">
                    Suporta repositórios ZIP até 250MB (SAST + SCA + Terraform/K8s ML Rules)
                  </p>
                </div>

                <div className="pt-2">
                  <button
                    onClick={handleStartSimulatedScan}
                    disabled={isScanning}
                    className={cn(
                      "px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-bold uppercase tracking-widest rounded-xl transition-all shadow-lg flex items-center gap-2 mx-auto disabled:opacity-50",
                      isScanning && "animate-pulse"
                    )}
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="animate-spin" size={16} /> Processando Varredura...
                      </>
                    ) : (
                      <>
                        <Zap size={16} /> Iniciar Varredura VulnScan AI
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Pipeline Live Progress */}
            <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 space-y-6 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2 mb-4">
                  <Activity className="text-emerald-400" size={18} /> Live Scan Pipeline
                </h3>

                {/* Progress Bar */}
                <div className="space-y-2 mb-6">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-zinc-400">Progresso Geral</span>
                    <span className="text-blue-400 font-bold">{scanProgress}%</span>
                  </div>
                  <div className="w-full h-2 bg-zinc-900 rounded-full overflow-hidden border border-zinc-800">
                    <div 
                      className="h-full bg-gradient-to-r from-blue-500 via-emerald-400 to-emerald-500 transition-all duration-500" 
                      style={{ width: `${scanProgress}%` }}
                    />
                  </div>
                </div>

                {/* Steps List */}
                <div className="space-y-3 font-mono text-xs">
                  {[
                    { step: 1, title: 'Upload para S3 com URL Pré-Assinada', desc: 'Armazenamento seguro em bucket privado com chave KMS' },
                    { step: 2, title: 'Antivírus & Extração em Sandbox', desc: 'Varredura ClamAV e unzipper em contêiner isolado efêmero' },
                    { step: 3, title: 'Análise SAST (GoSec / Bandit / Semgrep)', desc: 'Identificação de vulnerabilidades em código fonte' },
                    { step: 4, title: 'Análise SCA (Software Composition)', desc: 'Auditoria de dependências conhecidas (CVEs/CWEs)' },
                    { step: 5, title: 'Motor IA/ML de Configurações (IaC)', desc: 'Checagem de manifestos Kubernetes e scripts Terraform' },
                    { step: 6, title: 'Geração de Relatórios (MD / PDF / DOCX)', desc: 'Síntese com PoCs acionáveis e diagramação editorial' }
                  ].map(s => {
                    const isDone = scanStep > s.step || (scanStep === 6 && s.step === 6);
                    const isCurrent = scanStep === s.step && isScanning;
                    return (
                      <div 
                        key={s.step} 
                        className={cn(
                          "p-3 rounded-xl border transition-all flex items-start gap-3",
                          isDone ? "bg-emerald-500/5 border-emerald-500/20 text-zinc-300" :
                          isCurrent ? "bg-blue-500/10 border-blue-500/40 text-blue-300 animate-pulse" :
                          "bg-zinc-900/30 border-zinc-800/50 text-zinc-600"
                        )}
                      >
                        <div className="mt-0.5">
                          {isDone ? (
                            <CheckCircle2 size={16} className="text-emerald-400" />
                          ) : isCurrent ? (
                            <RefreshCw size={16} className="text-blue-400 animate-spin" />
                          ) : (
                            <div className="w-4 h-4 rounded-full border border-zinc-700 flex items-center justify-center text-[10px] font-bold text-zinc-600">
                              {s.step}
                            </div>
                          )}
                        </div>
                        <div>
                          <p className="font-bold text-xs">{s.title}</p>
                          <p className="text-[10px] text-zinc-500 mt-0.5">{s.desc}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="pt-4 border-t border-zinc-800 text-[11px] font-mono text-zinc-500 flex items-center justify-between">
                <span>Status da Fila: RabbitMQ (Active)</span>
                <span className="text-emerald-400 font-bold">1 Workers Livres</span>
              </div>
            </div>
          </div>

          {/* Vulnerabilities Detected Section */}
          <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
              <div>
                <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <ShieldAlert className="text-red-500" size={18} /> Vulnerabilidades Identificadas ({simulatedVulnerabilities.length})
                </h2>
                <p className="text-xs text-zinc-400 mt-1">
                  Mapeamento de falhas críticas P0/P1 e vetores de risco arquiteturais com prova de conceito (PoC).
                </p>
              </div>

              <div className="flex items-center gap-2">
                <span className="px-2.5 py-1 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-xs font-mono font-bold">
                  1x P0 Crítico
                </span>
                <span className="px-2.5 py-1 bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-lg text-xs font-mono font-bold">
                  2x P1 Alto
                </span>
                <span className="px-2.5 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg text-xs font-mono font-bold">
                  1x P2 Médio
                </span>
              </div>
            </div>

            {/* Vuln Accordion / Cards */}
            <div className="space-y-4">
              {simulatedVulnerabilities.map(vuln => (
                <div key={vuln.id} className="bg-zinc-900/40 border border-zinc-800/80 rounded-xl p-5 space-y-4 hover:border-zinc-700 transition-all">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className={cn(
                        "px-2.5 py-1 rounded text-xs font-mono font-bold uppercase",
                        vuln.severity === 'P0' ? "bg-red-500 text-white" :
                        vuln.severity === 'P1' ? "bg-amber-500 text-black" : "bg-blue-500 text-white"
                      )}>
                        {vuln.severity}
                      </span>
                      <h3 className="text-sm font-mono font-bold text-white">{vuln.title}</h3>
                    </div>

                    <div className="flex items-center gap-3 text-xs font-mono text-zinc-400">
                      <span className="bg-zinc-800 px-2.5 py-1 rounded border border-zinc-700/50">{vuln.scanner}</span>
                      <span className="text-zinc-500">{vuln.cwe}</span>
                    </div>
                  </div>

                  <p className="text-xs text-zinc-300 leading-relaxed">{vuln.impact}</p>

                  <div className="text-xs font-mono text-blue-400 flex items-center gap-2">
                    <FileCode2 size={14} /> Localização: <code className="bg-zinc-900 px-2 py-0.5 rounded text-zinc-200">{vuln.filePath}:{vuln.line}</code>
                  </div>

                  {/* Code Snippet */}
                  <div className="bg-[#0a0a0a] border border-zinc-800 rounded-lg p-3 text-xs font-mono text-zinc-300 overflow-x-auto relative group">
                    <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-1">Código Afetado</div>
                    <pre className="text-red-300/90 leading-relaxed">{vuln.codeSnippet}</pre>
                  </div>

                  {/* PoC and Recommendation Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                    <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3 space-y-1">
                      <div className="text-[10px] font-mono font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Terminal size={12} /> Proof of Concept (PoC)
                      </div>
                      <code className="text-[11px] font-mono text-zinc-300 block break-all bg-black/40 p-2 rounded border border-zinc-800/50">
                        {vuln.poc}
                      </code>
                    </div>

                    <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3 space-y-1">
                      <div className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                        <CheckCircle2 size={12} /> Remediacao Recomendada
                      </div>
                      <p className="text-[11px] font-mono text-zinc-300 whitespace-pre-line leading-relaxed">
                        {vuln.recommendation}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Generated Report Previewer */}
          <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
              <div>
                <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <FileText className="text-emerald-400" size={18} /> Previsualizacao de Relatorio Gerado
                </h2>
                <p className="text-xs text-zinc-400 mt-1">
                  Formatado com regras de diagramação editorial (margens de 2.5cm, órfãs/viúvas, fontes Montserrat/Open Sans/Fira Code).
                </p>
              </div>

              <div className="flex items-center gap-2">
                {(['markdown', 'pdf', 'docx'] as const).map(fmt => (
                  <button
                    key={fmt}
                    onClick={() => setActiveReportFormat(fmt)}
                    className={cn(
                      "px-3 py-1.5 rounded-lg text-xs font-mono font-bold uppercase transition-all flex items-center gap-1.5",
                      activeReportFormat === fmt 
                        ? "bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 shadow-md" 
                        : "bg-zinc-900 border border-zinc-800 text-zinc-500 hover:text-zinc-300"
                    )}
                  >
                    <FileText size={12} /> {fmt.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {/* Document Render Area */}
            <div className="bg-[#0d0d0d] border border-zinc-800 rounded-xl p-6 md:p-8 space-y-6 max-h-[500px] overflow-y-auto font-sans">
              {/* Document Header */}
              <div className="flex justify-between items-center border-b border-zinc-800 pb-4 text-xs font-mono text-zinc-500">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-blue-500" />
                  <span className="font-bold text-zinc-300">VulnScan AI Report Engine</span>
                </div>
                <span>Data: {new Date().toLocaleDateString('pt-BR')}</span>
              </div>

              <div className="space-y-4">
                <h1 className="text-xl font-bold text-white tracking-tight font-mono">
                  Vulnerability Scan Report for {sampleProjects.find(s => s.id === selectedSample)?.name}
                </h1>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-zinc-900/50 p-4 rounded-xl border border-zinc-800 text-xs font-mono">
                  <div>
                    <span className="text-zinc-500 block">ID da Varredura</span>
                    <span className="text-zinc-200 font-bold">scan-88f2a10</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block">Total de Vulnerabilidades</span>
                    <span className="text-red-400 font-bold">4 Detectadas</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block">Criticidade Média</span>
                    <span className="text-amber-400 font-bold">P0 (Alta)</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block">Status da Exportação</span>
                    <span className="text-emerald-400 font-bold">Pronto para Download</span>
                  </div>
                </div>

                <h2 className="text-sm font-bold text-blue-400 uppercase tracking-wider font-mono pt-2">
                  Resumo Executivo
                </h2>
                <p className="text-xs text-zinc-300 leading-relaxed">
                  Este relatório detalha os achados da varredura automatizada efetuada pelo VulnScan AI no pacote do projeto selecionado. 
                  Foi identificada uma falha crítica de autorização no nível de objeto (BOLA / Subpath Traversal) permitindo vazamento de credenciais do sistema e escalada de privilégios.
                </p>

                <h2 className="text-sm font-bold text-blue-400 uppercase tracking-wider font-mono pt-2">
                  Sumário de Achados
                </h2>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono border-collapse border border-zinc-800">
                    <thead>
                      <tr className="bg-zinc-900 text-zinc-400">
                        <th className="p-2.5 border border-zinc-800">ID</th>
                        <th className="p-2.5 border border-zinc-800">Severidade</th>
                        <th className="p-2.5 border border-zinc-800">Título</th>
                        <th className="p-2.5 border border-zinc-800">Arquivo Afetado</th>
                      </tr>
                    </thead>
                    <tbody className="text-zinc-300">
                      {simulatedVulnerabilities.map(v => (
                        <tr key={v.id} className="hover:bg-zinc-900/30">
                          <td className="p-2.5 border border-zinc-800 text-blue-400">{v.id}</td>
                          <td className="p-2.5 border border-zinc-800 font-bold">{v.severity}</td>
                          <td className="p-2.5 border border-zinc-800">{v.title}</td>
                          <td className="p-2.5 border border-zinc-800 text-zinc-400">{v.filePath}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Document Footer */}
              <div className="flex justify-between items-center border-t border-zinc-800 pt-4 text-[10px] font-mono text-zinc-500">
                <span>Cliente: VulnScan Enterprise User</span>
                <span>Página 1 de 4</span>
                <span>Versão do Scanner: 1.0.4-release</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: ARCHITECTURE & ADRs */}
      {activeTab === 'architecture' && (
        <div className="space-y-8 animate-in fade-in duration-300">
          <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 md:p-8 space-y-6">
            <div>
              <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Layers className="text-blue-500" size={18} /> Matriz de Decisões Arquiteturais (ADRs)
              </h2>
              <p className="text-xs text-zinc-400 mt-1">
                Registros formais de decisões técnicas, trade-offs, motivações e impacto futuro no SaaS.
              </p>
            </div>

            {/* ADR Selector Tabs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
              {[
                { id: 'adr-001', title: 'ADR 001: Backend', sub: 'Go + Python' },
                { id: 'adr-002', title: 'ADR 002: Banco de Dados', sub: 'PostgreSQL' },
                { id: 'adr-003', title: 'ADR 003: Filas', sub: 'RabbitMQ + Redis' },
                { id: 'adr-004', title: 'ADR 004: Orquestração', sub: 'Kubernetes (K8s)' },
                { id: 'adr-005', title: 'ADR 005: Relatórios', sub: 'Pandoc + Puppeteer' },
              ].map(adr => (
                <button
                  key={adr.id}
                  onClick={() => setSelectedAdr(adr.id)}
                  className={cn(
                    "p-3 rounded-xl border text-left transition-all",
                    selectedAdr === adr.id 
                      ? "bg-blue-600/10 border-blue-500/40 text-blue-400" 
                      : "bg-zinc-900/40 border-zinc-800 text-zinc-400 hover:border-zinc-700"
                  )}
                >
                  <p className="text-xs font-mono font-bold">{adr.title}</p>
                  <p className="text-[10px] font-mono text-zinc-500">{adr.sub}</p>
                </button>
              ))}
            </div>

            {/* ADR Content Viewer */}
            <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6 space-y-4 font-mono text-xs text-zinc-300 leading-relaxed">
              {selectedAdr === 'adr-001' && (
                <div className="space-y-3">
                  <Badge variant="info">ADR 001 - Linguagem e Framework Backend</Badge>
                  <h3 className="text-sm font-bold text-white">Solução Escolhida: Go (Golang) para Core API/Workers + Python para Módulos de IA/ML</h3>
                  <p><strong className="text-blue-400">Problema:</strong> Necessidade de alta performance, concorrência nativa sem overhead de memória e suporte a bibliotecas científicas de IA.</p>
                  <p><strong className="text-emerald-400">Vantagens:</strong> Baixo consumo de memória por goroutine (&lt;2KB), suporte a chamadas concorrentes massivas de varredura e facilidade de deploy em binários únicos estáticos em contêineres.</p>
                  <p><strong className="text-amber-400">Trade-offs:</strong> Equipe precisa manter pipelines gRPC entre os serviços em Go e as ferramentas de parsing em Python.</p>
                </div>
              )}

              {selectedAdr === 'adr-002' && (
                <div className="space-y-3">
                  <Badge variant="info">ADR 002 - Banco de Dados Principal</Badge>
                  <h3 className="text-sm font-bold text-white">Solução Escolhida: PostgreSQL (com suporte a JSONB para vulnerabilidades)</h3>
                  <p><strong className="text-blue-400">Problema:</strong> Armazenar transações ACID de usuários, históricos de varredura e metadados flexíveis de relatórios.</p>
                  <p><strong className="text-emerald-400">Vantagens:</strong> Tipagem forte, tabelas relacionais com integridade referencial para tenancy e colunas JSONB para metadados dinâmicos de vulnerabilidade.</p>
                  <p><strong className="text-amber-400">Trade-offs:</strong> Requer ajuste fino de pooling de conexões (pgBouncer) sob alta concorrência.</p>
                </div>
              )}

              {selectedAdr === 'adr-003' && (
                <div className="space-y-3">
                  <Badge variant="info">ADR 003 - Fila de Mensagens Assíncrona</Badge>
                  <h3 className="text-sm font-bold text-white">Solução Escolhida: RabbitMQ (Processamento) + Redis Streams (Notificações Realtime)</h3>
                  <p><strong className="text-blue-400">Problema:</strong> Desacoplar o upload do arquivo do tempo de execução do scanner de código sem bloquear a API HTTP.</p>
                  <p><strong className="text-emerald-400">Vantagens:</strong> Garantias de entrega com ack/nack, réplicas duráveis, Dead Letter Queues (DLQ) para varreduras com erro.</p>
                  <p><strong className="text-amber-400">Trade-offs:</strong> Manutenção de dois clusters de mensageria (RabbitMQ e Redis).</p>
                </div>
              )}

              {selectedAdr === 'adr-004' && (
                <div className="space-y-3">
                  <Badge variant="info">ADR 004 - Orquestração de Contêineres</Badge>
                  <h3 className="text-sm font-bold text-white">Solução Escolhida: Managed Kubernetes Cluster (GKE / EKS)</h3>
                  <p><strong className="text-blue-400">Problema:</strong> Executar e isolar dinamicamente tarefas de varredura e geração de relatórios com autoscaling responsivo.</p>
                  <p><strong className="text-emerald-400">Vantagens:</strong> Auto-healing, isolamento de rede com NetworkPolicies e Pod Security Standards, autoscaling horizontal de pods (HPA).</p>
                  <p><strong className="text-amber-400">Trade-offs:</strong> Requer monitoramento avançado de custos e gerenciamento de imagens.</p>
                </div>
              )}

              {selectedAdr === 'adr-005' && (
                <div className="space-y-3">
                  <Badge variant="info">ADR 005 - Exportação de Documentos PDF/DOCX</Badge>
                  <h3 className="text-sm font-bold text-white">Solução Escolhida: Pandoc (para DOCX) + Puppeteer Headless (para PDF via HTML/CSS)</h3>
                  <p><strong className="text-blue-400">Problema:</strong> Gerar relatórios corporativos com precisão tipográfica editorial, regras de margem de 2.5cm, órfãs/viúvas e sumário clicável.</p>
                  <p><strong className="text-emerald-400">Vantagens:</strong> Fidelidade visual absoluta utilizando padrões CSS Paged Media e flexibilidade para Word/DOCX via Pandoc.</p>
                  <p><strong className="text-amber-400">Trade-offs:</strong> Pipeline de geração em 2 etapas com uso de Puppeteer requer recursos adicionais de memória no worker.</p>
                </div>
              )}
            </div>

            {/* Microservices C4 Context Diagram Visualizer */}
            <div className="space-y-4 pt-4 border-t border-zinc-800">
              <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Visão de Microserviços & Fluxo de Comunicação
              </h3>

              <div className="bg-black/60 border border-zinc-800 rounded-xl p-6 overflow-x-auto">
                <div className="min-w-[650px] flex items-center justify-between gap-4 font-mono text-xs">
                  <div className="p-4 bg-zinc-900 border border-zinc-700 rounded-xl text-center space-y-1">
                    <span className="text-blue-400 font-bold block">Frontend Next.js</span>
                    <span className="text-[10px] text-zinc-500">React + TS (Port 3000)</span>
                  </div>

                  <ChevronRight size={20} className="text-zinc-600 shrink-0" />

                  <div className="p-4 bg-zinc-900 border border-zinc-700 rounded-xl text-center space-y-1">
                    <span className="text-emerald-400 font-bold block">API Gateway (Go)</span>
                    <span className="text-[10px] text-zinc-500">JWT + Rate Limit (Port 8080)</span>
                  </div>

                  <ChevronRight size={20} className="text-zinc-600 shrink-0" />

                  <div className="p-4 bg-zinc-900 border border-zinc-700 rounded-xl text-center space-y-1">
                    <span className="text-amber-400 font-bold block">RabbitMQ Queue</span>
                    <span className="text-[10px] text-zinc-500">Scan & Report Tasks</span>
                  </div>

                  <ChevronRight size={20} className="text-zinc-600 shrink-0" />

                  <div className="p-4 bg-zinc-900 border border-zinc-700 rounded-xl text-center space-y-1">
                    <span className="text-purple-400 font-bold block">Scan Workers (Go/Python)</span>
                    <span className="text-[10px] text-zinc-500">Isolated Pods Sandbox</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SCHEMA */}
      {activeTab === 'schema' && (
        <div className="space-y-8 animate-in fade-in duration-300">
          <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 md:p-8 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Database className="text-blue-500" size={18} /> Esquema de Banco de Dados PostgreSQL (Relacional + JSONB)
                </h2>
                <p className="text-xs text-zinc-400 mt-1">
                  Estrutura de dados otimizada para multi-tenancy corporativo, auditoria de varreduras e rastreabilidade de relatórios.
                </p>
              </div>

              <button
                onClick={() => handleCopy(`-- Schema PostgreSQL VulnScan AI\nCREATE TABLE users (...);`, 'schema-sql')}
                className="px-3 py-1.5 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 rounded-lg text-xs font-mono flex items-center gap-1.5"
              >
                {copiedCode === 'schema-sql' ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />} Copiar SQL
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                { name: 'users', desc: 'Usuários, hashes de senha Argon2/Bcrypt, papéis RBAC e segredos MFA.' },
                { name: 'organizations', desc: 'Tenants empresariais vinculados a planos de assinatura.' },
                { name: 'scans', desc: 'Registros das tarefas de varredura, chaves S3 do ZIP e estatísticas.' },
                { name: 'vulnerabilities', desc: 'Vulnerabilidades detectadas (P0-P4), linhas, arquivos e PoCs.' },
                { name: 'reports', desc: 'Caminhos S3 para artefatos gerados em Markdown, PDF e DOCX.' },
                { name: 'audit_logs', desc: 'Logs imutáveis de ações de usuários e alterações de sistema.' }
              ].map(table => (
                <div key={table.name} className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-blue-400 uppercase">Tabela: {table.name}</span>
                    <Badge variant="neutral">PostgreSQL</Badge>
                  </div>
                  <p className="text-xs text-zinc-400 leading-relaxed">{table.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: SECURITY & ZERO-TRUST */}
      {activeTab === 'security' && (
        <div className="space-y-8 animate-in fade-in duration-300">
          <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 md:p-8 space-y-6">
            <div>
              <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Lock className="text-amber-400" size={18} /> Postura de Segurança Zero-Trust & Compliance
              </h2>
              <p className="text-xs text-zinc-400 mt-1">
                Garantias rigorosas de privacidade, criptografia de ponta a ponta e conformidade regulatória.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { title: 'JWT Atrelado ao IP do Cliente', desc: 'Tokens de acesso contêm o hash do IP do cliente e são rejeitados em tentativas de roubo de sessão.', status: 'Ativo' },
                { title: 'Criptografia mTLS Interna', desc: 'Toda comunicação inter-serviço (API -> Workers -> Database) usa certificados TLS mútuos.', status: 'Ativo' },
                { title: 'Sandboxing Efêmero de Contêineres', desc: 'Varreduras rodam em contêineres K8s isolados sem privilégios de root, destruídos após o término.', status: 'Ativo' },
                { title: 'Conformidade LGPD / GDPR', desc: 'Direito ao esquecimento com expurgo seguro de ZIPs e dados pessoais mediante solicitação.', status: 'Conforme' },
                { title: 'SOC 2 & ISO 27001 Controls', desc: 'Trilhas de auditoria imutáveis registradas na tabela audit_logs para cada ação crítica.', status: 'Conforme' },
                { title: 'URLs Pré-Assinadas de Validade Curta', desc: 'Uploads de ZIP e downloads de relatórios usam URLs do S3 com validade máxima de 15 minutos.', status: 'Ativo' }
              ].map(sec => (
                <div key={sec.title} className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-white">{sec.title}</span>
                    <span className="px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-mono rounded">
                      {sec.status}
                    </span>
                  </div>
                  <p className="text-xs text-zinc-400 leading-relaxed">{sec.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: FINOPS */}
      {activeTab === 'finops' && (
        <div className="space-y-8 animate-in fade-in duration-300">
          <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 md:p-8 space-y-6">
            <div>
              <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <DollarSign className="text-emerald-400" size={18} /> Painel FinOps & Estratégias de Otimização de Custos
              </h2>
              <p className="text-xs text-zinc-400 mt-1">
                Estimativas de recursos, autoscaling de workers para escala zero e ciclo de vida de armazenamento S3 Glacier.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-xl text-center">
                <span className="text-xs font-mono text-zinc-500 block">Custo por Varredura Estimado</span>
                <span className="text-lg font-mono font-bold text-emerald-400">$0.012 / scan</span>
              </div>
              <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-xl text-center">
                <span className="text-xs font-mono text-zinc-500 block">Autoscaling K8s (HPA)</span>
                <span className="text-lg font-mono font-bold text-blue-400">0 a 50 Pods</span>
              </div>
              <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-xl text-center">
                <span className="text-xs font-mono text-zinc-500 block">Retenção de ZIPs</span>
                <span className="text-lg font-mono font-bold text-amber-400">7 Dias (Auto-Delete)</span>
              </div>
              <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-xl text-center">
                <span className="text-xs font-mono text-zinc-500 block">SLA de Disponibilidade</span>
                <span className="text-lg font-mono font-bold text-purple-400">99.9% Uptime</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: BLUEPRINT */}
      {activeTab === 'blueprint' && (
        <div className="space-y-8 animate-in fade-in duration-300">
          <div className="bg-[#121212] border border-zinc-800 rounded-2xl p-6 md:p-8 space-y-6">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
              <div>
                <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <FileCode2 className="text-blue-500" size={18} /> Blueprint de Código e Configurações de Referência
                </h2>
                <p className="text-xs text-zinc-400 mt-1">
                  Exemplos de implementação pronta para produção do servidor Go, worker Python e esquema SQL.
                </p>
              </div>

              <button
                onClick={() => handleCopy(`.env.example content`, 'blueprint-env')}
                className="px-3 py-1.5 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 rounded-lg text-xs font-mono flex items-center gap-1.5"
              >
                {copiedCode === 'blueprint-env' ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />} Copiar Blueprint
              </button>
            </div>

            <div className="bg-[#0a0a0a] border border-zinc-800 rounded-xl p-5 font-mono text-xs text-zinc-300 overflow-x-auto">
              <div className="text-zinc-500 uppercase text-[10px] mb-2">// .env.example - Configurações Globais</div>
              <pre className="text-emerald-300/90 leading-relaxed">{`APP_ENV=production
APP_PORT=8080
JWT_SECRET=super_secret_jwt_key_replace_in_prod
DB_HOST=postgres.internal
DB_PORT=5432
DB_USER=vulnscan_user
DB_PASSWORD=vault_injected_secret
DB_NAME=vulnscan_db
AWS_S3_BUCKET_UPLOADS=vulnscan-uploads-prod
AWS_S3_BUCKET_REPORTS=vulnscan-reports-prod
RABBITMQ_HOST=rabbitmq.internal
REDIS_HOST=redis.internal`}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
