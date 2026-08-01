import { Link } from 'react-router-dom';
import { TID } from '../testIds';
import { Terminal, ShieldAlert, Zap, FileText, Cpu, Bug, Layers, Code2, Lock, Activity } from 'lucide-react';

const scanners = [
  { name: 'Semgrep', desc: 'Multi-language SAST · 30K+ rules · SAST', color: '#00ff41' },
  { name: 'Bandit', desc: 'Python security linter · CWE-mapped', color: '#00e5ff' },
  { name: 'Gitleaks', desc: 'Secrets & credentials scanner', color: '#ffb800' },
  { name: 'IaC Rules', desc: 'Kubernetes · Docker · Terraform hardening', color: '#ff3b30' },
  { name: 'SCA Engine', desc: 'CVE detection across npm & PyPI', color: '#a78bfa' },
  { name: 'Claude Sonnet 4.5', desc: 'AI-generated reproducible PoC + patches', color: '#00ff41' },
];

export default function LandingPage() {
  return (
    <div className="relative">
      {/* Hero */}
      <section className="relative overflow-hidden grid-bg">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-black/40 to-[#0a0a0a] pointer-events-none" />
        <div className="relative max-w-7xl mx-auto px-6 pt-20 pb-24 grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-sm border border-[#00ff41]/30 bg-[#00ff41]/5 font-mono text-[10px] uppercase tracking-[0.25em] text-[#00ff41]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00ff41] pulse-matrix" />
              Realtime · Reproducible · Zero-Trust
            </div>
            <h1 className="text-5xl md:text-6xl font-bold tracking-tight leading-[1.05]">
              Real vulnerabilities.<br />
              <span className="text-[#00ff41]">Reproducible</span> proof.<br />
              <span className="text-white/40">One terminal away.</span>
            </h1>
            <p className="text-white/70 text-lg leading-relaxed max-w-2xl">
              VulnScan.AI ingests your source code, runs a full pipeline of real security scanners
              (Semgrep, Bandit, Gitleaks, IaC, SCA), and generates reproducible proof-of-concept
              exploits — executable directly from an embedded terminal in your browser.
            </p>
            <div className="flex flex-wrap items-center gap-4 pt-4">
              <Link
                to="/register"
                data-testid={TID.landing.ctaGetStarted}
                className="group inline-flex items-center gap-2 px-6 py-3 bg-[#00ff41] text-black font-mono text-xs uppercase tracking-widest font-bold rounded-sm hover:bg-white transition-colors"
              >
                <Zap className="w-4 h-4" />
                Start Scanning
                <span className="opacity-40 group-hover:translate-x-1 transition-transform">→</span>
              </Link>
              <a
                href="#pipeline"
                data-testid={TID.landing.ctaLearnMore}
                className="inline-flex items-center gap-2 px-6 py-3 border border-white/15 hover:border-[#00ff41]/50 font-mono text-xs uppercase tracking-widest rounded-sm transition-colors"
              >
                <Terminal className="w-4 h-4" />
                Watch The Pipeline
              </a>
            </div>

            <div className="grid grid-cols-3 gap-4 pt-8 border-t border-white/8 mt-8 max-w-xl">
              <div>
                <div className="font-mono text-2xl font-bold text-[#00ff41]">6</div>
                <div className="font-mono text-[10px] uppercase tracking-widest text-white/50">Scanners</div>
              </div>
              <div>
                <div className="font-mono text-2xl font-bold">30K+</div>
                <div className="font-mono text-[10px] uppercase tracking-widest text-white/50">SAST Rules</div>
              </div>
              <div>
                <div className="font-mono text-2xl font-bold">AI</div>
                <div className="font-mono text-[10px] uppercase tracking-widest text-white/50">Reproducible PoC</div>
              </div>
            </div>
          </div>

          {/* Fake terminal preview */}
          <div className="lg:col-span-5">
            <div className="relative rounded-sm border border-[#00ff41]/30 bg-[#050505] glow-matrix overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-2 border-b border-white/8 bg-black">
                <span className="w-2.5 h-2.5 rounded-full bg-[#ff3b30]" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#ffb800]" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#00ff41]" />
                <span className="ml-3 font-mono text-[10px] uppercase tracking-widest text-white/50">
                  vulnscan · scan-88f2a10 · terminal
                </span>
              </div>
              <div className="p-5 font-mono text-[12px] leading-relaxed">
                <div className="text-[#00ff41]">$ vulnscan upload project.zip</div>
                <div className="text-white/60 mt-1">[✓] Extracted 234 files (blocked 0)</div>
                <div className="text-white/60">[✓] Semgrep: 12 findings</div>
                <div className="text-white/60">[✓] Bandit: 3 findings</div>
                <div className="text-white/60">[✓] Gitleaks: 2 secrets exposed</div>
                <div className="text-white/60">[✓] IaC: 4 misconfigurations</div>
                <div className="text-white/60">[✓] SCA: 3 known CVEs</div>
                <div className="text-[#ffb800] mt-2">
                  → AI enriching top 8 findings with PoC...
                </div>
                <div className="text-[#00ff41] mt-2">[+] Report ready · 24 findings</div>
                <div className="mt-3 text-white/40">$ curl -X POST /api/download?f=../../../etc/passwd</div>
                <div className="text-[#ff3b30]">root:x:0:0:root:/root:/bin/bash</div>
                <div className="text-[#ff3b30]">daemon:x:1:1:daemon:/usr/sbin:...</div>
                <div className="text-[#00ff41] mt-2">
                  <span>_</span>
                  <span className="blink-cursor" />
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Pipeline */}
      <section id="pipeline" className="border-t border-white/8 bg-black py-20">
        <div className="max-w-7xl mx-auto px-6">
          <div className="mb-12 max-w-2xl">
            <div className="font-mono text-[10px] uppercase tracking-[0.3em] text-[#00ff41] mb-3">01 · Pipeline</div>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">
              A tactical assembly of scanners, orchestrated in seconds.
            </h2>
            <p className="text-white/60">
              No fake UI. No mocked data. Every scanner is real, every command reproducible.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-0 border-t border-l border-white/8">
            {scanners.map((s) => (
              <div
                key={s.name}
                className="p-6 border-r border-b border-white/8 relative group hover:bg-white/[0.02] transition-colors"
              >
                <div className="flex items-center justify-between mb-4">
                  <div
                    className="w-10 h-10 rounded-sm border flex items-center justify-center"
                    style={{ borderColor: s.color + '40', background: s.color + '10' }}
                  >
                    <Cpu className="w-5 h-5" style={{ color: s.color }} />
                  </div>
                  <span className="font-mono text-[10px] uppercase tracking-widest text-white/30">Active</span>
                </div>
                <div className="font-mono text-lg font-bold">{s.name}</div>
                <div className="text-white/60 text-sm mt-1">{s.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-6 grid grid-cols-1 md:grid-cols-3 gap-8">
          <FeatureCard
            icon={<Terminal className="w-6 h-6" />}
            title="Real embedded terminal"
            body="xterm.js terminal wired to a sandboxed workspace per scan. Reproduce every PoC without leaving your browser."
          />
          <FeatureCard
            icon={<Bug className="w-6 h-6" />}
            title="AI proof-of-concept"
            body="Claude Sonnet 4.5 turns every critical finding into a step-by-step reproducible exploit with expected outputs."
          />
          <FeatureCard
            icon={<FileText className="w-6 h-6" />}
            title="Executive reports"
            body="Export PDF and Markdown reports with severity summary, CWE, patch diffs and reproduction instructions."
          />
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-white/8 py-20 bg-gradient-to-b from-black to-[#0a0a0a]">
        <div className="max-w-4xl mx-auto px-6 text-center space-y-6">
          <ShieldAlert className="w-10 h-10 text-[#00ff41] mx-auto" />
          <h2 className="text-3xl md:text-4xl font-bold tracking-tight">
            Stop reading vulnerability lists.<br /> Start reproducing them.
          </h2>
          <p className="text-white/60 max-w-2xl mx-auto">
            Create an account, upload your first ZIP, and watch the pipeline run in real time.
          </p>
          <Link
            to="/register"
            className="inline-flex items-center gap-2 px-8 py-3 bg-[#00ff41] text-black font-mono text-xs uppercase tracking-widest font-bold rounded-sm hover:bg-white transition-colors"
          >
            <Zap className="w-4 h-4" /> Get Started Free
          </Link>
        </div>
      </section>
    </div>
  );
}

function FeatureCard({ icon, title, body }) {
  return (
    <div className="p-6 border border-white/8 rounded-sm bg-[#0f0f0f] hover:border-[#00ff41]/30 transition-colors">
      <div className="w-10 h-10 rounded-sm bg-[#00ff41]/10 border border-[#00ff41]/30 flex items-center justify-center text-[#00ff41] mb-4">
        {icon}
      </div>
      <div className="font-mono text-lg font-bold mb-2">{title}</div>
      <div className="text-white/60 text-sm leading-relaxed">{body}</div>
    </div>
  );
}
