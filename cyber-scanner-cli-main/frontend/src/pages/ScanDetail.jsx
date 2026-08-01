import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api, { API } from '../lib/api';
import ScanTerminal from '../components/ScanTerminal';
import { TID } from '../testIds';
import {
  ArrowLeft, Terminal as TerminalIcon, ShieldAlert, FileText, Loader2, Sparkles,
  CheckCircle2, XCircle, Copy, Check, Play, FileCode2, Bug, Download,
} from 'lucide-react';

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function SevBadge({ level, priority }) {
  const cls = {
    CRITICAL: 'sev-CRITICAL pulse-crimson',
    HIGH: 'sev-HIGH',
    MEDIUM: 'sev-MEDIUM',
    LOW: 'sev-LOW',
    INFO: 'sev-INFO',
  }[level] || 'sev-LOW';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border font-mono text-[10px] font-bold uppercase tracking-widest ${cls}`}>
      {priority ? `${priority} · ` : ''}{level}
    </span>
  );
}

function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="w-7 h-7 flex items-center justify-center rounded-sm border border-white/10 hover:border-[#00ff41]/40 hover:text-[#00ff41] transition-colors"
      title="Copy"
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

function VulnCard({ v, onAnalyze, onRunInTerminal, analyzing }) {
  const [open, setOpen] = useState(false);
  const ai = v.ai_analysis;

  return (
    <div
      data-testid={TID.scan.vulnRow(v.id)}
      className="border border-white/10 rounded-sm bg-[#0f0f0f] hover:border-white/20 transition-colors"
    >
      <button
        onClick={() => setOpen((s) => !s)}
        className="w-full text-left p-5 flex flex-col md:flex-row md:items-start gap-4"
      >
        <SevBadge level={v.severity} priority={v.priority} />
        <div className="flex-1 min-w-0">
          <div className="font-mono text-sm font-bold truncate">{v.title}</div>
          <div className="font-mono text-[10px] text-white/40 mt-1 uppercase tracking-widest flex flex-wrap gap-3">
            <span>{v.scanner}</span>
            <span>·</span>
            <span className="truncate">{v.file_path}:{v.line_start}</span>
            {v.cwe && <><span>·</span><span>{v.cwe}</span></>}
          </div>
        </div>
        <span className="font-mono text-[10px] uppercase tracking-widest text-white/40">
          {open ? '▲ Collapse' : '▼ Expand'}
        </span>
      </button>

      {open && (
        <div className="border-t border-white/8 p-5 space-y-4">
          {v.description && (
            <Section title="Description">
              <p className="text-white/70 text-sm whitespace-pre-wrap">{v.description}</p>
            </Section>
          )}

          {v.code_snippet && (
            <Section title="Code snippet">
              <pre className="bg-black border border-white/10 rounded-sm p-3 text-xs font-mono text-[#ff3b30]/90 overflow-x-auto">{v.code_snippet}</pre>
            </Section>
          )}

          {ai ? (
            <>
              {ai.impact && (
                <Section title="Impact">
                  <p className="text-white/80 text-sm">{ai.impact}</p>
                </Section>
              )}
              {ai.root_cause && (
                <Section title="Root cause">
                  <p className="text-white/80 text-sm">{ai.root_cause}</p>
                </Section>
              )}
              {ai.attack_vector && (
                <Section title="Attack vector">
                  <pre className="text-white/80 text-sm whitespace-pre-wrap font-mono">{ai.attack_vector}</pre>
                </Section>
              )}
              {ai.poc_commands?.length > 0 && (
                <Section title="Proof of Concept · Reproducible">
                  <div className="space-y-2">
                    {ai.poc_commands.map((c) => (
                      <div key={c.step} className="border border-white/10 bg-black rounded-sm p-3 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <div className="font-mono text-[10px] uppercase tracking-widest text-[#00ff41]">
                            Step {c.step}: {c.description}
                          </div>
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => onRunInTerminal(c.command)}
                              className="px-2 py-1 rounded-sm bg-[#00ff41] text-black hover:bg-white font-mono text-[10px] uppercase tracking-widest font-bold transition-colors flex items-center gap-1"
                              title="Run in embedded terminal"
                            >
                              <Play className="w-2.5 h-2.5" /> Run
                            </button>
                            <CopyBtn text={c.command} />
                          </div>
                        </div>
                        <pre className="text-sm font-mono text-white/90 whitespace-pre-wrap break-all">{c.command}</pre>
                        {c.expected_output && (
                          <div className="font-mono text-[10px] text-white/40 pt-1">
                            Expected: <span className="text-[#00ff41]">{c.expected_output}</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </Section>
              )}
              {ai.remediation && (
                <Section title="Remediation">
                  <p className="text-white/80 text-sm whitespace-pre-wrap">{ai.remediation}</p>
                </Section>
              )}
              {ai.patch_diff && (
                <Section title="Patch diff">
                  <pre className="bg-black border border-white/10 rounded-sm p-3 text-xs font-mono overflow-x-auto whitespace-pre-wrap">{ai.patch_diff}</pre>
                </Section>
              )}
            </>
          ) : (
            <div className="p-4 border border-white/10 rounded-sm bg-black flex items-center justify-between gap-4">
              <div className="text-white/60 text-sm">
                <span className="font-mono text-[10px] uppercase tracking-widest text-[#00ff41] block mb-1">
                  AI enrichment
                </span>
                No AI analysis yet. Generate reproducible PoC + remediation with Claude Sonnet 4.5.
              </div>
              <button
                onClick={() => onAnalyze(v.id)}
                disabled={analyzing}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-sm bg-[#00ff41] text-black hover:bg-white font-mono text-[10px] uppercase tracking-widest font-bold transition-colors disabled:opacity-60"
              >
                {analyzing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                Analyze
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <div className="font-mono text-[10px] uppercase tracking-[0.25em] text-[#00ff41] mb-2">
        {title}
      </div>
      {children}
    </div>
  );
}

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [vulns, setVulns] = useState([]);
  const [tab, setTab] = useState('overview');
  const [analyzing, setAnalyzing] = useState('');
  const [loading, setLoading] = useState(true);

  const loadScan = async () => {
    try {
      const { data } = await api.get(`/scans/${id}`);
      setScan(data);
    } catch (e) {
      console.error('Failed to load scan', e);
    }
  };
  const loadVulns = async () => {
    try {
      const { data } = await api.get(`/scans/${id}/vulnerabilities`);
      setVulns(data);
    } catch (e) {
      console.error('Failed to load vulnerabilities', e);
    }
    setLoading(false);
  };

  useEffect(() => {
    setLoading(true);
    loadScan();
    loadVulns();
    const iv = setInterval(() => {
      loadScan();
      if (scan?.status !== 'completed' && scan?.status !== 'failed') loadVulns();
    }, 4000);
    return () => clearInterval(iv);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const onAnalyze = async (vulnId) => {
    setAnalyzing(vulnId);
    try {
      await api.post(`/scans/${id}/vulnerabilities/${vulnId}/analyze`);
      await loadVulns();
    } finally {
      setAnalyzing('');
    }
  };

  const onRunInTerminal = (cmd) => {
    setTab('terminal');
    setTimeout(() => {
      if (typeof window.__vulnscan_terminal_inject === 'function') {
        window.__vulnscan_terminal_inject(cmd);
      }
    }, 300);
  };

  const downloadPdf = async () => {
    const token = localStorage.getItem('vulnscan_token');
    const url = `${API}/scans/${id}/report.pdf`;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `vulnscan-${id.slice(0, 8)}.pdf`;
    a.click();
  };

  const downloadMd = async () => {
    const token = localStorage.getItem('vulnscan_token');
    const url = `${API}/scans/${id}/report.md`;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `vulnscan-${id.slice(0, 8)}.md`;
    a.click();
  };

  if (loading || !scan) {
    return (
      <div className="max-w-7xl mx-auto px-6 py-16 text-center">
        <Loader2 className="w-6 h-6 animate-spin text-[#00ff41] mx-auto mb-3" />
        <div className="font-mono text-xs uppercase tracking-widest text-white/50">Loading scan...</div>
      </div>
    );
  }

  const counts = scan.counts || {};
  const running = scan.status !== 'completed' && scan.status !== 'failed';

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
      <Link
        to="/dashboard"
        className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-white/50 hover:text-[#00ff41] transition-colors"
      >
        <ArrowLeft className="w-3 h-3" /> Back to dashboard
      </Link>

      <div className="border border-white/10 bg-[#0f0f0f] rounded-sm p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-2">
          <div className="font-mono text-[10px] uppercase tracking-[0.3em] text-[#00ff41]">
            Scan · {scan.id.slice(0, 8)}
          </div>
          <h1 className="text-2xl font-bold tracking-tight">{scan.project_name}</h1>
          <div className="font-mono text-[10px] text-white/40 uppercase tracking-widest">
            {scan.filename} · created {new Date(scan.created_at).toLocaleString()}
          </div>
        </div>

        <div className="flex flex-col justify-between gap-3">
          <div className="grid grid-cols-4 gap-2">
            <MiniStat label="Crit" value={counts.CRITICAL || 0} color="#ff3b30" />
            <MiniStat label="High" value={counts.HIGH || 0} color="#ffb800" />
            <MiniStat label="Med" value={counts.MEDIUM || 0} color="#007aff" />
            <MiniStat label="Low" value={counts.LOW || 0} color="#8e8e93" />
          </div>
          {running && (
            <div className="space-y-1">
              <div className="h-1.5 bg-white/8 rounded-full relative overflow-hidden">
                <div className="h-full bg-[#00ff41] transition-all" style={{ width: `${scan.progress || 0}%` }} />
                <div className="scanning-bar" />
              </div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-white/40 flex justify-between">
                <span className="text-[#00ff41]">{scan.current_step || 'queued'}</span>
                <span>{scan.progress || 0}%</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap items-center gap-1 border-b border-white/8">
        <Tab id="overview" tab={tab} setTab={setTab} testid={TID.scan.tabOverview}>
          <FileCode2 className="w-3.5 h-3.5" /> Overview
        </Tab>
        <Tab id="vulns" tab={tab} setTab={setTab} testid={TID.scan.tabVulns}>
          <Bug className="w-3.5 h-3.5" /> Vulnerabilities ({vulns.length})
        </Tab>
        <Tab id="terminal" tab={tab} setTab={setTab} testid={TID.scan.tabTerminal}>
          <TerminalIcon className="w-3.5 h-3.5" /> Terminal
        </Tab>
        <Tab id="report" tab={tab} setTab={setTab} testid={TID.scan.tabReport}>
          <FileText className="w-3.5 h-3.5" /> Report
        </Tab>
      </div>

      {tab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="border border-white/10 rounded-sm bg-[#0f0f0f] p-5 space-y-4">
            <div className="font-mono text-[10px] uppercase tracking-[0.25em] text-[#00ff41]">
              Scanner pipeline log
            </div>
            <ul className="space-y-2 max-h-96 overflow-y-auto pr-2">
              {(scan.scanner_log || []).map((l, i) => (
                <li key={`${l.ts}-${l.step}-${i}`} className="flex items-start gap-3 text-xs font-mono">
                  <span className="text-white/30 shrink-0 mt-0.5">
                    {new Date(l.ts).toLocaleTimeString()}
                  </span>
                  <span className="px-2 py-0.5 rounded-sm bg-white/5 border border-white/10 text-[#00ff41] uppercase tracking-widest text-[10px] shrink-0">
                    {l.step}
                  </span>
                  <span className="text-white/70">{l.message}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="border border-white/10 rounded-sm bg-[#0f0f0f] p-5 space-y-4">
            <div className="font-mono text-[10px] uppercase tracking-[0.25em] text-[#00ff41]">
              Severity breakdown
            </div>
            <SeverityChart counts={counts} total={vulns.length} />
            <div className="pt-4 border-t border-white/8 flex flex-wrap gap-3">
              <button
                data-testid={TID.scan.downloadPdf}
                onClick={downloadPdf}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-sm bg-[#00ff41] text-black hover:bg-white font-mono text-[10px] uppercase tracking-widest font-bold transition-colors"
              >
                <Download className="w-3 h-3" /> PDF
              </button>
              <button
                data-testid={TID.scan.downloadMd}
                onClick={downloadMd}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-sm border border-white/15 hover:border-[#00ff41]/40 font-mono text-[10px] uppercase tracking-widest transition-colors"
              >
                <Download className="w-3 h-3" /> Markdown
              </button>
            </div>
          </div>
        </div>
      )}

      {tab === 'vulns' && (
        <div className="space-y-3">
          {vulns.length === 0 ? (
            <div className="border border-white/10 rounded-sm bg-[#0f0f0f] p-10 text-center">
              {running ? (
                <>
                  <Loader2 className="w-6 h-6 animate-spin text-[#00ff41] mx-auto mb-3" />
                  <div className="font-mono text-xs uppercase tracking-widest text-white/50">
                    Scanning in progress · {scan.current_step}
                  </div>
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-8 h-8 text-[#00ff41] mx-auto mb-3" />
                  <div className="font-mono text-sm">No vulnerabilities detected.</div>
                </>
              )}
            </div>
          ) : (
            vulns.map((v) => (
              <VulnCard
                key={v.id}
                v={v}
                onAnalyze={onAnalyze}
                onRunInTerminal={onRunInTerminal}
                analyzing={analyzing === v.id}
              />
            ))
          )}
        </div>
      )}

      {tab === 'terminal' && <ScanTerminal scanId={id} />}

      {tab === 'report' && (
        <div className="border border-white/10 rounded-sm bg-[#0f0f0f] p-6 space-y-4">
          <div className="font-mono text-[10px] uppercase tracking-[0.3em] text-[#00ff41]">
            Executive report
          </div>
          <h2 className="text-xl font-bold">Assessment Report · {scan.project_name}</h2>
          <p className="text-white/60 text-sm">
            Download the full assessment. Includes summary, per-finding root cause, reproducible PoC and remediation.
          </p>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={downloadPdf}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-sm bg-[#00ff41] text-black hover:bg-white font-mono text-xs uppercase tracking-widest font-bold transition-colors"
            >
              <Download className="w-4 h-4" /> Download PDF
            </button>
            <button
              onClick={downloadMd}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-sm border border-white/15 hover:border-[#00ff41]/40 font-mono text-xs uppercase tracking-widest transition-colors"
            >
              <Download className="w-4 h-4" /> Download Markdown
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Tab({ id, tab, setTab, testid, children }) {
  const active = tab === id;
  return (
    <button
      data-testid={testid}
      onClick={() => setTab(id)}
      className={`inline-flex items-center gap-2 px-4 py-2.5 font-mono text-[10px] uppercase tracking-widest transition-colors border-b-2 -mb-px ${
        active
          ? 'text-[#00ff41] border-[#00ff41]'
          : 'text-white/50 border-transparent hover:text-white'
      }`}
    >
      {children}
    </button>
  );
}

function MiniStat({ label, value, color }) {
  return (
    <div className="p-2 rounded-sm border border-white/8 text-center" style={{ background: `${color}08` }}>
      <div className="font-mono text-lg font-bold" style={{ color }}>{value}</div>
      <div className="font-mono text-[9px] uppercase tracking-widest text-white/50">{label}</div>
    </div>
  );
}

function SeverityChart({ counts, total }) {
  const items = [
    { label: 'Critical', v: counts.CRITICAL || 0, c: '#ff3b30' },
    { label: 'High', v: counts.HIGH || 0, c: '#ffb800' },
    { label: 'Medium', v: counts.MEDIUM || 0, c: '#007aff' },
    { label: 'Low', v: counts.LOW || 0, c: '#8e8e93' },
  ];
  const max = Math.max(1, ...items.map((i) => i.v), total);
  return (
    <div className="space-y-2">
      {items.map((i) => (
        <div key={i.label} className="flex items-center gap-3">
          <div className="w-16 font-mono text-[10px] uppercase tracking-widest text-white/60">
            {i.label}
          </div>
          <div className="flex-1 h-2 bg-white/5 rounded-sm overflow-hidden">
            <div className="h-full transition-all" style={{ width: `${(i.v / max) * 100}%`, background: i.c }} />
          </div>
          <div className="font-mono text-xs font-bold w-8 text-right" style={{ color: i.c }}>
            {i.v}
          </div>
        </div>
      ))}
    </div>
  );
}
