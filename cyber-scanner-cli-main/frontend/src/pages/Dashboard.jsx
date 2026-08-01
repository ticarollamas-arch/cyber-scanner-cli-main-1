import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../lib/api';
import { TID } from '../testIds';
import { formatDistanceToNow } from 'date-fns';
import { Zap, ShieldAlert, CheckCircle2, XCircle, Loader2, Activity, Trash2, FileCode2 } from 'lucide-react';

function SeverityDot({ label, count, color }) {
  return (
    <div className="flex items-center gap-2 min-w-[60px]">
      <span className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
      <span className="font-mono text-xs">
        <span className="font-bold" style={{ color }}>{count}</span>
        <span className="text-white/40 ml-1 uppercase tracking-wider text-[10px]">{label}</span>
      </span>
    </div>
  );
}

function StatusBadge({ status }) {
  if (status === 'completed') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border border-[#00ff41]/40 bg-[#00ff41]/10 text-[#00ff41] font-mono text-[10px] uppercase tracking-widest">
        <CheckCircle2 className="w-3 h-3" /> Completed
      </span>
    );
  }
  if (status === 'failed') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border border-[#ff3b30]/40 bg-[#ff3b30]/10 text-[#ff3b30] font-mono text-[10px] uppercase tracking-widest">
        <XCircle className="w-3 h-3" /> Failed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border border-[#ffb800]/40 bg-[#ffb800]/10 text-[#ffb800] font-mono text-[10px] uppercase tracking-widest">
      <Loader2 className="w-3 h-3 animate-spin" /> {status}
    </span>
  );
}

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = () =>
    api
      .get('/scans')
      .then((r) => setScans(r.data))
      .catch(() => setScans([]))
      .finally(() => setLoading(false));

  useEffect(() => {
    load();
    const iv = setInterval(load, 4000);
    return () => clearInterval(iv);
  }, []);

  const remove = async (id) => {
    if (!window.confirm('Delete scan and its data?')) return;
    await api.delete(`/scans/${id}`);
    load();
  };

  const totals = scans.reduce(
    (acc, s) => {
      acc.total++;
      if (s.status === 'completed') acc.completed++;
      acc.critical += s.counts?.CRITICAL || 0;
      acc.high += s.counts?.HIGH || 0;
      return acc;
    },
    { total: 0, completed: 0, critical: 0, high: 0 }
  );

  return (
    <div className="max-w-7xl mx-auto px-6 py-10 space-y-8">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.3em] text-[#00ff41] mb-2">
            Operations · Dashboard
          </div>
          <h1 className="text-3xl font-bold tracking-tight">Vulnerability Scans</h1>
          <p className="text-white/50 text-sm mt-1">
            Upload code archives and reproduce vulnerabilities in a sandboxed terminal.
          </p>
        </div>
        <Link
          to="/scan/new"
          data-testid={TID.dashboard.newScanBtn}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#00ff41] text-black hover:bg-white font-mono text-xs uppercase tracking-widest font-bold rounded-sm transition-colors"
        >
          <Zap className="w-4 h-4" /> New Scan
        </Link>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-0 border-t border-l border-white/8">
        <Stat testid={TID.dashboard.statsTotal} label="Total Scans" value={totals.total} accent="#f5f5f5" />
        <Stat testid={TID.dashboard.statsCompleted} label="Completed" value={totals.completed} accent="#00ff41" />
        <Stat testid={TID.dashboard.statsCritical} label="Critical Findings" value={totals.critical} accent="#ff3b30" />
        <Stat label="High Findings" value={totals.high} accent="#ffb800" />
      </div>

      <div className="border border-white/8 rounded-sm bg-[#0f0f0f] overflow-hidden">
        <div className="px-5 py-3 border-b border-white/8 flex items-center justify-between">
          <div className="font-mono text-xs uppercase tracking-widest text-white/70 flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 text-[#00ff41]" /> Scan History
          </div>
          <span className="font-mono text-[10px] text-white/40">Auto-refresh · 4s</span>
        </div>
        {loading ? (
          <div className="p-10 text-center text-white/40 font-mono text-xs">Loading...</div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center space-y-4">
            <FileCode2 className="w-8 h-8 text-white/20 mx-auto" />
            <p className="text-white/50 font-mono text-sm">No scans yet. Upload your first ZIP to begin.</p>
            <Link
              to="/scan/new"
              className="inline-flex items-center gap-2 px-4 py-2 border border-[#00ff41]/40 text-[#00ff41] hover:bg-[#00ff41]/10 font-mono text-xs uppercase tracking-widest rounded-sm transition-colors"
            >
              <Zap className="w-3 h-3" /> Start Scan
            </Link>
          </div>
        ) : (
          <ul className="divide-y divide-white/5">
            {scans.map((s) => (
              <li
                key={s.id}
                data-testid={TID.dashboard.scanCard(s.id)}
                className="hover:bg-white/[0.02] transition-colors"
              >
                <div className="px-5 py-4 flex flex-col md:flex-row md:items-center gap-4">
                  <div className="flex-1 min-w-0">
                    <Link
                      to={`/scan/${s.id}`}
                      className="font-mono text-sm font-bold hover:text-[#00ff41] transition-colors truncate block"
                    >
                      {s.project_name}
                    </Link>
                    <div className="font-mono text-[10px] text-white/40 uppercase tracking-widest mt-1">
                      {s.filename} · {formatDistanceToNow(new Date(s.created_at), { addSuffix: true })}
                    </div>
                  </div>

                  {s.status !== 'completed' && s.status !== 'failed' && (
                    <div className="w-full md:w-40">
                      <div className="h-1 bg-white/8 rounded-full relative overflow-hidden">
                        <div
                          className="h-full bg-[#00ff41] transition-all"
                          style={{ width: `${s.progress || 0}%` }}
                        />
                        <div className="scanning-bar" />
                      </div>
                      <div className="text-[10px] font-mono text-white/40 mt-1 uppercase tracking-widest">
                        {s.current_step || 'queued'} · {s.progress || 0}%
                      </div>
                    </div>
                  )}

                  <div className="flex items-center gap-4">
                    <SeverityDot label="C" count={s.counts?.CRITICAL || 0} color="#ff3b30" />
                    <SeverityDot label="H" count={s.counts?.HIGH || 0} color="#ffb800" />
                    <SeverityDot label="M" count={s.counts?.MEDIUM || 0} color="#007aff" />
                    <SeverityDot label="L" count={s.counts?.LOW || 0} color="#8e8e93" />
                  </div>

                  <StatusBadge status={s.status} />

                  <button
                    onClick={() => remove(s.id)}
                    className="w-8 h-8 rounded-sm border border-white/10 text-white/40 hover:text-[#ff3b30] hover:border-[#ff3b30]/40 flex items-center justify-center transition-colors"
                    title="Delete"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, accent, testid }) {
  return (
    <div
      data-testid={testid}
      className="p-5 border-r border-b border-white/8 relative"
      style={{ background: `linear-gradient(180deg, ${accent}05 0%, transparent 100%)` }}
    >
      <div className="font-mono text-[10px] uppercase tracking-[0.25em] text-white/50">{label}</div>
      <div className="font-mono text-3xl font-bold mt-1" style={{ color: accent }}>
        {value}
      </div>
    </div>
  );
}
