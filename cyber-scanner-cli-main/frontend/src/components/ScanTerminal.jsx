import { useEffect, useRef, useState } from 'react';
import api from '../lib/api';
import { TID } from '../testIds';
import { Loader2, Play, CornerDownLeft, Trash2 } from 'lucide-react';

const PRESETS = [
  { label: 'ls -la', cmd: 'ls -la' },
  { label: 'tree', cmd: 'find . -type f -not -path "*/node_modules/*" -not -path "*/.git/*" | head -30' },
  { label: 'cat pkg', cmd: 'cat package.json 2>/dev/null || cat requirements.txt 2>/dev/null || echo "No pkg file"' },
  { label: 'grep secrets', cmd: 'grep -RIn --include="*.py" --include="*.js" --include="*.env" -E "(api_key|secret|token|password)" . | head -20' },
];

// Very small ANSI color parser (foreground true-color + reset)
function ansiToSpans(text) {
  const parts = [];
  let idx = 0;
  let currentStyle = null;
  const re = /\x1b\[([\d;]*)m/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > idx) {
      parts.push({ text: text.slice(idx, m.index), style: currentStyle });
    }
    const code = m[1];
    if (code === '' || code === '0') {
      currentStyle = null;
    } else if (code.startsWith('38;2;')) {
      const [, , , r, g, b] = code.split(';');
      currentStyle = { color: `rgb(${r},${g},${b})` };
    } else if (code === '31') currentStyle = { color: '#ff3b30' };
    else if (code === '32') currentStyle = { color: '#00ff41' };
    else if (code === '33') currentStyle = { color: '#ffb800' };
    else if (code === '34') currentStyle = { color: '#007aff' };
    else if (code === '36') currentStyle = { color: '#00e5ff' };
    else if (code === '37') currentStyle = { color: '#e5e5e5' };
    idx = m.index + m[0].length;
  }
  if (idx < text.length) {
    parts.push({ text: text.slice(idx), style: currentStyle });
  }
  return parts;
}

const BANNER_LINES = [
  { text: 'VulnScan.AI · Sandboxed Terminal', style: { color: '#00ff41', fontWeight: 700 } },
  { text: 'Type commands to reproduce vulnerabilities inside this scan workspace.', style: { color: '#8e8e93' } },
  { text: 'Try: ls -la · cat file.py · curl · python3 · node · grep · git', style: { color: '#8e8e93' } },
  { text: '─'.repeat(60), style: { color: '#00ff4160' } },
];

export default function ScanTerminal({ scanId }) {
  const [lines, setLines] = useState(BANNER_LINES);
  const [cmd, setCmd] = useState('');
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState([]);
  const [histIdx, setHistIdx] = useState(-1);
  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [lines]);

  useEffect(() => {
    // Focus terminal input when this component is shown
    inputRef.current?.focus();
  }, []);

  const appendLine = (line) => setLines((ls) => [...ls, line]);

  const runCommand = async (raw) => {
    const command = raw.trim();
    if (!command) return;
    setBusy(true);
    setHistory((h) => [command, ...h].slice(0, 50));
    setHistIdx(-1);
    appendLine({ text: `$ ${command}`, style: { color: '#00ff41', fontWeight: 600 } });
    try {
      const { data } = await api.post(`/scans/${scanId}/terminal`, { command });
      if (data.stdout) {
        data.stdout.split('\n').forEach((l, i, arr) => {
          if (i === arr.length - 1 && l === '') return;
          appendLine({ text: l || ' ', style: { color: '#e5e5e5' } });
        });
      }
      if (data.stderr) {
        data.stderr.split('\n').forEach((l, i, arr) => {
          if (i === arr.length - 1 && l === '') return;
          appendLine({ text: l || ' ', style: { color: '#ff3b30' } });
        });
      }
      const meta = `[exit ${data.returncode} · ${data.duration_ms}ms]`;
      appendLine({
        text: meta,
        style: { color: data.returncode === 0 ? '#8e8e93' : '#ff3b30', fontSize: 11 },
      });
    } catch (err) {
      appendLine({
        text: `Error: ${err?.response?.data?.detail || err.message}`,
        style: { color: '#ff3b30' },
      });
    } finally {
      setBusy(false);
      setCmd('');
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  };

  const injectPoc = (cmdText) => {
    runCommand(cmdText);
  };

  useEffect(() => {
    window.__vulnscan_terminal_inject = injectPoc;
    return () => { delete window.__vulnscan_terminal_inject; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !busy) {
      e.preventDefault();
      runCommand(cmd);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length && histIdx < history.length - 1) {
        const ni = histIdx + 1;
        setHistIdx(ni);
        setCmd(history[ni]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (histIdx > 0) {
        const ni = histIdx - 1;
        setHistIdx(ni);
        setCmd(history[ni]);
      } else {
        setHistIdx(-1);
        setCmd('');
      }
    } else if (e.key === 'l' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      setLines(BANNER_LINES);
    }
  };

  const clear = () => setLines(BANNER_LINES);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {PRESETS.map((p, i) => (
          <button
            key={p.label}
            data-testid={TID.terminal.presetBtn(i)}
            onClick={() => runCommand(p.cmd)}
            disabled={busy}
            className="px-3 py-1.5 rounded-sm border border-white/10 hover:border-[#00ff41]/40 hover:text-[#00ff41] font-mono text-[10px] uppercase tracking-widest transition-colors disabled:opacity-50"
          >
            <Play className="w-3 h-3 inline mr-1" /> {p.label}
          </button>
        ))}
        <button
          onClick={clear}
          className="px-3 py-1.5 rounded-sm border border-white/10 hover:border-[#ff3b30]/40 hover:text-[#ff3b30] font-mono text-[10px] uppercase tracking-widest transition-colors ml-auto"
        >
          <Trash2 className="w-3 h-3 inline mr-1" /> Clear
        </button>
        {busy && (
          <span className="flex items-center gap-2 text-[#00ff41] font-mono text-[10px] uppercase tracking-widest">
            <Loader2 className="w-3 h-3 animate-spin" /> Executing...
          </span>
        )}
      </div>

      <div
        data-testid={TID.terminal.container}
        className="border border-[#00ff41]/30 bg-[#050505] rounded-sm p-4 glow-matrix font-mono text-[12px] leading-relaxed overflow-y-auto"
        style={{ height: 420 }}
        onClick={() => inputRef.current?.focus()}
      >
        {lines.map((l, i) => (
          <div key={i} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', ...(l.style || {}) }}>
            {l.text}
          </div>
        ))}
        <div className="flex items-center" ref={bottomRef}>
          <span className="text-[#00ff41] mr-2">$</span>
          <input
            ref={inputRef}
            type="text"
            value={cmd}
            onChange={(e) => setCmd(e.target.value)}
            onKeyDown={onKeyDown}
            disabled={busy}
            data-testid={TID.terminal.input}
            placeholder={busy ? 'Executing...' : 'Type a command and press Enter'}
            className="flex-1 bg-transparent outline-none font-mono text-[12px] text-white placeholder-white/25 caret-[#00ff41]"
            autoComplete="off"
            spellCheck="false"
          />
          {!busy && <span className="text-[#00ff41] animate-pulse ml-1">▊</span>}
        </div>
      </div>

      <div className="flex items-center justify-between font-mono text-[10px] text-white/40 uppercase tracking-widest">
        <span>Sandboxed to /app/workspace/{scanId.slice(0, 8)}/src · 30s timeout</span>
        <span className="flex items-center gap-1.5">
          <CornerDownLeft className="w-3 h-3" /> Enter to run · ↑↓ history · Ctrl+L clear
        </span>
      </div>
    </div>
  );
}
