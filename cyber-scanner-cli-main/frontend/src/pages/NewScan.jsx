import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../lib/api';
import { TID } from '../testIds';
import { UploadCloud, Loader2, FileCode2, Zap } from 'lucide-react';

export default function NewScan() {
  const [projectName, setProjectName] = useState('');
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);
  const fileRef = useRef(null);
  const nav = useNavigate();

  const onFile = (f) => {
    if (!f) return;
    if (!f.name.toLowerCase().endsWith('.zip')) {
      setError('Only .zip files are supported');
      return;
    }
    if (f.size > 100 * 1024 * 1024) {
      setError('Max size is 100MB');
      return;
    }
    setError('');
    setFile(f);
    if (!projectName) setProjectName(f.name.replace(/\.zip$/i, ''));
  };

  const submit = async (e) => {
    e.preventDefault();
    if (!file || !projectName) {
      setError('Provide a project name and a ZIP file');
      return;
    }
    setUploading(true);
    setError('');
    const fd = new FormData();
    fd.append('project_name', projectName);
    fd.append('file', file);
    try {
      const { data } = await api.post('/scans', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (evt) => {
          setProgress(Math.round((evt.loaded / (evt.total || 1)) * 100));
        },
      });
      nav(`/scan/${data.id}`);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-6 py-12 space-y-8">
      <div>
        <div className="font-mono text-[10px] uppercase tracking-[0.3em] text-[#00ff41] mb-2">
          Operations · New Scan
        </div>
        <h1 className="text-3xl font-bold tracking-tight">Upload code archive</h1>
        <p className="text-white/50 text-sm mt-1">
          ZIP files up to 100MB. Extraction is jailed and each finding runs against Semgrep, Bandit, Gitleaks, IaC and SCA.
        </p>
      </div>

      <form onSubmit={submit} className="space-y-6 bg-[#0f0f0f] border border-white/10 rounded-sm p-6">
        <label className="block">
          <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-white/60 mb-1.5 block">
            Project name
          </span>
          <input
            type="text"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            placeholder="checkout-service-v2"
            data-testid={TID.upload.projectNameInput}
            className="w-full px-4 py-2.5 rounded-sm bg-black border border-white/10 focus:border-[#00ff41]/60 focus:outline-none font-mono text-sm transition-colors"
            required
          />
        </label>

        <div
          data-testid={TID.upload.dropzone}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            onFile(e.dataTransfer.files?.[0]);
          }}
          onClick={() => fileRef.current?.click()}
          className={`cursor-pointer border-2 border-dashed rounded-sm p-10 text-center transition-all ${
            dragging
              ? 'border-[#00ff41] bg-[#00ff41]/10 glow-matrix'
              : 'border-white/15 hover:border-[#00ff41]/40 hover:bg-white/[0.02]'
          }`}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".zip"
            className="hidden"
            onChange={(e) => onFile(e.target.files?.[0])}
            data-testid={TID.upload.fileInput}
          />
          {file ? (
            <div className="space-y-2">
              <FileCode2 className="w-8 h-8 text-[#00ff41] mx-auto" />
              <div className="font-mono text-sm font-bold">{file.name}</div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-white/40">
                {(file.size / 1024 / 1024).toFixed(2)} MB · click to change
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <UploadCloud className="w-10 h-10 text-white/40 mx-auto" />
              <div className="font-mono text-sm">
                Drop <span className="text-[#00ff41]">.zip</span> here or click to browse
              </div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-white/40">
                Max 100MB · Semgrep + Bandit + Gitleaks + IaC + SCA
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="p-3 rounded-sm border border-[#ff3b30]/40 bg-[#ff3b30]/10 text-[#ff3b30] font-mono text-xs">
            {error}
          </div>
        )}

        {uploading && progress < 100 && (
          <div className="space-y-1">
            <div className="h-1 bg-white/8 rounded-full overflow-hidden">
              <div className="h-full bg-[#00ff41] transition-all" style={{ width: `${progress}%` }} />
            </div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-white/50">
              Uploading · {progress}%
            </div>
          </div>
        )}

        <button
          type="submit"
          disabled={uploading || !file || !projectName}
          data-testid={TID.upload.submitBtn}
          className="w-full py-3 rounded-sm bg-[#00ff41] text-black hover:bg-white font-mono text-xs uppercase tracking-[0.25em] font-bold transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
          {uploading ? 'Uploading...' : 'Start Scan'}
        </button>
      </form>
    </div>
  );
}
