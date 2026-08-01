import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { TID } from '../testIds';
import { ShieldAlert, Terminal, LogOut, LayoutDashboard, Zap } from 'lucide-react';

export default function Shell({ children, showNav = true }) {
  const { user, logout } = useAuth();
  const nav = useNavigate();

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-[#f5f5f5] flex flex-col">
      {showNav && (
        <header className="border-b border-white/8 bg-[#0f0f0f]/80 backdrop-blur sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between gap-6">
            <Link to={user ? '/dashboard' : '/'} className="flex items-center gap-3 group">
              <div className="w-9 h-9 rounded-sm bg-black border border-[#00ff41]/40 flex items-center justify-center glow-matrix group-hover:scale-105 transition-transform">
                <ShieldAlert className="w-5 h-5 text-[#00ff41]" strokeWidth={2} />
              </div>
              <div className="leading-none">
                <div className="font-mono text-sm font-bold tracking-tight">VulnScan<span className="text-[#00ff41]">.</span>AI</div>
                <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-white/40">Vulnerability Intel · v1.0</div>
              </div>
            </Link>

            {user ? (
              <div className="flex items-center gap-3">
                <Link
                  to="/dashboard"
                  data-testid="nav-dashboard"
                  className="hidden md:flex items-center gap-2 px-3 py-2 rounded-sm bg-white/5 border border-white/10 hover:border-[#00ff41]/40 hover:bg-[#00ff41]/5 transition-colors font-mono text-xs uppercase tracking-wider"
                >
                  <LayoutDashboard className="w-3.5 h-3.5" /> Dashboard
                </Link>
                <Link
                  to="/scan/new"
                  data-testid="nav-new-scan"
                  className="hidden md:flex items-center gap-2 px-3 py-2 rounded-sm bg-[#00ff41] text-black hover:bg-[#00ff41]/90 transition-colors font-mono text-xs uppercase tracking-wider font-bold"
                >
                  <Zap className="w-3.5 h-3.5" /> New Scan
                </Link>
                <div className="hidden sm:block text-right leading-tight">
                  <div className="font-mono text-xs text-white/90">{user.name || user.email.split('@')[0]}</div>
                  <div className="font-mono text-[10px] text-white/40 uppercase tracking-widest">Operator</div>
                </div>
                <button
                  data-testid={TID.auth.logoutBtn}
                  onClick={() => {
                    logout();
                    nav('/');
                  }}
                  className="w-9 h-9 flex items-center justify-center rounded-sm border border-white/10 bg-white/5 hover:border-[#ff3b30]/40 hover:text-[#ff3b30] transition-colors"
                  title="Logout"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <Link
                  to="/login"
                  data-testid={TID.landing.login}
                  className="px-4 py-2 rounded-sm border border-white/10 hover:border-[#00ff41]/40 font-mono text-xs uppercase tracking-wider transition-colors"
                >
                  Login
                </Link>
                <Link
                  to="/register"
                  className="px-4 py-2 rounded-sm bg-[#00ff41] text-black hover:bg-[#00ff41]/90 font-mono text-xs uppercase tracking-wider font-bold transition-colors"
                >
                  Get Started
                </Link>
              </div>
            )}
          </div>
        </header>
      )}
      <main className="flex-1">{children}</main>
      <footer className="border-t border-white/8 bg-black py-6">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-[10px] uppercase tracking-[0.2em] text-white/40">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#00ff41] pulse-matrix" /> System · Operational
          </div>
          <div>Semgrep · Bandit · Gitleaks · IaC · SCA · Claude Sonnet 4.5</div>
          <div>© 2026 VulnScan.AI</div>
        </div>
      </footer>
    </div>
  );
}
