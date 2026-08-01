import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { TID } from '../testIds';
import { ShieldAlert, Loader2 } from 'lucide-react';

export default function AuthPage({ mode = 'login' }) {
  const isRegister = mode === 'register';
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, register } = useAuth();
  const nav = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (isRegister) {
        await register(email, password, name);
      } else {
        await login(email, password);
      }
      nav('/dashboard');
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center px-6 py-16 grid-bg">
      <div className="w-full max-w-md relative">
        <div className="absolute inset-0 bg-[#00ff41]/5 blur-3xl opacity-40 pointer-events-none" />
        <div className="relative border border-white/10 bg-[#0f0f0f] rounded-sm p-8 space-y-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-sm border border-[#00ff41]/40 bg-[#00ff41]/10 flex items-center justify-center glow-matrix">
              <ShieldAlert className="w-5 h-5 text-[#00ff41]" />
            </div>
            <div>
              <div className="font-mono text-xs uppercase tracking-[0.25em] text-[#00ff41]">Secure Access</div>
              <div className="text-xl font-bold">{isRegister ? 'Create operator account' : 'Sign in to console'}</div>
            </div>
          </div>

          <form onSubmit={submit} className="space-y-4">
            {isRegister && (
              <Field
                label="Operator name"
                type="text"
                value={name}
                onChange={setName}
                placeholder="Ana Silva"
                testid={TID.auth.nameInput}
              />
            )}
            <Field
              label="Email"
              type="email"
              value={email}
              onChange={setEmail}
              placeholder="you@company.com"
              testid={TID.auth.emailInput}
              required
            />
            <Field
              label="Password"
              type="password"
              value={password}
              onChange={setPassword}
              placeholder="min. 6 chars"
              testid={TID.auth.passwordInput}
              required
            />

            {error && (
              <div className="p-3 rounded-sm border border-[#ff3b30]/40 bg-[#ff3b30]/10 text-[#ff3b30] font-mono text-xs">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              data-testid={TID.auth.submitBtn}
              className="w-full py-3 rounded-sm bg-[#00ff41] text-black hover:bg-white font-mono text-xs uppercase tracking-[0.25em] font-bold transition-colors flex items-center justify-center gap-2 disabled:opacity-60"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              {isRegister ? 'Create Account' : 'Enter Console'}
            </button>
          </form>

          <div className="border-t border-white/8 pt-4 text-center font-mono text-xs text-white/50">
            {isRegister ? (
              <>
                Already have an account?{' '}
                <Link to="/login" data-testid={TID.auth.toggleMode} className="text-[#00ff41] hover:underline">
                  Sign in
                </Link>
              </>
            ) : (
              <>
                No account yet?{' '}
                <Link to="/register" data-testid={TID.auth.toggleMode} className="text-[#00ff41] hover:underline">
                  Register
                </Link>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Field({ label, type, value, onChange, placeholder, testid, required }) {
  return (
    <label className="block">
      <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-white/60 mb-1.5 block">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        data-testid={testid}
        className="w-full px-4 py-2.5 rounded-sm bg-black border border-white/10 focus:border-[#00ff41]/60 focus:outline-none font-mono text-sm placeholder:text-white/25 transition-colors"
      />
    </label>
  );
}
