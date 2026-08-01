import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './lib/auth';
import Shell from './components/Shell';
import LandingPage from './pages/LandingPage';
import AuthPage from './pages/AuthPage';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';

function Protected({ children }) {
  const { user, ready } = useAuth();
  if (!ready) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#0a0a0a]">
        <div className="font-mono text-xs uppercase tracking-widest text-white/50">Initializing...</div>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function Public({ children }) {
  const { user, ready } = useAuth();
  if (!ready) return null;
  if (user) return <Navigate to="/dashboard" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route
            path="/"
            element={
              <Shell>
                <LandingPage />
              </Shell>
            }
          />
          <Route
            path="/login"
            element={
              <Public>
                <Shell>
                  <AuthPage mode="login" />
                </Shell>
              </Public>
            }
          />
          <Route
            path="/register"
            element={
              <Public>
                <Shell>
                  <AuthPage mode="register" />
                </Shell>
              </Public>
            }
          />
          <Route
            path="/dashboard"
            element={
              <Protected>
                <Shell>
                  <Dashboard />
                </Shell>
              </Protected>
            }
          />
          <Route
            path="/scan/new"
            element={
              <Protected>
                <Shell>
                  <NewScan />
                </Shell>
              </Protected>
            }
          />
          <Route
            path="/scan/:id"
            element={
              <Protected>
                <Shell>
                  <ScanDetail />
                </Shell>
              </Protected>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
