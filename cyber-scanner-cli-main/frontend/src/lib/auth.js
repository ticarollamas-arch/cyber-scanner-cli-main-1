import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import api from './api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('vulnscan_user') || 'null');
    } catch {
      return null;
    }
  });
  const [ready, setReady] = useState(false);

  const persist = useCallback((token, u) => {
    localStorage.setItem('vulnscan_token', token);
    localStorage.setItem('vulnscan_user', JSON.stringify(u));
    setUser(u);
  }, []);

  const login = async (email, password) => {
    const { data } = await api.post('/auth/login', { email, password });
    persist(data.token, data.user);
    return data.user;
  };

  const register = async (email, password, name) => {
    const { data } = await api.post('/auth/register', { email, password, name });
    persist(data.token, data.user);
    return data.user;
  };

  const logout = () => {
    localStorage.removeItem('vulnscan_token');
    localStorage.removeItem('vulnscan_user');
    setUser(null);
  };

  useEffect(() => {
    const token = localStorage.getItem('vulnscan_token');
    if (!token) {
      setReady(true);
      return;
    }
    api
      .get('/auth/me')
      .then((r) => setUser(r.data))
      .catch(() => {
        localStorage.removeItem('vulnscan_token');
        localStorage.removeItem('vulnscan_user');
        setUser(null);
      })
      .finally(() => setReady(true));
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, register, logout, ready }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
