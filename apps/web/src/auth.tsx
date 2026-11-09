import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { api, post, setCsrfToken } from './api';
import type { User } from './types';

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => void;
}
const AuthContext = createContext<AuthContextValue | null>(null);
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const revision = useRef(0);
  const updateUser = useCallback((value: User | null) => {
    setUser(value);
    setCsrfToken(value?.csrf_token ?? '');
  }, []);
  const refresh = useCallback(() => {
    const current = ++revision.current;
    setLoading(true);
    setError(null);
    api<User>('/auth/me')
      .then((value) => {
        if (current === revision.current) updateUser(value);
      })
      .catch((err) => {
        if (current !== revision.current) return;
        updateUser(null);
        if (err.status !== 401) setError(err.message);
      })
      .finally(() => {
        if (current === revision.current) setLoading(false);
      });
  }, [updateUser]);
  useEffect(refresh, [refresh]);
  useEffect(() => {
    const expired = () => {
      ++revision.current;
      updateUser(null);
      setError('Your session expired. Sign in to continue.');
    };
    window.addEventListener('nyctr:session-expired', expired);
    return () => window.removeEventListener('nyctr:session-expired', expired);
  }, [updateUser]);
  const login = async (email: string, password: string) => {
    ++revision.current;
    const next = await post<User>('/auth/login', { email, password });
    updateUser(next);
    setError(null);
    window.location.hash = next.role === 'member' ? '/portal' : '/overview';
  };
  const logout = async () => {
    await post('/auth/logout');
    ++revision.current;
    updateUser(null);
    window.location.hash = '/';
  };
  return (
    <AuthContext.Provider value={{ user, loading, error, login, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}
export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('Missing authentication context');
  return value;
}
