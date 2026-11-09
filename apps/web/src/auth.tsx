import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { ApiError, api, post, setCsrfToken } from './api';
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

/**
 * Shares the server-authenticated identity and an in-memory CSRF token.
 * Request revisions prevent an older session refresh from restoring a signed-out identity.
 * Roles here control presentation; the API remains the authorization boundary.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const revision = useRef(0);

  /** Updates identity and CSRF together so requests cannot reuse a cleared session's token. */
  const updateUser = useCallback((value: User | null) => {
    setUser(value);
    setCsrfToken(value?.csrf_token ?? '');
  }, []);

  /** Reloads the current server session, ignoring results superseded by a later auth action. */
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
    /** Removes local access after a protected API request reports an expired session. */
    const expired = () => {
      ++revision.current;
      updateUser(null);
      setError('Your session expired. Sign in to continue.');
    };
    window.addEventListener('nyctr:session-expired', expired);
    return () => window.removeEventListener('nyctr:session-expired', expired);
  }, [updateUser]);

  /** Establishes a server session and opens the role's landing page without persisting credentials. */
  const login = async (email: string, password: string) => {
    ++revision.current;
    const next = await post<User>('/auth/login', { email, password });
    updateUser(next);
    setError(null);
    window.location.hash = next.role === 'member' ? '/portal' : '/overview';
  };

  /**
   * Clears local identity after revocation or an already-expired server session.
   * Other HTTP and transport failures propagate to the caller without claiming logout succeeded.
   */
  const logout = async () => {
    try {
      await post('/auth/logout');
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 401)) throw error;
    }
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

/** Requires an AuthProvider so consumers cannot silently operate without session state. */
export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('Missing authentication context');
  return value;
}
