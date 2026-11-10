import { useState, type FormEvent } from 'react';
import { ArrowRight, Fingerprint, LockKeyhole } from 'lucide-react';
import { useAuth } from '../auth';
import { useApi } from '../api';
import type { AuthConfig } from '../types';
import { Badge, Brand, ErrorState, Field, InlineError, Loading } from '../components/ui';

/**
 * Displays only authentication methods enabled by the server's public configuration.
 * Known demo identities are offered exclusively in demo mode; passwords remain in
 * form state and are sent only to the session endpoint.
 */
export default function SignIn() {
  const { login, error: sessionError } = useAuth();
  const config = useApi<AuthConfig>('/auth/config');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** Coordinates a single sign-in attempt and exposes its failure without logging credentials. */
  const signIn = async (username: string, secret: string) => {
    setPending(true);
    setError(null);
    try {
      await login(username, secret);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  /** Prevents browser form navigation and passes local credentials to the shared login flow. */
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void signIn(email, password);
  };
  const oidcError = new URLSearchParams(window.location.search).get('error');
  return (
    <main className="signin-page">
      <section className="signin-story">
        <Brand />
        <div className="signin-message">
          <h1 className="display">
            See what is connected.
            <br />
            Know why something was blocked.
          </h1>
          <p className="lede">
            One place for your network, DNS and hypervisor. Evidence first, and nothing changes
            without a rule you wrote or a decision you made.
          </p>
          <ul className="signin-values">
            <li>
              <i className="ev observed" /> Seen happening
            </li>
            <li>
              <i className="ev configured" /> A setting
            </li>
            <li>
              <i className="ev inferred" /> Worked out by Nyctr
            </li>
          </ul>
        </div>
        <footer>Open-source network security workspace</footer>
      </section>
      <section className="signin-form-area">
        <div className="signin-form">
          <h2 className="display d2">Sign in</h2>
          <p className="lede">Blocked from a site? Sign in to see why and ask to open it.</p>
          {config.loading ? (
            <Loading text="Checking sign-in options…" />
          ) : config.error ? (
            <ErrorState message={config.error} retry={config.reload} />
          ) : (
            <>
              <InlineError
                message={
                  error ||
                  sessionError ||
                  (oidcError
                    ? 'Single sign-on could not be completed. Please try again or contact your administrator.'
                    : null)
                }
              />
              {config.data?.oidc_enabled && (
                <a className="button secondary full" href="/api/auth/oidc/login">
                  <Fingerprint size={17} />
                  Continue with single sign-on
                  <ArrowRight size={16} />
                </a>
              )}
              {config.data?.local_enabled && (
                <form onSubmit={submit} className="form-stack">
                  <Field label="Email address">
                    <input
                      type="email"
                      autoComplete="username"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      placeholder="you@example.com"
                      disabled={pending}
                    />
                  </Field>
                  <Field label="Password">
                    <input
                      type="password"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      disabled={pending}
                    />
                  </Field>
                  <button className="button primary full" type="submit" disabled={pending}>
                    {pending ? 'Signing in…' : 'Sign in'}
                    <ArrowRight size={16} />
                  </button>
                </form>
              )}
              {!config.data?.local_enabled && !config.data?.oidc_enabled && (
                <ErrorState message="No sign-in method is configured. Ask the server administrator to configure local or OIDC authentication." />
              )}
              {config.data?.mode === 'demo' && (
                <div className="demo-signin">
                  <Badge tone="blue">Demo workspace</Badge>
                  <p>
                    Explore synthetic data with a real authenticated session. Live integrations are
                    disabled in this mode.
                  </p>
                  <div className="button-row">
                    <button
                      className="button secondary"
                      disabled={pending}
                      onClick={() => void signIn('admin@nyctr.demo', 'nyctr-demo')}
                    >
                      Explore as admin
                    </button>
                    <button
                      className="button secondary"
                      disabled={pending}
                      onClick={() => void signIn('jamie@nyctr.demo', 'nyctr-demo')}
                    >
                      Open member portal
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
          <div className="signin-footnote">
            <LockKeyhole size={13} /> Your session is secured with a server-managed cookie.
          </div>
        </div>
      </section>
    </main>
  );
}
