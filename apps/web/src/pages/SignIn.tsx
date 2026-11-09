import { useState, type FormEvent } from 'react';
import { ArrowRight, Fingerprint, LockKeyhole, Network, ShieldCheck } from 'lucide-react';
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
          <span className="eyebrow">Your network. In focus.</span>
          <h1>
            See the connections.
            <br />
            <span>Understand the risk.</span>
          </h1>
          <p>
            A clear view across your infrastructure, network policies, and the connections that
            matter.
          </p>
          <div className="signin-path" aria-hidden="true">
            <div>
              <Network size={25} />
            </div>
            <span />
            <div className="path-focus">
              <ShieldCheck size={29} />
            </div>
            <span />
            <div>
              <Fingerprint size={25} />
            </div>
          </div>
          <div className="signin-values">
            <span>
              <ShieldCheck size={16} /> Evidence-led analysis
            </span>
            <span>
              <LockKeyhole size={16} /> Human-controlled changes
            </span>
          </div>
        </div>
        <footer>
          Open-source network security workspace <span>0.1.0 alpha</span>
        </footer>
      </section>
      <section className="signin-form-area">
        <div className="signin-form">
          <span className="icon-tile large">
            <LockKeyhole size={25} />
          </span>
          <h2>Welcome to Nyctr</h2>
          <p>Sign in to your network workspace.</p>
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
