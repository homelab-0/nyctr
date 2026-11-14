import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Ban,
  Braces,
  History,
  Inbox,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  Network,
  PlugZap,
  Server,
  Settings as SettingsIcon,
  ShieldAlert,
  Sparkles,
  Unlock,
  Wifi,
  X,
} from 'lucide-react';
import { useApi } from './api';
import { useAuth } from './auth';
import Assistant from './components/Assistant';
import { Brand, Empty, InlineError, Loading, registerSources } from './components/ui';
import type { IconComponent } from './components/ui';
import type { AttentionItem, Catalog, Rules } from './types';
import Activity from './pages/Activity';
import Blocks from './pages/Blocks';
import Briefing from './pages/Briefing';
import Findings from './pages/Findings';
import Guests from './pages/Guests';
import Integrations from './pages/Integrations';
import Inventory from './pages/Inventory';
import MapPage from './pages/MapPage';
import OpenNow from './pages/OpenNow';
import Queries from './pages/Queries';
import Requests from './pages/Requests';
import Setup from './pages/Setup';
import SignIn from './pages/SignIn';
import Portal from './pages/member/Portal';
import { isAssistantKey, rememberShortcut, shortcutEnabled } from './lib/shortcut';
import { mayChange } from './lib/format';

interface NavItem {
  id: string;
  name: string;
  icon: IconComponent;
  count?: number;
}
interface NavGroup {
  title: string;
  items: NavItem[];
}

/** Tracks hash navigation and query parameters without sending client route state to the server. */
export function useRoute() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    /** Mirrors browser back/forward navigation into React's current route. */
    const change = () => setHash(window.location.hash);
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  return useMemo(() => {
    const [path, query] = hash.replace(/^#\/?/, '').split('?');
    return { page: path || '', params: new URLSearchParams(query) };
  }, [hash]);
}

/** States in one line what Nyctr is allowed to change, from the server's own settings. */
export function writeLine(rules: Rules | null, demo: boolean) {
  if (demo) return 'Demo: every change is simulated';
  if (!rules) return 'Checking what Nyctr may change';
  // The same words as the headline on Sources, so the two cannot disagree.
  const allowed = mayChange(rules.sources);
  return allowed ? `May change ${allowed}` : 'Read-only for every source';
}

/**
 * The administrator console: labelled sidebar, page area and the assistant drawer.
 * Roles here only choose what to show; every API endpoint authorizes on its own.
 */
function Console({ page, params }: { page: string; params: URLSearchParams }) {
  const { user, logout } = useAuth();
  const attention = useApi<AttentionItem[]>('/attention');
  const rules = useApi<Rules>('/rules');
  const catalog = useApi<Catalog>('/integrations/catalog');
  // Chips and names for every kind of source come from the server, not from this app.
  if (catalog.data) registerSources(catalog.data.providers);
  const [navOpen, setNavOpen] = useState(false);
  const [assistant, setAssistant] = useState(false);
  const [shortcut, setShortcut] = useState(shortcutEnabled);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);
  const sidebar = useRef<HTMLElement>(null);
  const items = attention.data || [];
  const count = (kind: string) => items.filter((item) => item.kind === kind).length || undefined;
  const navigation: NavGroup[] = [
    {
      title: 'Network',
      items: [
        { id: 'briefing', name: 'Briefing', icon: LayoutDashboard },
        { id: 'map', name: 'Map', icon: Network },
        { id: 'inventory', name: 'Inventory', icon: Server },
        { id: 'findings', name: 'Findings', icon: ShieldAlert, count: count('finding') },
      ],
    },
    {
      title: 'Access',
      items: [
        { id: 'queries', name: 'Queries', icon: Braces },
        { id: 'blocks', name: 'Blocks', icon: Ban },
        { id: 'requests', name: 'Requests', icon: Inbox, count: count('request') },
        { id: 'access', name: 'Open now', icon: Unlock },
        { id: 'guests', name: 'Guests', icon: Wifi, count: count('guest') },
      ],
    },
    {
      title: 'Platform',
      items: [
        { id: 'sources', name: 'Sources', icon: PlugZap, count: count('source') },
        { id: 'activity', name: 'Activity', icon: History },
        { id: 'setup', name: 'Setup', icon: SettingsIcon },
      ],
    },
  ];
  const current = navigation.flatMap((group) => group.items).find((item) => item.id === page);
  const title = current?.name || 'Not found';
  const reloadAttention = attention.reload;
  /** Lets a screen refresh the shared attention list after it changed something. */
  const refresh = useCallback(() => reloadAttention(), [reloadAttention]);

  useEffect(() => {
    setNavOpen(false);
    document.title = `${title} · Nyctr`;
    document.getElementById('main-content')?.scrollTo(0, 0);
  }, [page, title]);
  useEffect(() => {
    /**
     * Opens the drawer when any screen asks a question. A toggles it outside form fields,
     * unless the person turned that shortcut off in the drawer.
     */
    const onAsk = () => setAssistant(true);
    const onKey = (event: KeyboardEvent) => {
      if (isAssistantKey(event, shortcut)) setAssistant((value) => !value);
      if (event.key === 'Escape') setNavOpen(false);
    };
    window.addEventListener('nyctr:ask', onAsk);
    document.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('nyctr:ask', onAsk);
      document.removeEventListener('keydown', onKey);
    };
  }, [shortcut]);

  /** Displays genuine revocation failures while AuthProvider handles success or session expiry. */
  const signOut = async () => {
    setLoggingOut(true);
    setLogoutError(null);
    try {
      await logout();
    } catch (e) {
      setLogoutError((e as Error).message);
    } finally {
      setLoggingOut(false);
    }
  };
  if (!user) return null;
  const demo = user.mode === 'demo';
  return (
    <div className={`app ${assistant ? 'with-drawer' : ''}`}>
      <a
        className="skip-link"
        href="#main-content"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById('main-content')?.focus();
        }}
      >
        Skip to content
      </a>
      {navOpen && (
        <button className="scrim" aria-label="Close navigation" onClick={() => setNavOpen(false)} />
      )}
      <aside
        ref={sidebar}
        className={`side ${navOpen ? 'open' : ''}`}
        aria-label="Console navigation"
      >
        <div className="side-brand">
          <a href="#/briefing" aria-label="Nyctr home">
            <Brand />
          </a>
          <button
            className="icon-button side-close"
            onClick={() => setNavOpen(false)}
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        </div>
        <nav>
          {navigation.map((group) => (
            <section className="nav-group" key={group.title}>
              <h2>{group.title}</h2>
              {group.items.map((item) => (
                <a
                  key={item.id}
                  href={`#/${item.id}`}
                  className={`nav-item ${page === item.id ? 'active' : ''}`}
                  aria-current={page === item.id ? 'page' : undefined}
                >
                  <item.icon size={16} strokeWidth={1.8} />
                  <span>{item.name}</span>
                  {item.count !== undefined && <span className="count">{item.count}</span>}
                </a>
              ))}
            </section>
          ))}
        </nav>
        <div className="side-foot">
          <a className="writes" href="#/sources" title="What Nyctr may change: see Sources for all">
            <LockKeyhole size={13} />
            <span>{writeLine(rules.data, demo)}</span>
          </a>
          <div className="side-user">
            <span className="avatar">{(user.name || user.email).slice(0, 1).toUpperCase()}</span>
            <div>
              <strong>{user.name}</strong>
              <small>Administrator</small>
            </div>
            <button
              className="icon-button"
              disabled={loggingOut}
              title="Sign out"
              aria-label="Sign out"
              onClick={() => void signOut()}
            >
              <LogOut size={16} />
            </button>
          </div>
          <InlineError message={logoutError} />
        </div>
      </aside>
      <div className="main" inert={navOpen}>
        <header className="top">
          <button
            className="icon-button nav-toggle"
            onClick={() => setNavOpen(true)}
            aria-label="Open navigation"
            aria-expanded={navOpen}
          >
            <Menu size={20} />
          </button>
          <strong className="top-title">{title}</strong>
          <span className="top-fill" />
          {demo && <span className="tag blue top-mode">Demo data</span>}
          <button
            className="button secondary small ask"
            onClick={() => setAssistant((value) => !value)}
            aria-pressed={assistant}
          >
            <Sparkles size={15} /> Ask Nyctr {shortcut && <kbd>A</kbd>}
          </button>
        </header>
        <main id="main-content" className="content" tabIndex={-1}>
          <Screen
            page={page}
            params={params}
            attention={items}
            loading={attention.loading}
            refresh={refresh}
            sources={rules.data?.sources}
          />
        </main>
      </div>
      <Assistant
        open={assistant}
        onClose={() => setAssistant(false)}
        attention={items}
        shortcut={shortcut}
        onShortcut={(value) => {
          rememberShortcut(value);
          setShortcut(value);
        }}
      />
    </div>
  );
}

/** Selects the administrator screen for a route. */
function Screen({
  page,
  params,
  attention,
  loading,
  refresh,
  sources,
}: {
  page: string;
  params: URLSearchParams;
  attention: AttentionItem[];
  loading: boolean;
  refresh: () => void;
  sources?: Rules['sources'];
}) {
  switch (page) {
    case 'briefing':
      return <Briefing attention={attention} loading={loading} />;
    case 'map':
      return <MapPage params={params} sources={sources} />;
    case 'inventory':
      return <Inventory params={params} />;
    case 'findings':
      return <Findings params={params} />;
    case 'queries':
      return <Queries params={params} />;
    case 'blocks':
      return <Blocks />;
    case 'requests':
      return <Requests params={params} onChange={refresh} />;
    case 'access':
      return <OpenNow onChange={refresh} />;
    case 'guests':
      return <Guests params={params} onChange={refresh} />;
    case 'sources':
      return <Integrations sources={sources} />;
    case 'activity':
      return <Activity />;
    case 'setup':
      return <Setup params={params} />;
    default:
      return (
        <Empty
          title="This screen could not be found"
          text="Go back to the briefing to continue."
          action={
            <a className="button primary" href="#/briefing">
              Open the briefing
            </a>
          }
        />
      );
  }
}

/** Chooses sign-in, the member portal or the administrator console for the current session. */
export default function App() {
  const { user, loading } = useAuth();
  const route = useRoute();
  if (loading)
    return (
      <div className="boot-screen">
        <Brand />
        <Loading text="Opening Nyctr…" />
      </div>
    );
  if (!user) return <SignIn />;
  if (user.role === 'member') return <Portal page={route.page} params={route.params} />;
  return <Console key={user.id} page={route.page || 'briefing'} params={route.params} />;
}
