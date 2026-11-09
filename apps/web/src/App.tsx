import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity as ActivityIcon,
  ArrowUpRight,
  Blocks as BlocksIcon,
  Bot,
  ChevronRight,
  ClipboardCheck,
  FileCheck2,
  GitBranch,
  Globe2,
  Inbox,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  Network,
  PlugZap,
  SearchCheck,
  Server,
  Settings as SettingsIcon,
  Shield,
  ShieldAlert,
  Users,
  X,
} from 'lucide-react';
import { useAuth } from './auth';
import { Badge, Brand, Empty, InlineError, Loading } from './components/ui';
import type { IconComponent } from './components/ui';
import SignIn from './pages/SignIn';
import Overview from './pages/Overview';
import Explorer from './pages/Explorer';
import Resources from './pages/Resources';
import Findings from './pages/Findings';
import Integrations from './pages/Integrations';
import Blocks from './pages/Blocks';
import Requests from './pages/Requests';
import { Activity, AIProvider, Changes, Settings } from './pages/Workspace';

interface NavItem {
  id: string;
  name: string;
  icon: IconComponent;
}
interface NavGroup {
  title: string;
  items: NavItem[];
}
const adminNavigation: NavGroup[] = [
  {
    title: 'Workspace',
    items: [
      { id: 'overview', name: 'Overview', icon: LayoutDashboard },
      { id: 'explorer', name: 'Network explorer', icon: Network },
      { id: 'infrastructure', name: 'Infrastructure', icon: Server },
      { id: 'investigations', name: 'Investigations', icon: SearchCheck },
    ],
  },
  {
    title: 'Security',
    items: [
      { id: 'findings', name: 'Findings', icon: ShieldAlert },
      { id: 'policies', name: 'Policies', icon: Shield },
      { id: 'traffic', name: 'Traffic & DNS', icon: ActivityIcon },
    ],
  },
  {
    title: 'Access',
    items: [
      { id: 'blocks', name: 'Block inbox', icon: Inbox },
      { id: 'requests', name: 'Requests', icon: ClipboardCheck },
      { id: 'changes', name: 'Changes', icon: FileCheck2 },
      { id: 'activity', name: 'Activity', icon: ActivityIcon },
    ],
  },
  {
    title: 'Manage',
    items: [
      { id: 'integrations', name: 'Integrations', icon: PlugZap },
      { id: 'ai', name: 'AI provider', icon: Bot },
      { id: 'members', name: 'Members & roles', icon: Users },
      { id: 'settings', name: 'Settings', icon: SettingsIcon },
    ],
  },
];
const memberNavigation: NavGroup[] = [
  {
    title: 'Your access',
    items: [
      { id: 'portal', name: 'Recent blocks', icon: Inbox },
      { id: 'devices', name: 'My devices', icon: Server },
      { id: 'requests', name: 'My requests', icon: ClipboardCheck },
    ],
  },
];

/** Tracks hash navigation and query parameters without sending client route state to the server. */
function useRoute() {
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

/**
 * Selects the view for a session's role and route. This is a navigation convenience;
 * each API endpoint independently authorizes the requested resources and actions.
 */
function Content({
  page,
  params,
  member,
}: {
  page: string;
  params: URLSearchParams;
  member: boolean;
}) {
  if (member) {
    if (page === 'devices') return <Resources member />;
    if (page === 'requests') return <Requests />;
    return <Blocks />;
  }
  switch (page) {
    case 'overview':
      return <Overview />;
    case 'explorer':
      return <Explorer params={params} />;
    case 'infrastructure':
      return <Resources />;
    case 'policies':
      return <Resources policies />;
    case 'findings':
      return <Findings params={params} />;
    case 'investigations':
      return <Findings params={params} investigations />;
    case 'blocks':
    case 'portal':
      return <Blocks />;
    case 'traffic':
      return <Blocks traffic />;
    case 'requests':
      return <Requests />;
    case 'integrations':
      return <Integrations />;
    case 'activity':
      return <Activity />;
    case 'ai':
      return <AIProvider />;
    case 'changes':
      return <Changes />;
    case 'members':
      return <Settings members />;
    case 'settings':
      return <Settings />;
    default:
      return (
        <Empty
          title="This view could not be found"
          text="Return to the workspace to continue."
          action={
            <a className="button primary" href="#/overview">
              Open overview
            </a>
          }
        />
      );
  }
}

/**
 * Provides the authenticated workspace shell and a narrower member navigation.
 * Keeps demo/read-only capabilities visible and preserves server errors on sign-out.
 */
export default function App() {
  const { user, loading, logout } = useAuth();
  const route = useRoute();
  const [navOpen, setNavOpen] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);
  const sidebar = useRef<HTMLElement>(null);
  const member = user?.role === 'member';
  const page =
    member && !['portal', 'devices', 'requests'].includes(route.page)
      ? 'portal'
      : route.page || 'overview';
  const navigation = member ? memberNavigation : adminNavigation;
  const title =
    navigation.flatMap((n) => n.items).find((n) => n.id === page)?.name ||
    (member ? 'Recent blocks' : 'Workspace');
  const group =
    navigation.find((n) => n.items.some((item) => item.id === page))?.title || 'Workspace';
  /** Resets view-local navigation affordances when the route or its query changes. */
  useEffect(() => {
    setNavOpen(false);
    document.title = `${title} · Nyctr`;
    document.getElementById('main-content')?.scrollTo(0, 0);
  }, [page, title, route.params.toString()]);
  /** Confines keyboard focus to the open mobile drawer while the main content is inert. */
  useEffect(() => {
    if (!navOpen) return;
    sidebar.current?.querySelector<HTMLElement>('a')?.focus();
    /** Cycles drawer focus with Tab and returns focus to its trigger on Escape. */
    const handle = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setNavOpen(false);
        document.getElementById('nav-toggle')?.focus();
      }
      if (event.key === 'Tab') {
        const items = [
          ...(sidebar.current?.querySelectorAll<HTMLElement>('a, button:not([disabled])') || []),
        ];
        if (event.shiftKey && document.activeElement === items[0]) {
          event.preventDefault();
          items.at(-1)?.focus();
        }
        if (!event.shiftKey && document.activeElement === items.at(-1)) {
          event.preventDefault();
          items[0]?.focus();
        }
      }
    };
    document.addEventListener('keydown', handle);
    return () => document.removeEventListener('keydown', handle);
  }, [navOpen]);
  if (loading)
    return (
      <div className="boot-screen">
        <Brand />
        <Loading text="Opening your workspace…" />
      </div>
    );
  if (!user) return <SignIn />;
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
  return (
    <div className={`app-shell ${member ? 'member-workspace' : ''}`}>
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
        <button
          className="nav-backdrop"
          aria-label="Close navigation"
          onClick={() => setNavOpen(false)}
        />
      )}
      <aside
        ref={sidebar}
        className={`sidebar ${navOpen ? 'open' : ''}`}
        aria-label="Workspace navigation"
      >
        <a className="brand-link" href={member ? '#/portal' : '#/overview'} aria-label="Nyctr home">
          <Brand />
          <span className="version-chip">ALPHA</span>
        </a>
        <button
          className="mobile-close icon-button"
          onClick={() => setNavOpen(false)}
          aria-label="Close navigation"
        >
          <X size={20} />
        </button>
        <div className="workspace-selector">
          <span className="workspace-icon">
            <Globe2 size={18} />
          </span>
          <div>
            <strong>{member ? 'Member portal' : 'Network workspace'}</strong>
            <small>{user.mode === 'demo' ? 'Demo environment' : 'Self-hosted'}</small>
          </div>
        </div>
        <nav>
          {navigation.map((nav) => (
            <section className="nav-group" key={nav.title}>
              <h2>{nav.title}</h2>
              {nav.items.map((item) => (
                <a
                  key={item.id}
                  href={`#/${item.id}`}
                  className={`nav-item ${page === item.id ? 'active' : ''}`}
                  aria-current={page === item.id ? 'page' : undefined}
                >
                  <item.icon size={17} strokeWidth={1.7} />
                  <span>{item.name}</span>
                </a>
              ))}
            </section>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="read-only-label">
            <LockKeyhole size={13} />
            <span>Read-only infrastructure</span>
          </div>
          <a
            href="https://github.com/homelab-0/nyctr"
            className="project-link"
            target="_blank"
            rel="noreferrer"
          >
            <GitBranch size={14} />
            Open-source on GitHub
            <ArrowUpRight size={13} />
          </a>
          <div className="sidebar-user">
            <span className="avatar">{(user.name || user.email).slice(0, 1).toUpperCase()}</span>
            <div>
              <strong>{user.name}</strong>
              <small>{member ? 'Member' : 'Administrator'}</small>
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
      <div className="main-window" inert={navOpen}>
        <header className="topbar">
          <div className="topbar-left">
            <button
              id="nav-toggle"
              className="icon-button mobile-menu"
              onClick={() => setNavOpen(true)}
              aria-label="Open navigation"
              aria-expanded={navOpen}
            >
              <Menu size={21} />
            </button>
            <span>{group}</span>
            <ChevronRight size={13} />
            <strong>{title}</strong>
          </div>
          <div className="topbar-right">
            <span className="connection-label">
              <span />
              {user.mode === 'demo' ? 'Demo workspace' : 'Authenticated workspace'}
            </span>
            <Badge>{member ? 'Member' : 'Admin'}</Badge>
          </div>
        </header>
        {user.mode === 'demo' && (
          <div className="demo-banner">
            <BlocksIcon size={14} />
            <span>
              <strong>Demo mode</strong> · Synthetic network data. Requests and reviews are saved in
              this demo workspace.
            </span>
            <Badge>Live collection disabled</Badge>
          </div>
        )}
        <main id="main-content" className="page-content" tabIndex={-1}>
          <Content key={`${page}-${user.id}`} page={page} params={route.params} member={member} />
        </main>
      </div>
    </div>
  );
}
