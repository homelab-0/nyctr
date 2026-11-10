import { useEffect, useRef, type ReactNode, type ComponentType, type SVGProps } from 'react';
import {
  AlertCircle,
  ArrowRight,
  Box,
  Cable,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Database,
  Globe2,
  HardDrive,
  Laptop,
  Loader2,
  Network,
  Router,
  Search,
  Server,
  Shield,
  Wifi,
  X,
} from 'lucide-react';
import { label } from '../api';

export type IconComponent = ComponentType<
  SVGProps<SVGSVGElement> & { size?: number; strokeWidth?: number }
>;
/** Maps normalized resource kinds to icons, including a fallback for newly supported providers. */
export const kindIcon = (kind: string): IconComponent =>
  ({
    site: Globe2,
    gateway: Router,
    switch: Cable,
    access_point: Wifi,
    network: Network,
    client: Laptop,
    host: Server,
    workload: Box,
    bridge: Cable,
    dns_profile: Database,
    domain: Globe2,
    policy: Shield,
  })[kind] || HardDrive;

/** Renders the shared wordmark; the adjacent text supplies the decorative image's accessible name. */
export function Brand({ small = false }: { small?: boolean }) {
  return (
    <span className={`brand ${small ? 'small' : ''}`}>
      <img src="/nyctr-mark.svg" alt="" />
      <span>NYCTR</span>
    </span>
  );
}
/** Adds a consistent visual label; tone is presentation and never an authorization decision. */
export function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
/** Colors a reported status without inferring that a reviewed request grants network access. */
export function Status({ value }: { value: string }) {
  const tone = /high|denied|failed|error|blocked/.test(value)
    ? 'red'
    : /medium|pending|partial|unattributed|unknown/.test(value)
      ? 'amber'
      : /connected|ready|reviewed|observed/.test(value)
        ? 'green'
        : 'blue';
  return <Badge tone={tone}>{label(value)}</Badge>;
}
/** Keeps observed, configured, and inferred source provenance visually distinct. */
export function EvidenceBadge({ kind }: { kind: string }) {
  return (
    <Badge tone={kind === 'observed' ? 'green' : kind === 'configured' ? 'blue' : 'amber'}>
      {label(kind)}
    </Badge>
  );
}
/** Supplies a view's heading, explanatory scope, and optional contextual actions. */
export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div>
        {eyebrow && <span className="aside">{eyebrow}</span>}
        <h1 className="display d2">{title}</h1>
        <p className="lede">{description}</p>
      </div>
      {actions && <div className="button-row">{actions}</div>}
    </header>
  );
}
/** Groups related view content with an optional semantic heading and its associated action. */
export function Card({
  title,
  action,
  children,
  className = '',
}: {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {title && (
        <div className="card-heading">
          <h2>{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
/** Explains why a result set is empty and optionally provides a relevant recovery action. */
export function Empty({
  title,
  text,
  icon: Icon = Search,
  action,
}: {
  title: string;
  text: string;
  icon?: IconComponent;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon size={24} />
      </span>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}
/** Announces an in-progress read through a live status region. */
export function Loading({ text = 'Loading your workspace…' }: { text?: string }) {
  return (
    <div className="loading" role="status">
      <Loader2 className="spin" size={20} />
      <span>{text}</span>
    </div>
  );
}
/** Announces a failed view load and offers retry only when the caller can repeat the read. */
export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="error-state" role="alert">
      <AlertCircle size={20} />
      <div>
        <strong>Unable to load this view</strong>
        <p>{message}</p>
      </div>
      {retry && (
        <button className="button secondary small" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  );
}
/** Keeps evidence limitations and capability boundaries alongside the affected UI. */
export function Notice({ children, tone = 'blue' }: { children: ReactNode; tone?: string }) {
  return (
    <div className={`notice ${tone}`}>
      <CircleHelp size={16} />
      <div>{children}</div>
    </div>
  );
}
/** Announces form failures without reserving an empty alert when there is no error. */
export function InlineError({ message }: { message: string | null }) {
  return message ? (
    <div className="inline-error" role="alert">
      <AlertCircle size={15} />
      {message}
    </div>
  ) : null;
}
/** Announces the specific completed operation supplied by the caller through a status region. */
export function Success({ children }: { children: ReactNode }) {
  return (
    <div className="success" role="status">
      <CheckCircle2 size={16} />
      {children}
    </div>
  );
}
/** Pairs a server-derived count with a caption that preserves its measurement scope. */
export function Metric({
  label: text,
  value,
  caption,
  icon: Icon,
}: {
  label: string;
  value: number | string;
  caption: string;
  icon: IconComponent;
}) {
  return (
    <div className="metric card">
      <div className="metric-top">
        <span>{text}</span>
        <Icon size={17} />
      </div>
      <strong>{value}</strong>
      <small>{caption}</small>
    </div>
  );
}
/** Styles navigation as an action while preserving anchor keyboard and browser behavior. */
export function LinkButton({
  href,
  children,
  primary = false,
}: {
  href: string;
  children: ReactNode;
  primary?: boolean;
}) {
  return (
    <a className={`button ${primary ? 'primary' : 'secondary'}`} href={href}>
      {children}
      <ArrowRight size={15} />
    </a>
  );
}
/** Associates a wrapped form control with its visible label and optional explanatory hint. */
export function Field({
  label: text,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span>{text}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}
/** Exposes a controlled local filter with an accessible label independent of placeholder text. */
export function SearchInput({
  value,
  onChange,
  placeholder = 'Search…',
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="search-field">
      <Search size={16} />
      <span className="sr-only">{placeholder}</span>
      <input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </label>
  );
}
/**
 * Uses a native modal dialog for focus containment and background interaction blocking.
 * Escape and genuine backdrop clicks delegate closure to the owner; a ref keeps
 * the latest callback available without reopening the dialog on each render.
 */
export function Modal({
  title,
  children,
  onClose,
  className = '',
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  className?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    element.showModal();
    /** Lets the owner remove dialog state instead of leaving an implicitly closed mounted modal. */
    const onCancel = (event: Event) => {
      event.preventDefault();
      closeRef.current();
    };
    element.addEventListener('cancel', onCancel);
    return () => {
      element.removeEventListener('cancel', onCancel);
      element.close();
    };
  }, []);
  return (
    <dialog
      ref={dialog}
      className={`modal ${className}`}
      aria-labelledby="modal-title"
      onClick={(e) => {
        if (e.target === dialog.current) {
          const rect = dialog.current.getBoundingClientRect();
          if (
            e.clientX < rect.left ||
            e.clientX > rect.right ||
            e.clientY < rect.top ||
            e.clientY > rect.bottom
          )
            onClose();
        }
      }}
    >
      <div className="modal-heading">
        <h2 id="modal-title">{title}</h2>
        <button className="icon-button" onClick={onClose} aria-label="Close dialog">
          <X size={19} />
        </button>
      </div>
      {children}
    </dialog>
  );
}
/** Preserves a route back to the full graph when the explorer is focused on one resource. */
export function Breadcrumb({ current }: { current: string }) {
  return (
    <div className="breadcrumb">
      <a href="#/map">Whole map</a>
      <ChevronRight size={13} />
      <span>{current}</span>
    </div>
  );
}

/** A panel with an optional heading row. The building block of every console screen. */
export function Panel({
  title,
  hint,
  action,
  children,
  flush = false,
  className = '',
}: {
  title?: ReactNode;
  hint?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <div className="panel-head">
          <div>
            <h2>{title}</h2>
            {hint && <p>{hint}</p>}
          </div>
          {action}
        </div>
      )}
      <div className={`panel-body ${flush ? 'flush' : ''}`}>{children}</div>
    </section>
  );
}
/** A segmented control. Options may carry a count shown beside the label. */
export function Seg<T extends string>({
  value,
  onChange,
  options,
  label: name,
}: {
  value: T;
  onChange: (value: T) => void;
  options: { id: T; name: string; count?: number }[];
  label: string;
}) {
  return (
    <div className="seg" role="group" aria-label={name}>
      {options.map((option) => (
        <button
          key={option.id}
          type="button"
          aria-pressed={value === option.id}
          onClick={() => onChange(option.id)}
        >
          {option.name}
          {option.count !== undefined && <span className="n">{option.count}</span>}
        </button>
      ))}
    </div>
  );
}
/** Names a risk band for a score. A missing score is unknown, never low. */
export const bandOf = (score: number | null | undefined) =>
  score === null || score === undefined
    ? 'unknown'
    : score <= 30
      ? 'low'
      : score <= 60
        ? 'medium'
        : 'high';
/** Shows a risk score, or a hatched "No score" when Nyctr could not assess it. */
export function Score({ value, big = false }: { value: number | null | undefined; big?: boolean }) {
  const band = bandOf(value);
  return (
    <span
      className={`score ${band} ${big ? 'big' : ''}`}
      title={band === 'unknown' ? 'Unknown risk, not low risk' : `${band} risk`}
    >
      {band === 'unknown' ? 'No score' : value}
    </span>
  );
}
/** The 0 to 100 scale with the score marked and, when given, the automatic limit. */
export function RiskScale({ value, limit }: { value: number | null; limit?: number }) {
  if (value === null)
    return (
      <div className="scale unknown" role="img" aria-label="Risk is unknown">
        <i />
      </div>
    );
  return (
    <div className="scale" role="img" aria-label={`Risk score ${value} out of 100`}>
      <i />
      <i />
      <i />
      <b style={{ left: `${Math.min(100, Math.max(0, value))}%` }} />
      {limit !== undefined && (
        <span className="limit" style={{ left: `${limit}%` }}>
          <span>Automatic up to {limit}</span>
        </span>
      )}
    </div>
  );
}
/** Lists why a score is what it is, in the order the scorer produced. */
export function Factors({ items }: { items: { label: string; points: number | null }[] }) {
  return (
    <ul className="factors">
      {items.map((item) => (
        <li key={item.label}>
          <span className="pts">{item.points === null ? '?' : `+${item.points}`}</span>
          <span>{item.label}</span>
        </li>
      ))}
    </ul>
  );
}
const SOURCES: Record<string, { letter: string; tone: string; name: string }> = {
  unifi_network: { letter: 'U', tone: 's-unifi', name: 'UniFi' },
  unifi_fabric: { letter: 'U', tone: 's-unifi', name: 'UniFi Site Manager' },
  proxmox: { letter: 'P', tone: 's-pve', name: 'Proxmox' },
  nextdns: { letter: 'D', tone: 's-dns', name: 'NextDNS' },
  nyctr: { letter: 'N', tone: 's-nyctr', name: 'Nyctr' },
};
/** Describes a provider for chips, colours and plain names. */
export const sourceOf = (provider: string) =>
  SOURCES[provider] || { letter: '?', tone: '', name: label(provider) };
/** A coloured letter chip naming where a fact came from, optionally with its name. */
export function SourceTag({
  provider,
  named = false,
  big = false,
}: {
  provider: string;
  named?: boolean;
  big?: boolean;
}) {
  const source = sourceOf(provider);
  const chip = (
    <span className={`src ${source.tone} ${big ? 'big' : ''}`} title={source.name}>
      {source.letter}
    </span>
  );
  return named ? (
    <span className="srcn">
      {chip}
      {source.name}
    </span>
  ) : (
    chip
  );
}
const EVIDENCE: Record<string, string> = {
  observed: 'Seen happening',
  configured: 'A setting',
  inferred: 'Worked out by Nyctr',
  assigned: 'Tied to a device by you',
  unverified: 'Device label not confirmed',
  unattributed: 'No device known',
};
/** Line style carries the evidence kind: solid observed, dashed configured, dotted inferred. */
export function Evidence({ kind, plain = false }: { kind: string; plain?: boolean }) {
  const style =
    kind === 'observed' || kind === 'assigned'
      ? 'observed'
      : kind === 'configured'
        ? 'configured'
        : 'inferred';
  return (
    <span className="evw">
      <i className={`ev ${style}`} />
      {plain ? label(kind) : EVIDENCE[kind] || label(kind)}
    </span>
  );
}
/** A term and value list for facts about one thing. */
export function KV({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([term, value]) => (
        <div key={term} style={{ display: 'contents' }}>
          <dt>{term}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
/** An on/off switch with its state exposed to assistive technology. */
export function Switch({
  checked,
  onChange,
  label: text,
  disabled = false,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label className="switch">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={text}
        disabled={disabled}
        onClick={() => onChange(!checked)}
      />
      {checked ? 'On' : 'Off'}
    </label>
  );
}
/** A bounded number control used inside written rules. */
export function Stepper({
  value,
  onChange,
  min,
  max,
  step = 1,
  label: text,
}: {
  value: number;
  onChange: (value: number) => void;
  min: number;
  max: number;
  step?: number;
  label: string;
}) {
  return (
    <span className="stepper" role="group" aria-label={text}>
      <button
        type="button"
        aria-label={`Lower ${text}`}
        disabled={value <= min}
        onClick={() => onChange(Math.max(min, value - step))}
      >
        −
      </button>
      <output>{value}</output>
      <button
        type="button"
        aria-label={`Raise ${text}`}
        disabled={value >= max}
        onClick={() => onChange(Math.min(max, value + step))}
      >
        +
      </button>
    </span>
  );
}
