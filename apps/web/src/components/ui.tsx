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
    <header className="page-heading">
      <div>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
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
      <a href="#/explorer">All resources</a>
      <ChevronRight size={13} />
      <span>{current}</span>
    </div>
  );
}
