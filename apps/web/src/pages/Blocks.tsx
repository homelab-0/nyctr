import { useEffect, useState, type FormEvent } from 'react';
import {
  ArrowRight,
  CircleHelp,
  Clock3,
  FileText,
  Globe2,
  Inbox,
  Laptop,
  RefreshCw,
  ShieldQuestion,
} from 'lucide-react';
import { dateTime, label, post, relativeTime, useApi } from '../api';
import { useAuth } from '../auth';
import type { Block } from '../types';
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  EvidenceBadge,
  Field,
  InlineError,
  Loading,
  Modal,
  Notice,
  PageHeader,
  SearchInput,
  Success,
} from '../components/ui';

/** Collects user intent for one observed block; submission records a request, never an exception. */
function RequestForm({
  block,
  onClose,
  onSaved,
}: {
  block: Block;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [reason, setReason] = useState('');
  const [duration, setDuration] = useState(60);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** Persists the reason and requested duration after the API rechecks ownership and freshness. */
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setPending(true);
    setError(null);
    try {
      await post('/requests', {
        block_id: block.id,
        reason: reason.trim(),
        duration_minutes: duration,
      });
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setPending(false);
    }
  };
  return (
    <Modal title="Request access review" onClose={onClose}>
      <form onSubmit={submit} className="modal-body form-stack">
        <div className="request-destination">
          <span className="icon-tile">
            <Globe2 size={23} />
          </span>
          <div>
            <strong>{block.domain}</strong>
            <small>{block.device_name || 'Unattributed device'}</small>
          </div>
        </div>
        <Field label="Why do you need access?">
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Tell your administrator what you were trying to do…"
            required
            minLength={10}
            maxLength={2000}
            rows={4}
          />
        </Field>
        <Field label="Requested duration">
          <select value={duration} onChange={(e) => setDuration(Number(e.target.value))}>
            <option value={15}>15 minutes</option>
            <option value={30}>30 minutes</option>
            <option value={60}>1 hour</option>
            <option value={120}>2 hours</option>
            <option value={240}>4 hours</option>
          </select>
        </Field>
        <Notice>
          Your request is saved for administrator review. This release does not grant access or
          change DNS and firewall rules.
        </Notice>
        <InlineError message={error} />
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            className="button primary"
            disabled={pending || reason.trim().length < 10}
          >
            {pending ? 'Submitting…' : 'Submit request'}
            <ArrowRight size={15} />
          </button>
        </div>
      </form>
    </Modal>
  );
}

/**
 * Presents the API-authorized observation inbox for administrators or members.
 * Local expiry keeps an open screen current; the server owns identity checks and
 * request eligibility. Expiry hides inbox entries without deleting request history.
 */
export default function Blocks({ traffic = false }: { traffic?: boolean }) {
  const { user } = useAuth();
  const member = user?.role === 'member';
  const result = useApi<Block[]>('/blocks');
  const [selected, setSelected] = useState('');
  const [search, setSearch] = useState('');
  const [request, setRequest] = useState<Block | null>(null);
  const [saved, setSaved] = useState(false);
  const [now, setNow] = useState(Date.now());
  /** Advances the display clock so observations stop appearing requestable while this view stays open. */
  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 30000);
    return () => window.clearInterval(interval);
  }, []);
  const filtered = (result.data || []).filter(
    (block) =>
      Date.parse(block.expires_at) > now &&
      `${block.domain} ${block.device_name} ${block.source} ${block.reason}`
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  const block = filtered.find((b) => b.id === selected) || filtered[0];
  return (
    <>
      <PageHeader
        eyebrow={member ? 'Member portal' : 'Access & observations'}
        title={member ? 'Your recent blocks' : traffic ? 'Traffic & DNS' : 'Block inbox'}
        description={
          member
            ? 'Find a blocked connection on your devices and ask your administrator to review it.'
            : traffic
              ? 'Recorded block observations from supported collection channels.'
              : 'Recent blocks across personal devices, infrastructure, and unattributed sources.'
        }
        actions={
          <button className="button secondary" onClick={result.reload}>
            <RefreshCw size={15} />
            Refresh
          </button>
        }
      />
      {member ? (
        <div className="member-intro">
          <span className="icon-tile">
            <Laptop size={22} />
          </span>
          <div>
            <strong>Only your authorized devices appear here.</strong>
            <p>
              Old observations expire from this inbox. Submitted requests remain in your request
              history.
            </p>
          </div>
        </div>
      ) : (
        <Notice>
          Observations without a reliable user-device association stay in the administrator inbox.
          An IP address or DNS profile alone does not establish ownership.
        </Notice>
      )}
      {saved && (
        <Success>
          Request submitted for review.{' '}
          <a href="#/requests">
            View requests
            <ArrowRight size={14} />
          </a>
        </Success>
      )}
      {result.loading ? (
        <Loading text="Loading recent observations…" />
      ) : result.error ? (
        <ErrorState message={result.error} retry={result.reload} />
      ) : !result.data?.length ? (
        <Card>
          <Empty
            icon={Inbox}
            title="No recent blocks"
            text={
              member
                ? 'Fresh blocks on your assigned devices will appear here when a supported source observes them.'
                : 'Collected block observations will appear here. An empty inbox does not prove that nothing was blocked.'
            }
          />
        </Card>
      ) : (
        <div className="split-view block-view">
          <Card className="list-panel">
            <div className="table-toolbar">
              <SearchInput
                value={search}
                onChange={setSearch}
                placeholder="Search domains or devices…"
              />
            </div>
            <div className="list-summary">
              <span>{filtered.length} recent observations</span>
              <Badge>Time-limited inbox</Badge>
            </div>
            <div className="select-list block-list">
              {filtered.map((item) => (
                <button
                  key={item.id}
                  className={block?.id === item.id ? 'selected' : ''}
                  onClick={() => setSelected(item.id)}
                >
                  <div className="block-item-top">
                    <span className="icon-tile">
                      <Globe2 size={19} />
                    </span>
                    <div>
                      <strong>{item.domain}</strong>
                      <small>
                        <Laptop size={12} />
                        {item.device_name || 'Unattributed device'}
                      </small>
                    </div>
                  </div>
                  <div className="row-between">
                    <Badge>{label(item.source)}</Badge>
                    <span className="tiny muted">{relativeTime(item.observed_at)}</span>
                  </div>
                </button>
              ))}
              {!filtered.length && (
                <Empty
                  title={search ? 'No matching observations' : 'These observations have expired'}
                  text={
                    search
                      ? 'Try another domain or device name.'
                      : 'Refresh to check for new events. Submitted requests remain available.'
                  }
                />
              )}
            </div>
          </Card>
          {block && (
            <Card className="detail-panel">
              <div className="detail-heading">
                <div className="button-row">
                  <Badge tone="red">Blocked</Badge>
                  <EvidenceBadge kind={block.evidence_kind} />
                </div>
                <h2 className="domain-title">{block.domain}</h2>
                <p>
                  <Laptop size={15} />
                  {block.device_name || 'Unattributed device'}
                  <span className="dot-divider" />
                  {relativeTime(block.observed_at)}
                </p>
              </div>
              <div className="detail-body">
                <div className="reason-box">
                  <span className="section-label">Reported block reason</span>
                  <p>{block.reason || 'The source did not provide a block reason.'}</p>
                  <small>
                    <FileText size={12} />
                    {label(block.source)}
                  </small>
                </div>
                <div className="risk-summary">
                  <span className="icon-tile large amber">
                    <ShieldQuestion size={26} />
                  </span>
                  <div>
                    <span className="section-label">Risk assessment</span>
                    <h3>
                      {block.risk_score == null ? 'Not assessed' : `${block.risk_score} / 100`}
                    </h3>
                    <p>
                      {block.risk_explanation ||
                        'There is not enough verified evidence to assign a risk score.'}
                    </p>
                  </div>
                </div>
                <Notice tone="amber">
                  A missing block reason does not establish that a destination is safe. Review the
                  evidence before making an exception.
                </Notice>
                <dl className="details-list">
                  <div>
                    <dt>Observed</dt>
                    <dd>{dateTime(block.observed_at)}</dd>
                  </div>
                  <div>
                    <dt>Expires from inbox</dt>
                    <dd>{dateTime(block.expires_at)}</dd>
                  </div>
                  <div>
                    <dt>Attribution</dt>
                    <dd>{label(block.attribution)}</dd>
                  </div>
                  <div>
                    <dt>Source</dt>
                    <dd>{label(block.source)}</dd>
                  </div>
                </dl>
                <div className="detail-action">
                  <div>
                    <h3>Need to reach this destination?</h3>
                    <p>Explain what you need and request a temporary access review.</p>
                  </div>
                  <button
                    className="button primary full"
                    onClick={() => setRequest(block)}
                    disabled={Date.parse(block.expires_at) <= now}
                  >
                    Request access
                    <ArrowRight size={16} />
                  </button>
                  <small>
                    <Clock3 size={12} />
                    Submitting a request does not change network access.
                  </small>
                </div>
              </div>
            </Card>
          )}
        </div>
      )}
      <div className="page-footer">
        <span>
          <CircleHelp size={13} />
          {member
            ? 'Shared devices appear only when explicitly assigned to you.'
            : 'Only supported, collected observations are shown.'}
        </span>
        <a className="text-link" href="#/requests">
          Request history
          <ArrowRight size={13} />
        </a>
      </div>
      {request && (
        <RequestForm
          block={request}
          onClose={() => setRequest(null)}
          onSaved={() => setSaved(true)}
        />
      )}
    </>
  );
}
