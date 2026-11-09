import { useState, type FormEvent } from 'react';
import { ArrowRight, ClipboardCheck, Clock3, Inbox, MessageSquare } from 'lucide-react';
import { dateTime, label, post, relativeTime, useApi } from '../api';
import { useAuth } from '../auth';
import type { AccessRequest } from '../types';
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  Field,
  InlineError,
  Loading,
  Modal,
  Notice,
  PageHeader,
  Status,
  Success,
} from '../components/ui';

function Review({
  request,
  onClose,
  onSaved,
}: {
  request: AccessRequest;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [decision, setDecision] = useState('reviewed');
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await post(`/requests/${encodeURIComponent(request.id)}/review`, {
        decision,
        note: note.trim(),
      });
      onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  return (
    <Modal title="Review access request" onClose={onClose}>
      <form onSubmit={submit} className="modal-body form-stack">
        <div className="request-destination">
          <span className="icon-tile">
            <ClipboardCheck size={23} />
          </span>
          <div>
            <strong>{request.domain}</strong>
            <small>
              {request.device_name} · {request.duration_minutes} minutes requested
            </small>
          </div>
        </div>
        <blockquote className="request-reason">{request.reason}</blockquote>
        <Field label="Review outcome">
          <select value={decision} onChange={(e) => setDecision(e.target.value)}>
            <option value="reviewed">Record as reviewed</option>
            <option value="denied">Deny request</option>
          </select>
        </Field>
        <Field label="Review note">
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            required
            minLength={3}
            maxLength={2000}
            rows={4}
            placeholder="Record the evidence and your decision…"
          />
        </Field>
        <Notice>
          This records your review and audit event only. No exception is created, and access remains
          unchanged.
        </Notice>
        <InlineError message={error} />
        <div className="modal-actions">
          <button className="button secondary" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button primary"
            type="submit"
            disabled={pending || note.trim().length < 3}
          >
            {pending ? 'Saving…' : 'Save review'}
            <ArrowRight size={15} />
          </button>
        </div>
      </form>
    </Modal>
  );
}

export default function Requests() {
  const result = useApi<AccessRequest[]>('/requests');
  const { user } = useAuth();
  const admin = user?.role === 'admin';
  const [filter, setFilter] = useState('all');
  const [review, setReview] = useState<AccessRequest | null>(null);
  const [success, setSuccess] = useState(false);
  const data = (result.data || []).filter((r) => filter === 'all' || r.status === filter);
  return (
    <>
      <PageHeader
        eyebrow={admin ? 'Access review' : 'Member portal'}
        title={admin ? 'Access requests' : 'My requests'}
        description={
          admin
            ? 'Review the reason, requested scope, and evidence before deciding what happens next.'
            : 'Follow the requests you have submitted and your administrator’s review notes.'
        }
      />
      <Notice>
        Request history is retained separately from the time-limited block inbox. A reviewed request
        is not an active exception.
      </Notice>
      {success && <Success>Review recorded. No network configuration was changed.</Success>}
      <div className="tabs">
        {['all', 'pending', 'reviewed', 'denied'].map((status) => (
          <button
            key={status}
            className={filter === status ? 'active' : ''}
            onClick={() => setFilter(status)}
          >
            {label(status)}
            <span>
              {(result.data || []).filter((r) => status === 'all' || r.status === status).length}
            </span>
          </button>
        ))}
      </div>
      {result.loading ? (
        <Loading />
      ) : result.error ? (
        <ErrorState message={result.error} retry={result.reload} />
      ) : !data.length ? (
        <Card>
          <Empty
            title={filter === 'all' ? 'No requests yet' : `No ${filter} requests`}
            text="Requests submitted from a recent block will appear here with their review history."
            icon={Inbox}
            action={
              <a className="button secondary" href={admin ? '#/blocks' : '#/portal'}>
                Open recent blocks
                <ArrowRight size={15} />
              </a>
            }
          />
        </Card>
      ) : (
        <div className="requests-stack">
          {data.map((request) => (
            <Card className="request-card" key={request.id}>
              <div className="request-card-heading">
                <span className="icon-tile">
                  <ClipboardCheck size={21} />
                </span>
                <div>
                  <h2>{request.domain}</h2>
                  <p>
                    {request.device_name} · Requested {relativeTime(request.created_at)}
                  </p>
                </div>
                <Status value={request.status} />
              </div>
              <div className="request-card-body">
                <div>
                  <span className="section-label">Reason for access</span>
                  <p>{request.reason}</p>
                  {request.review_note && (
                    <div className="review-note">
                      <MessageSquare size={16} />
                      <div>
                        <strong>Administrator’s review</strong>
                        <p>{request.review_note}</p>
                      </div>
                    </div>
                  )}
                </div>
                <div className="request-meta">
                  <span>
                    <Clock3 size={14} />
                    {request.duration_minutes} minutes requested
                  </span>
                  <small title={dateTime(request.created_at)}>{dateTime(request.created_at)}</small>
                  {admin && <small className="mono">Requester: {request.requester_id}</small>}
                  {admin && request.status === 'pending' && (
                    <button className="button primary small" onClick={() => setReview(request)}>
                      Review request
                      <ArrowRight size={14} />
                    </button>
                  )}
                  {request.status === 'reviewed' && (
                    <Badge>Review recorded · no access change</Badge>
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
      {review && (
        <Review
          request={review}
          onClose={() => setReview(null)}
          onSaved={() => {
            result.reload();
            setSuccess(true);
          }}
        />
      )}
    </>
  );
}
