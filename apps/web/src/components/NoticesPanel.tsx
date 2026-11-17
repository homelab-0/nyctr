import { useEffect, useState, type FormEvent } from 'react';
import { post, put, useApi } from '../api';
import { failureText } from '../lib/schedule';
import { ErrorState, Field, InlineError, Loading, Notice, Panel, Success } from './ui';

interface NoticeSend {
  id: string;
  kind: string;
  state: string;
  words: string;
  at?: string;
}

function kindWords(kind: string): string {
  if (kind === 'test') return 'Test';
  if (kind === 'request_waiting') return 'Someone is waiting';
  if (kind === 'lease_stuck') return 'An opening could not be removed';
  return 'Notice';
}

interface Notices {
  target: string;
  secret_ref: string;
  unsigned: boolean;
  signing: string;
  problem: string | null;
  editable: boolean;
  hosts: string[];
  recent: NoticeSend[];
}

/**
 * Where Nyctr sends a notice when someone is waiting. The form takes an address and the name of a
 * secret. The secret itself stays on the server, and the notice cannot approve anything.
 */
export function NoticesPanel() {
  const read = useApi<Notices>('/notices');
  const [saved, setSaved] = useState<Notices | null>(null);
  const [target, setTarget] = useState('');
  const [secretRef, setSecretRef] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<'save' | 'test' | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const now = saved ?? read.data;
  // The first read fills the form. A later save or test must not replace a draft typed since it began.
  useEffect(() => {
    if (!read.data) return;
    setTarget(read.data.target);
    setSecretRef(read.data.secret_ref);
  }, [read.data]);
  if (!now)
    return read.error ? (
      <ErrorState message={read.error} retry={read.reload} />
    ) : (
      <Loading text="Loading notices…" />
    );
  const changed = target !== now.target || secretRef !== now.secret_ref;
  const hosts = now.hosts.length
    ? `Whoever runs this server allows notices to ${now.hosts.join(', ')}.`
    : 'Only a public HTTPS address. Whoever runs this server can list another in NYCTR_NOTICE_HOSTS.';
  const run = async (kind: 'save' | 'test') => {
    const sentTarget = target;
    const sentSecret = secretRef;
    setBusy(kind);
    setError(null);
    setNote(null);
    const keepDraft = (next: Notices) => {
      setSaved(next);
      setTarget((current) => (current === sentTarget ? next.target : current));
      setSecretRef((current) => (current === sentSecret ? next.secret_ref : current));
    };
    try {
      if (kind === 'test') {
        const next = await post<Notices>('/notices/test');
        keepDraft(next);
        const latest = next.recent.find((item) => item.kind === 'test');
        if (!latest) setError('The test is not among the last few sends.');
        else if (latest.state !== 'sent') setError(latest.words);
        else setNote(latest.words);
      } else {
        keepDraft(await put<Notices>('/notices', { target, secret_ref: secretRef }));
        setNote('Saved.');
      }
    } catch (caught) {
      setError(failureText(caught));
    }
    setBusy(null);
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run('save');
  };
  return (
    <Panel
      title="Notices"
      hint="Nyctr can tell you when someone is waiting, at an address you set. The message has no key, and the link only works after you sign in."
    >
      <form className="form-stack" onSubmit={submit} aria-busy={busy !== null}>
        {!now.editable && <Notice>This is the demo workspace. Notices cannot be set here.</Notice>}
        {now.unsigned && now.editable && <Notice>{now.signing}</Notice>}
        {now.problem && <InlineError message={now.problem} />}
        <Field
          label="Address"
          hint="Where to send the notice. It must be https unless whoever runs this server listed it."
        >
          <input
            maxLength={500}
            disabled={!now.editable}
            spellCheck={false}
            value={target}
            onChange={(event) => {
              setTarget(event.target.value);
              setNote(null);
            }}
          />
        </Field>
        <Field
          label="Name of the secret"
          hint="The name of a secret on the server, starting with NYCTR_NOTICE_SECRET_. Leave it empty to send without a signature. Never type the secret itself."
        >
          <input
            maxLength={120}
            autoComplete="off"
            spellCheck={false}
            disabled={!now.editable}
            value={secretRef}
            onChange={(event) => {
              setSecretRef(event.target.value);
              setNote(null);
            }}
          />
        </Field>
        <p className="aside">{hosts}</p>
        {now.recent.length > 0 && (
          <>
            <p className="aside">The last few sends</p>
            <ul>
              {now.recent.map((item) => (
                <li key={item.id}>
                  {kindWords(item.kind)}
                  {item.at ? (
                    <>
                      {' '}
                      <time dateTime={item.at}>{new Date(item.at).toLocaleString()}</time>
                    </>
                  ) : null}
                  {`. ${item.words}`}
                </li>
              ))}
            </ul>
          </>
        )}
        <div className="bar">
          <span className="bar">
            <button
              className="button secondary"
              type="button"
              disabled={busy !== null || changed || !now.editable || !now.target}
              title={changed ? 'Save first: the test uses what is saved.' : undefined}
              onClick={() => void run('test')}
            >
              {busy === 'test' ? 'Sending…' : 'Test'}
            </button>
            <button
              className="button primary"
              type="submit"
              disabled={busy !== null || !changed || !now.editable}
            >
              {busy === 'save' ? 'Saving…' : 'Save'}
            </button>
          </span>
        </div>
        <InlineError message={error} />
        {note && <Success>{note}</Success>}
      </form>
    </Panel>
  );
}
