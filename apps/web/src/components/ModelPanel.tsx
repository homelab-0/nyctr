import { useEffect, useState, type FormEvent } from 'react';
import { post, put, useApi } from '../api';
import { failureText } from '../lib/schedule';
import type { ModelConnection, ModelTest, TraceStyle } from '../types';
import { ErrorState, Field, InlineError, Loading, Notice, Panel, Success } from './ui';

/** Each way to trace calls, in the words the list shows. */
const TRACE: Record<TraceStyle, string> = {
  off: 'Off: nothing extra is sent',
  standard: 'A trace number only',
  proxy: 'For a tracing proxy: what each call is for',
  proxy_body: 'For a tracing proxy, also inside the request',
};

/** What one test found, in plain words. Nothing the endpoint said is shown. */
function testText({ outcome, status }: ModelTest): string {
  if (outcome === 'reachable') return 'The model answered.';
  if (outcome === 'not_reachable')
    return 'Nyctr could not reach the endpoint. Check the address, and that the server can reach it.';
  if (outcome === 'too_slow') return 'No answer came within the time limit.';
  if (outcome === 'wrong_shape')
    return 'Something answered, but not the way a chat endpoint does. Check the address and the model.';
  if (status && status >= 300 && status < 400)
    return `The endpoint sent Nyctr somewhere else (HTTP ${status}). Nyctr never follows that, so nothing more was sent.`;
  if (status === 401 || status === 403)
    return `The endpoint refused the key (HTTP ${status}). Check the secret.`;
  if (status === 404) return 'The endpoint does not know that address or that model (HTTP 404).';
  return `The endpoint refused the question (HTTP ${status}).`;
}

type Draft = Pick<
  ModelConnection,
  'endpoint' | 'model' | 'secret_ref' | 'trace' | 'timeout_seconds'
>;
/**
 * The form as it opens: what is in force, tracing included, so the list never reads as on when
 * nothing is traced. With no model anywhere the server offers the style for a tracing proxy.
 */
const draftOf = (now: ModelConnection): Draft => ({
  endpoint: now.endpoint,
  model: now.model,
  secret_ref: now.secret_ref,
  trace: now.trace,
  timeout_seconds: now.timeout_seconds,
});

/**
 * Where the model is, set by an administrator. The key is never typed here: the form takes the
 * name of a secret kept on the server, and the server decides which hosts an endpoint may be on.
 */
export function ModelPanel() {
  const read = useApi<ModelConnection>('/model');
  const [saved, setSaved] = useState<ModelConnection | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<'save' | 'test' | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [result, setResult] = useState<ModelTest | null>(null);
  const now = saved ?? read.data;
  useEffect(() => {
    if (now) setDraft(draftOf(now));
  }, [now]);
  if (!now || !draft)
    return read.error ? (
      <ErrorState message={read.error} retry={read.reload} />
    ) : (
      <Loading text="Loading the model…" />
    );
  const changed = JSON.stringify(draft) !== JSON.stringify(draftOf(now));
  const edit = (change: Partial<Draft>) => {
    setDraft({ ...draft, ...change });
    setNote(null);
    setResult(null);
  };
  const run = async (kind: 'save' | 'test') => {
    setBusy(kind);
    setError(null);
    setNote(null);
    setResult(null);
    try {
      if (kind === 'test') setResult(await post<ModelTest>('/model/test'));
      else {
        setSaved(await put<ModelConnection>('/model', draft));
        setNote('Saved. Press Test to check that the model answers.');
      }
    } catch (e) {
      setError(failureText(e));
    }
    setBusy(null);
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run('save');
  };
  const [least, most] = now.seconds;
  return (
    <Panel
      title="Model"
      hint="The model answers questions and explains findings. It sees only the evidence Nyctr shows it, and it cannot change anything."
    >
      <form className="form-stack" onSubmit={submit} aria-busy={busy !== null}>
        {!now.editable ? (
          <Notice>
            {now.connected
              ? 'This is the demo workspace. Its model was set on the server and cannot be changed here.'
              : 'This is the demo workspace. It answers from samples, and a model cannot be connected here.'}
          </Notice>
        ) : (
          !now.connected &&
          !now.problem && (
            <Notice>
              No model is connected, so the assistant is off. The list of what needs you is
              rule-based and always works.
            </Notice>
          )
        )}
        {now.problem && (
          <InlineError
            message={
              // What was saved here, or what the server itself was given: the sentence says which.
              now.source === 'console'
                ? `The saved model cannot be used right now. ${now.problem}`
                : now.problem
            }
          />
        )}
        <Field
          label="Endpoint"
          hint={
            !now.editable
              ? 'The address of a chat endpoint.'
              : now.hosts.length
                ? `The address of a chat endpoint, for example ${now.hosts[0]}/v1. Whoever runs the Nyctr server allows these servers, each exactly as written: ${now.hosts.join(', ')}.`
                : 'The address of a chat endpoint. Whoever runs the Nyctr server has not allowed any server yet (NYCTR_MODEL_HOSTS).'
          }
        >
          <input
            required
            maxLength={300}
            disabled={!now.editable}
            value={draft.endpoint}
            onChange={(e) => edit({ endpoint: e.target.value })}
          />
        </Field>
        <Field label="Model" hint="The model's name, as the endpoint knows it.">
          <input
            required
            maxLength={200}
            disabled={!now.editable}
            value={draft.model}
            onChange={(e) => edit({ model: e.target.value })}
          />
        </Field>
        <Field
          label="Name of the secret"
          hint={
            'The name of a secret on the server that holds the key. It starts with NYCTR_MODEL_SECRET_. Never type the key itself here. Leave it empty if the endpoint needs no key.' +
            (now.key === 'server'
              ? ' Right now the key set on the server with NYCTR_AI_API_KEY is used.'
              : '')
          }
        >
          <input
            maxLength={120}
            autoComplete="off"
            spellCheck={false}
            disabled={!now.editable}
            value={draft.secret_ref}
            onChange={(e) => edit({ secret_ref: e.target.value })}
          />
        </Field>
        {/* Each field keeps its own height: the two hints are not the same length. */}
        <div className="grid2" style={{ alignItems: 'start' }}>
          <Field
            label="Tracing"
            hint={
              'A trace lets a tracing proxy in front of the model group calls and review them. It says what a call is for and which Nyctr version sent it, never a person, a device or the key.' +
              (now.source === 'deployment'
                ? ' The choice shown was set on the server (NYCTR_AI_TRACE). Saving keeps it unless you pick another.'
                : '')
            }
          >
            <select
              disabled={!now.editable}
              value={draft.trace}
              onChange={(e) => edit({ trace: e.target.value as TraceStyle })}
            >
              {now.styles.map((style) => (
                <option key={style} value={style}>
                  {TRACE[style]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Time limit" hint={`Seconds to wait for an answer, ${least} to ${most}.`}>
            <input
              type="number"
              required
              min={least}
              max={most}
              disabled={!now.editable}
              value={draft.timeout_seconds}
              onChange={(e) => edit({ timeout_seconds: Number(e.target.value) })}
            />
          </Field>
        </div>
        <div className="bar">
          <span className="aside">
            {now.source === 'console' && 'Saved here. It replaces what was set on the server.'}
            {now.source === 'deployment' &&
              'This starting value was set on the server with NYCTR_AI_BASE_URL and NYCTR_AI_MODEL. What you save here replaces it.'}
            {now.source === 'none' &&
              now.editable &&
              'Nothing is set on the server and nothing is saved here.'}
          </span>
          <span className="bar">
            <button
              className="button secondary"
              type="button"
              disabled={busy !== null || changed || !now.connected}
              title={changed ? 'Save first: the test uses what is saved.' : undefined}
              onClick={() => void run('test')}
            >
              {busy === 'test' ? 'Testing…' : 'Test'}
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
        {result &&
          (result.outcome === 'reachable' ? (
            <Success>{testText(result)}</Success>
          ) : (
            <InlineError message={testText(result)} />
          ))}
      </form>
    </Panel>
  );
}
