import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { ArrowUp, Sparkles, X } from 'lucide-react';
import { post, useApi } from '../api';
import { hrefFor } from '../lib/links';
import type { AssistantAnswer, AssistantConfig, AssistantReference, AttentionItem } from '../types';
import { InlineError } from './ui';

interface Message {
  role: 'you' | 'nyctr';
  text: string;
  references?: AssistantReference[];
  provider?: string;
}

const SUGGESTED = [
  'What needs me first?',
  'Who is on the guest Wi-Fi?',
  'Which requests are waiting?',
  'Is any workload missing a firewall?',
  'What is open right now?',
];

/** Renders an answer, turning each [[ref]] the server kept into a link to that item. */
function Answer({ text, references = [] }: { text: string; references?: AssistantReference[] }) {
  const byRef = new Map(references.map((item) => [item.ref, item]));
  const parts: ReactNode[] = [];
  text.split(/(\[\[[A-Za-z0-9_-]+\]\])/).forEach((piece, index) => {
    const match = /^\[\[([A-Za-z0-9_-]+)\]\]$/.exec(piece);
    const item = match ? byRef.get(match[1]) : undefined;
    if (item)
      parts.push(
        <a key={index} className="cite" href={hrefFor(item.kind, item.id)}>
          {item.label}
        </a>,
      );
    else if (!match) parts.push(piece);
  });
  return <p>{parts}</p>;
}

/**
 * The assistant drawer. It can read and explain; it has no way to change anything.
 * Answers come from the server, which builds the evidence and removes any citation
 * to something the model was not shown.
 */
export default function Assistant({
  open,
  onClose,
  attention,
}: {
  open: boolean;
  onClose: () => void;
  attention: AttentionItem[];
}) {
  const config = useApi<AssistantConfig>('/assistant');
  const [messages, setMessages] = useState<Message[]>([]);
  const [draft, setDraft] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const end = useRef<HTMLDivElement>(null);
  const provider = config.data?.provider;

  /** Sends one question and appends the answer. A failure leaves the question visible. */
  const ask = async (question: string, findingId?: string) => {
    const text = question.trim();
    if (!text || pending) return;
    setMessages((list) => [...list, { role: 'you', text }]);
    setDraft('');
    setPending(true);
    setError(null);
    try {
      const result = await post<AssistantAnswer>('/assistant/ask', {
        question: text,
        finding_id: findingId ?? null,
      });
      setMessages((list) => [
        ...list,
        {
          role: 'nyctr',
          text: result.answer,
          references: result.references,
          provider: result.provider,
        },
      ]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  const askRef = useRef(ask);
  askRef.current = ask;

  useEffect(() => {
    /** Lets any screen open the drawer with a ready question, for example from a finding. */
    const onAsk = (event: Event) => {
      const detail = (event as CustomEvent<{ question?: string; findingId?: string }>).detail;
      if (detail?.question) void askRef.current(detail.question, detail.findingId);
    };
    window.addEventListener('nyctr:ask', onAsk);
    return () => window.removeEventListener('nyctr:ask', onAsk);
  }, []);
  useEffect(() => {
    if (open) input.current?.focus();
  }, [open]);
  useEffect(() => {
    end.current?.scrollIntoView?.({ block: 'end' });
  }, [messages, pending]);

  if (!open) return null;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void ask(draft);
  };
  return (
    <aside className="drawer" aria-label="Ask Nyctr">
      <header className="drawer-head">
        <span className="drawer-title">
          <Sparkles size={16} /> Ask Nyctr
        </span>
        <span className="tag">
          {provider === 'model'
            ? config.data?.model
            : provider === 'sample'
              ? 'Sample answers'
              : provider === 'off'
                ? 'No model connected'
                : '…'}
        </span>
        <button className="icon-button" onClick={onClose} aria-label="Close assistant">
          <X size={18} />
        </button>
      </header>
      <div className="drawer-body">
        {messages.length === 0 && (
          <div className="stack">
            <p className="aside">
              {provider === 'off'
                ? 'No model is connected, so questions are off. Set NYCTR_AI_BASE_URL and NYCTR_AI_MODEL on the server to turn them on. The list below is rule-based and always works.'
                : provider === 'sample'
                  ? 'Demo mode has no model connected. Answers here are assembled from the stored evidence by fixed templates, and say so.'
                  : 'It reads the same evidence you can see and links to it. It cannot change anything.'}
            </p>
            {attention.length > 0 && (
              <div className="stack tight">
                <h3>Needs you now</h3>
                <div className="rows boxed">
                  {attention.slice(0, 4).map((item) => (
                    <a
                      className="row"
                      key={`${item.kind}:${item.id}`}
                      href={hrefFor(item.kind, item.id)}
                    >
                      <i className={`dot ${item.severity}`} />
                      <span>
                        <span className="t">{item.title}</span>
                      </span>
                    </a>
                  ))}
                </div>
              </div>
            )}
            {provider !== 'off' && (
              <div className="stack tight">
                <h3>Try asking</h3>
                <div className="chips">
                  {SUGGESTED.map((question) => (
                    <button key={question} className="chip" onClick={() => void ask(question)}>
                      {question}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {messages.map((message, index) =>
          message.role === 'you' ? (
            <div className="msg you" key={index}>
              <p>{message.text}</p>
            </div>
          ) : (
            <div className="msg nyctr" key={index}>
              <Answer text={message.text} references={message.references} />
              {message.provider === 'sample' && (
                <span className="msg-foot">Sample answer. No model was used.</span>
              )}
            </div>
          ),
        )}
        {pending && <div className="msg nyctr thinking">Reading the evidence…</div>}
        <InlineError message={error} />
        <div ref={end} />
      </div>
      <form className="drawer-foot" onSubmit={submit}>
        <textarea
          ref={input}
          rows={2}
          value={draft}
          maxLength={600}
          disabled={provider === 'off'}
          placeholder={
            provider === 'off' ? 'Connect a model to ask questions' : 'Ask about your network'
          }
          aria-label="Your question"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              void ask(draft);
            }
          }}
        />
        <button
          className="button primary small"
          type="submit"
          disabled={pending || !draft.trim() || provider === 'off'}
          aria-label="Send question"
        >
          <ArrowUp size={16} />
        </button>
      </form>
    </aside>
  );
}
