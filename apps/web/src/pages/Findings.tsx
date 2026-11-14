import { useEffect, useState } from 'react';
import { Sparkles } from 'lucide-react';
import { post, useApi } from '../api';
import { everyText, useSchedule } from '../lib/schedule';
import { Empty, ErrorState, InlineError, Loading, Panel, Seg, kindIcon } from '../components/ui';
import { askNyctr } from '../lib/links';
import type { Finding, FindingChecks, Insight, Resource } from '../types';

const ORDER = ['high', 'medium', 'low', 'informational'];
const TONE: Record<string, string> = { high: 'red', medium: 'yellow', low: '', informational: '' };

/** The generated explanation of one finding, clearly marked as such and never shown as evidence. */
function Read({ finding }: { finding: Finding }) {
  const [insight, setInsight] = useState<Insight | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setInsight(null);
    setError(null);
  }, [finding.id]);
  /** Asks the server for the insight; it is cached there until the finding's evidence changes. */
  const load = async () => {
    setPending(true);
    setError(null);
    try {
      setInsight(await post<Insight>(`/findings/${encodeURIComponent(finding.id)}/insight`));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  return (
    <section className="ainote" aria-label="Nyctr's read">
      <header>
        <span className="ainote-title">
          <Sparkles size={15} /> Nyctr's read
        </span>
        {insight && (
          <span className="tag">
            {insight.provider === 'sample' ? 'Sample, no model' : insight.model}
          </span>
        )}
      </header>
      {!insight ? (
        <div className="stack tight">
          <p className="aside">
            An explanation written from the evidence above. It is commentary, not evidence, and it
            cannot change anything.
          </p>
          <InlineError message={error} />
          <div className="button-row">
            <button
              className="button secondary small"
              disabled={pending}
              onClick={() => void load()}
            >
              {pending ? 'Reading…' : 'Explain this finding'}
            </button>
          </div>
        </div>
      ) : (
        <div className="stack">
          <p className="ainote-take">{insight.take}</p>
          <div>
            <h3>Why</h3>
            <ul className="bullets">
              {insight.reasoning.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>
          <div>
            <h3>What you could do</h3>
            <ol className="bullets numbered">
              {insight.next_steps.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ol>
          </div>
          <div className="bar">
            <span className="aside">Confidence: {insight.confidence}</span>
            <button
              className="button quiet small"
              onClick={() => askNyctr(`Tell me more about "${finding.title}"`, finding.id)}
            >
              Ask about this
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

/** What the rules look at and what they never do, so an empty list is not read as "all checked". */
function Checked({ cover }: { cover: FindingChecks }) {
  return (
    <Panel title="What Nyctr checks" hint="Only these. Nothing else can produce a finding.">
      <div className="stack">
        <ul className="bullets">
          {cover.checks.map((check) => (
            <li key={check.text}>
              {check.text}
              {!check.active && (
                <span className="muted">
                  {' '}
                  (no collected source reports this, so there is nothing to check)
                </span>
              )}
            </li>
          ))}
        </ul>
        {cover.not_checked.length > 0 && (
          <div className="note hatch">
            <div>
              <b>Collected but not checked</b>
              <p>
                {cover.not_checked.join(', ')}. You can see these on the Map and in Inventory, but
                no check reads them, so nothing wrong with them would show up here.
              </p>
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

/** Findings from fixed rules over stored evidence, each with the evidence and what it does not prove. */
export default function Findings({ params }: { params: URLSearchParams }) {
  const findings = useApi<Finding[]>('/findings');
  const resources = useApi<Resource[]>('/resources');
  const cover = useApi<FindingChecks>('/findings/checks').data;
  const every = everyText(useSchedule().data);
  const [show, setShow] = useState<'open' | 'resolved'>('open');
  const [selected, setSelected] = useState<string | null>(params.get('id'));
  useEffect(() => {
    if (params.get('id')) setSelected(params.get('id'));
  }, [params]);
  if (findings.loading) return <Loading text="Loading findings…" />;
  if (findings.error) return <ErrorState message={findings.error} retry={findings.reload} />;
  const all = [...(findings.data || [])].sort(
    (a, b) =>
      ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || a.title.localeCompare(b.title),
  );
  const list = all.filter((item) =>
    show === 'open' ? item.status === 'open' : item.status !== 'open',
  );
  const finding = list.find((item) => item.id === selected) || list[0];
  const byId = new Map((resources.data || []).map((item) => [item.id, item]));
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d2">Findings</h1>
          <p className="lede">
            Produced by fixed rules from what your sources reported. Each one says what the evidence
            is and what it does not prove.
          </p>
        </div>
        <Seg
          label="Which findings"
          value={show}
          onChange={(value) => {
            setShow(value);
            setSelected(null);
          }}
          options={[
            {
              id: 'open',
              name: 'Open',
              count: all.filter((item) => item.status === 'open').length,
            },
            {
              id: 'resolved',
              name: 'Resolved',
              count: all.filter((item) => item.status !== 'open').length,
            },
          ]}
        />
      </header>
      {!finding ? (
        <Empty
          title={
            show !== 'open'
              ? 'Nothing resolved yet'
              : cover
                ? `No open findings from the ${cover.checks.length} checks listed below`
                : 'No open findings'
          }
          text={
            every
              ? `Findings are re-checked after every collection, ${every}.`
              : 'Findings are re-checked when a source is collected.'
          }
        />
      ) : (
        <div className="split wide-side">
          <Panel flush>
            <div className="rows">
              {list.map((item) => (
                <button
                  className={`row ${finding.id === item.id ? 'on' : ''}`}
                  key={item.id}
                  onClick={() => setSelected(item.id)}
                >
                  <i className={`dot ${item.severity}`} />
                  <span>
                    <span className="t">{item.title}</span>
                  </span>
                  <span className={`tag ${TONE[item.severity]}`}>{item.severity}</span>
                </button>
              ))}
            </div>
          </Panel>
          <div className="stack">
            <Panel>
              <div className="stack">
                <div className="bar">
                  <span className={`tag ${TONE[finding.severity]}`}>{finding.severity}</span>
                  <span className="aside">
                    {finding.id.startsWith('auto:') ? 'Found by a Nyctr rule' : 'Example finding'}
                  </span>
                </div>
                <h2 className="display d3">{finding.title}</h2>
                <p className="lede">{finding.summary}</p>
                <div>
                  <h3>Evidence</h3>
                  <ul className="bullets">
                    {finding.evidence.map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ul>
                </div>
                {finding.resource_ids.length > 0 && (
                  <div>
                    <h3>Involved</h3>
                    <div className="chips">
                      {finding.resource_ids.map((id) => {
                        const item = byId.get(id);
                        const Icon = kindIcon(item?.kind || '');
                        return (
                          <a
                            className="chip"
                            key={id}
                            href={`#/map?focus=${encodeURIComponent(id)}`}
                          >
                            <Icon size={14} /> {item?.name || id}
                          </a>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </Panel>
            <Read key={finding.id} finding={finding} />
          </div>
        </div>
      )}
      {cover && <Checked cover={cover} />}
    </div>
  );
}
