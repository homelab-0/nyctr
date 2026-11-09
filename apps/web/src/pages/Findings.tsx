import { useEffect, useState } from 'react';
import { ArrowRight, FileText, GitBranch, ShieldCheck } from 'lucide-react';
import { useApi } from '../api';
import type { Finding } from '../types';
import {
  Card,
  Empty,
  ErrorState,
  Loading,
  Notice,
  PageHeader,
  SearchInput,
  Status,
} from '../components/ui';

/**
 * Displays supplied findings and their evidence, with links into the focused explorer.
 * Empty results are not a safety assessment; this view neither generates findings
 * nor authorizes changes to the resources they describe.
 */
export default function Findings({
  params,
  investigations = false,
}: {
  params: URLSearchParams;
  investigations?: boolean;
}) {
  const result = useApi<Finding[]>('/findings');
  const [selected, setSelected] = useState(params.get('selected') || '');
  const [search, setSearch] = useState('');
  useEffect(() => {
    if (params.get('selected')) setSelected(params.get('selected')!);
  }, [params.toString()]);
  const filtered =
    result.data?.filter((f) =>
      `${f.title} ${f.summary}`.toLowerCase().includes(search.toLowerCase()),
    ) || [];
  const finding = filtered.find((f) => f.id === selected) || filtered[0];
  return (
    <>
      <PageHeader
        eyebrow="Security posture"
        title={investigations ? 'Investigations' : 'Findings'}
        description={
          investigations
            ? 'Follow each finding into the resources, relationships, and evidence behind it.'
            : 'Review potential exposure with source evidence and relationship context.'
        }
      />
      <Notice>
        Findings describe the available evidence. Missing telemetry and unsupported policy layers
        remain unknown.
      </Notice>
      {result.loading ? (
        <Loading />
      ) : result.error ? (
        <ErrorState message={result.error} retry={result.reload} />
      ) : !result.data?.length ? (
        <Card>
          <Empty
            title="No findings to review"
            text="The first live collectors import inventory and policy configuration. Automated posture evaluation is a later milestone; no findings does not mean no risk."
            icon={ShieldCheck}
          />
        </Card>
      ) : (
        <div className="split-view">
          <Card className="list-panel">
            <div className="table-toolbar">
              <SearchInput value={search} onChange={setSearch} placeholder="Search findings…" />
            </div>
            <div className="select-list">
              {filtered.map((f) => (
                <button
                  key={f.id}
                  className={finding?.id === f.id ? 'selected' : ''}
                  onClick={() => setSelected(f.id)}
                >
                  <div className="row-between">
                    <Status value={f.severity} />
                    <span className="tiny muted">{f.resource_ids.length} resources</span>
                  </div>
                  <strong>{f.title}</strong>
                  <p>{f.summary}</p>
                </button>
              ))}
              {!filtered.length && (
                <Empty title="No matching findings" text="Try a different search." />
              )}
            </div>
          </Card>
          {finding && (
            <Card className="detail-panel">
              <div className="detail-heading">
                <div className="button-row">
                  <Status value={finding.severity} />
                  <Status value={finding.status} />
                </div>
                <h2>{finding.title}</h2>
                <p>{finding.summary}</p>
              </div>
              <div className="detail-body">
                <h3 className="section-label">Supporting evidence</h3>
                <div className="evidence-list">
                  {finding.evidence.map((item, index) => (
                    <div key={index}>
                      <FileText size={17} />
                      <p>{typeof item === 'string' ? item : JSON.stringify(item)}</p>
                    </div>
                  ))}
                </div>
                <div className="relationship-prompt">
                  <span className="icon-tile">
                    <GitBranch size={22} />
                  </span>
                  <h3>See the path behind this finding</h3>
                  <p>
                    Open a focused explorer with the implicated resources and their recorded
                    relationships.
                  </p>
                  <a
                    className="button primary"
                    href={`#/explorer?finding=${encodeURIComponent(finding.id)}`}
                  >
                    Explore finding path
                    <ArrowRight size={16} />
                  </a>
                </div>
                <Notice>
                  Reviewing a finding does not change a policy. This release collects evidence and
                  records requests; execution is not enabled.
                </Notice>
              </div>
            </Card>
          )}
        </div>
      )}
    </>
  );
}
