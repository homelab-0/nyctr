import { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Expand,
  GitBranch,
  Layers2,
  Network,
  PanelRightClose,
  RefreshCw,
} from 'lucide-react';
import { dateTime, label, stringify, useApi } from '../api';
import type { Finding, Graph, Integration, Resource } from '../types';
import {
  Badge,
  Breadcrumb,
  Card,
  Empty,
  ErrorState,
  EvidenceBadge,
  Loading,
  Notice,
  PageHeader,
  SearchInput,
  kindIcon,
} from '../components/ui';
import { NetworkGraph } from '../components/NetworkGraph';

/**
 * Explores the full snapshot, a server-bounded neighborhood, or a finding's evidence.
 * Resource/relationship inspectors retain provenance and collection age; connectivity
 * in this view does not assert a successful end-to-end traffic path.
 */
export default function Explorer({ params }: { params: URLSearchParams }) {
  const focus = params.get('focus') || undefined;
  const findingId = params.get('finding');
  const depth = Number(params.get('depth') || 1);
  const result = useApi<Graph>(
    focus ? `/graph?focus=${encodeURIComponent(focus)}&depth=${depth}` : '/graph',
  );
  const findings = useApi<Finding[]>(findingId ? '/findings' : null);
  const integrations = useApi<Integration[]>('/integrations');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [tab, setTab] = useState('overview');
  useEffect(() => {
    setSelectedId(focus ?? null);
    setSelectedEdge(null);
    setSearch('');
  }, [focus, findingId]);
  const finding = findings.data?.find((f) => f.id === findingId);
  /** Includes finding-linked edges and their endpoints without inventing missing resources. */
  const graph = useMemo(() => {
    if (!result.data) return null;
    if (!finding || focus) return result.data;
    const ids = new Set(finding.resource_ids);
    const edges = result.data.edges.filter(
      (e) => finding.relationship_ids.includes(e.id) || (ids.has(e.source) && ids.has(e.target)),
    );
    edges.forEach((e) => {
      ids.add(e.source);
      ids.add(e.target);
    });
    return { nodes: result.data.nodes.filter((n) => ids.has(n.id)), edges };
  }, [result.data, finding, focus]);
  const selected = graph?.nodes.find((n) => n.id === selectedId);
  const edge = graph?.edges.find((e) => e.id === selectedEdge);
  const currentFocus = graph?.nodes.find((n) => n.id === focus);
  const collectionErrors =
    integrations.data?.filter((i) => i.last_error || /error|failed/i.test(i.status)) || [];
  const searchResults = search
    ? graph?.nodes
        .filter((r) =>
          `${r.name} ${r.kind} ${r.provider}`.toLowerCase().includes(search.toLowerCase()),
        )
        .slice(0, 7)
    : [];
  /** Opens a one-hop neighborhood while retaining any active finding context in the route. */
  const goFocus = (resource: Resource) => {
    window.location.hash = `/explorer?focus=${encodeURIComponent(resource.id)}&depth=1${findingId ? `&finding=${encodeURIComponent(findingId)}` : ''}`;
  };
  return (
    <>
      <PageHeader
        eyebrow="Network intelligence"
        title="Network explorer"
        description="Follow the relationships. Inspect the evidence. Understand what is connected."
        actions={
          <button className="button secondary" onClick={result.reload}>
            <RefreshCw size={15} />
            Refresh snapshot
          </button>
        }
      />
      {collectionErrors.length > 0 && (
        <Notice tone="amber">
          Collection needs attention for {collectionErrors.map((i) => i.name).join(', ')}. The graph
          retains the last valid evidence; inspect collection timestamps before relying on it.{' '}
          <a href="#/integrations" className="text-link">
            View source health
            <ArrowRight size={12} />
          </a>
        </Notice>
      )}
      {finding && (
        <div className="finding-context">
          <span className="icon-tile amber">
            <GitBranch size={20} />
          </span>
          <div>
            <small>Finding context</small>
            <strong>{finding.title}</strong>
            <p>{finding.summary}</p>
          </div>
          <a className="text-link" href={`#/findings?selected=${encodeURIComponent(finding.id)}`}>
            View finding
            <ArrowRight size={14} />
          </a>
        </div>
      )}
      <div className="explorer-toolbar">
        <div className="toolbar-left">
          <Badge tone="blue">
            <Network size={12} />
            {finding ? 'Finding relationships' : 'Relationship view'}
          </Badge>
          {currentFocus && <Breadcrumb current={currentFocus.name} />}
        </div>
        <div className="toolbar-right">
          {focus && (
            <label className="depth-control">
              Neighborhood
              <select
                aria-label="Relationship depth"
                value={depth}
                onChange={(e) => {
                  window.location.hash = `/explorer?focus=${encodeURIComponent(focus)}&depth=${e.target.value}${findingId ? `&finding=${encodeURIComponent(findingId)}` : ''}`;
                }}
              >
                <option value="1">1 hop</option>
                <option value="2">2 hops</option>
                <option value="3">3 hops</option>
              </select>
            </label>
          )}
          <div className="graph-search">
            <SearchInput value={search} onChange={setSearch} placeholder="Find in this graph…" />
            {Boolean(search) && (
              <div className="search-results">
                {searchResults?.length ? (
                  searchResults.map((resource) => (
                    <button
                      key={resource.id}
                      onClick={() => {
                        setSelectedId(resource.id);
                        setSelectedEdge(null);
                        setSearch('');
                      }}
                    >
                      <span>{resource.name}</span>
                      <small>{label(resource.kind)}</small>
                    </button>
                  ))
                ) : (
                  <p>No matching resources in this view.</p>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
      {result.loading || (findingId && findings.loading) ? (
        <Card>
          <Loading text="Loading network relationships…" />
        </Card>
      ) : result.error || findings.error ? (
        <ErrorState
          message={result.error || findings.error || ''}
          retry={() => {
            result.reload();
            findings.reload();
          }}
        />
      ) : graph?.nodes.length ? (
        <div className={`explorer-layout ${selected || edge ? 'has-inspector' : ''}`}>
          <div className="graph-container">
            <NetworkGraph
              graph={graph}
              selectedId={selectedId}
              selectedEdge={selectedEdge}
              onSelect={(r) => {
                setSelectedId(r.id);
                setSelectedEdge(null);
                setTab('overview');
              }}
              onSelectEdge={(id) => {
                setSelectedEdge(id);
                setSelectedId(null);
              }}
              onFocus={goFocus}
              focus={focus}
              emphasizedIds={finding?.resource_ids}
            />
            <div className="graph-bottom">
              <span>
                {graph.nodes.length} resources <i /> {graph.edges.length} relationships
              </span>
              <span>Drag to pan · Scroll to zoom · Double-click to focus</span>
            </div>
          </div>
          {(selected || edge) && (
            <aside className="inspector">
              <div className="inspector-top">
                <span className="eyebrow">
                  {selected ? 'Resource inspector' : 'Relationship evidence'}
                </span>
                <button
                  className="icon-button"
                  aria-label="Close inspector"
                  onClick={() => {
                    setSelectedId(null);
                    setSelectedEdge(null);
                  }}
                >
                  <PanelRightClose size={17} />
                </button>
              </div>
              {selected ? (
                <>
                  <div className="inspector-resource">
                    <span className="icon-tile large">
                      {(() => {
                        const Icon = kindIcon(selected.kind);
                        return <Icon size={26} />;
                      })()}
                    </span>
                    <h2>{selected.name}</h2>
                    <p>
                      {label(selected.kind)} · {label(selected.provider)}
                    </p>
                    <EvidenceBadge kind={selected.evidence_kind} />
                    {selected.attributes.missing_from_latest_snapshot === true && (
                      <div className="historical-inspector">
                        <Badge tone="amber">Missing from latest snapshot</Badge>
                      </div>
                    )}
                  </div>
                  <button className="button primary full" onClick={() => goFocus(selected)}>
                    <Expand size={15} />
                    Focus on this resource
                  </button>
                  <div className="tabs compact-tabs">
                    {['overview', 'relations', 'evidence'].map((t) => (
                      <button
                        key={t}
                        className={tab === t ? 'active' : ''}
                        onClick={() => setTab(t)}
                      >
                        {label(t)}
                      </button>
                    ))}
                  </div>
                  {tab === 'overview' && (
                    <>
                      <dl className="details-list">
                        <div>
                          <dt>Classification</dt>
                          <dd>{label(selected.classification)}</dd>
                        </div>
                        <div>
                          <dt>Last collected</dt>
                          <dd>{dateTime(selected.observed_at)}</dd>
                        </div>
                        <div>
                          <dt>Source identifier</dt>
                          <dd className="mono">{selected.source_id}</dd>
                        </div>
                        <div>
                          <dt>Site</dt>
                          <dd>{selected.site_id || 'Not supplied'}</dd>
                        </div>
                      </dl>
                      <h3 className="section-label">Source attributes</h3>
                      {Object.keys(selected.attributes).length ? (
                        <dl className="details-list">
                          {Object.entries(selected.attributes).map(([key, value]) => (
                            <div key={key}>
                              <dt>{label(key)}</dt>
                              <dd className={typeof value === 'object' ? 'mono' : ''}>
                                {stringify(value)}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      ) : (
                        <p className="muted small-text">No additional attributes were supplied.</p>
                      )}
                    </>
                  )}
                  {tab === 'relations' && (
                    <div className="relation-list">
                      {graph.edges
                        .filter((e) => e.source === selected.id || e.target === selected.id)
                        .map((e) => {
                          const peer = graph.nodes.find(
                            (n) => n.id === (e.source === selected.id ? e.target : e.source),
                          );
                          return (
                            <button
                              key={e.id}
                              onClick={() => {
                                setSelectedEdge(e.id);
                                setSelectedId(null);
                              }}
                            >
                              <GitBranch size={16} />
                              <span>
                                <small>{e.kind.replace(/_/g, ' ')}</small>
                                <strong>{peer?.name || 'Unknown resource'}</strong>
                                <small>{label(e.evidence_kind)}</small>
                              </span>
                              <ArrowRight size={14} />
                            </button>
                          );
                        })}
                    </div>
                  )}
                  {tab === 'evidence' && (
                    <>
                      <Notice>
                        “{label(selected.evidence_kind)}” describes how this resource entered the
                        model. It does not establish an end-to-end access decision.
                      </Notice>
                      <dl className="details-list">
                        <div>
                          <dt>Provider</dt>
                          <dd>{label(selected.provider)}</dd>
                        </div>
                        <div>
                          <dt>Collected</dt>
                          <dd>{dateTime(selected.observed_at)}</dd>
                        </div>
                      </dl>
                      <pre className="evidence-json">
                        {JSON.stringify(
                          { source_id: selected.source_id, attributes: selected.attributes },
                          null,
                          2,
                        )}
                      </pre>
                    </>
                  )}
                </>
              ) : (
                edge && (
                  <>
                    <h2 className="edge-title">{edge.kind.replace(/_/g, ' ')}</h2>
                    <EvidenceBadge kind={edge.evidence_kind} />
                    <div className="edge-endpoints">
                      {[edge.source, edge.target].map((id, i) => (
                        <div key={id}>
                          {i > 0 && <ArrowRight size={17} />}
                          <button
                            onClick={() => {
                              setSelectedEdge(null);
                              setSelectedId(id);
                            }}
                          >
                            {graph.nodes.find((n) => n.id === id)?.name || id}
                          </button>
                        </div>
                      ))}
                    </div>
                    <dl className="details-list">
                      <div>
                        <dt>Provider</dt>
                        <dd>{label(edge.provider)}</dd>
                      </div>
                      <div>
                        <dt>Collected</dt>
                        <dd>{dateTime(edge.observed_at)}</dd>
                      </div>
                    </dl>
                    <Notice>
                      A relationship shows recorded context. Other policies and enforcement layers
                      may affect actual reachability.
                    </Notice>
                    <pre className="evidence-json">{JSON.stringify(edge.attributes, null, 2)}</pre>
                  </>
                )
              )}
            </aside>
          )}
        </div>
      ) : (
        <Card>
          <Empty
            icon={Network}
            title={
              findingId ? 'No graph evidence for this finding' : 'Your network will appear here'
            }
            text="Connect a read-only integration and collect a snapshot to explore resources and their relationships."
            action={
              <a className="button primary" href="#/integrations">
                Open integrations
                <ArrowRight size={15} />
              </a>
            }
          />
        </Card>
      )}
      <div className="graph-legend">
        <span>
          <i className="legend-line" />
          Observed / configured relationship
        </span>
        <span>
          <i className="legend-line inferred" />
          Inferred relationship
        </span>
        <span>
          <Layers2 size={13} />
          Source evidence stays attached to each resource
        </span>
        {focus && (
          <a href="#/explorer" className="text-link">
            <ArrowLeft size={14} />
            Return to full network
          </a>
        )}
      </div>
    </>
  );
}
