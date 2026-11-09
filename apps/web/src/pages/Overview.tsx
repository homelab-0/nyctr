import {
  ArrowRight,
  CircleDot,
  GitBranch,
  Inbox,
  Network,
  PlugZap,
  ShieldAlert,
} from 'lucide-react';
import { label, relativeTime, useApi } from '../api';
import type {
  AccessRequest,
  AuditEvent,
  Finding,
  Graph,
  Integration,
  Overview as OverviewData,
} from '../types';
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  LinkButton,
  Loading,
  Metric,
  PageHeader,
  Status,
} from '../components/ui';
import { NetworkGraph } from '../components/NetworkGraph';
import { useAuth } from '../auth';

/**
 * Summarizes independently loaded server evidence, collection health, and pending reviews.
 * Failed sections remain explicit instead of converting unavailable data into a clean posture.
 */
export default function Overview() {
  const { user } = useAuth();
  const summary = useApi<OverviewData>('/overview');
  const findings = useApi<Finding[]>('/findings');
  const graph = useApi<Graph>('/graph');
  const integrations = useApi<Integration[]>('/integrations');
  const requests = useApi<AccessRequest[]>('/requests');
  const audit = useApi<AuditEvent[]>('/audit');
  const pending = requests.data?.filter((r) => r.status === 'pending') || [];
  return (
    <>
      <PageHeader
        eyebrow="Workspace"
        title="Overview"
        description="A connected view of your infrastructure, exposure, and decisions."
        actions={
          <LinkButton href="#/explorer" primary>
            Open explorer
          </LinkButton>
        }
      />
      <div className="overview-intro">
        <span className="icon-tile">
          <Inbox size={22} />
        </span>
        <div>
          <strong>A blocked connection has a next step.</strong>
          <p>Device-aware requests, source evidence, and a clear review trail.</p>
        </div>
        <a className="button secondary" href="#/blocks">
          Open block inbox
          <ArrowRight size={15} />
        </a>
      </div>
      {summary.loading ? (
        <Loading />
      ) : summary.error ? (
        <ErrorState message={summary.error} retry={summary.reload} />
      ) : (
        summary.data && (
          <div className="metrics-grid">
            <Metric
              label="Resources"
              value={summary.data.resource_count}
              caption="Across collected snapshots"
              icon={Network}
            />
            <Metric
              label="Relationships"
              value={summary.data.relationship_count}
              caption="With source evidence"
              icon={GitBranch}
            />
            <Metric
              label="Open findings"
              value={summary.data.finding_count}
              caption="Review the supporting context"
              icon={ShieldAlert}
            />
            <Metric
              label="Recent blocks"
              value={summary.data.recent_block_count}
              caption="Within the observation window"
              icon={Inbox}
            />
          </div>
        )
      )}
      <div className="overview-columns">
        <Card
          title="Needs attention"
          action={
            <a className="text-link" href="#/findings">
              All findings
              <ArrowRight size={14} />
            </a>
          }
        >
          {findings.loading ? (
            <Loading />
          ) : findings.error ? (
            <ErrorState message={findings.error} retry={findings.reload} />
          ) : findings.data?.length ? (
            <div className="rows">
              {findings.data.slice(0, 3).map((f) => (
                <a
                  className="item-row"
                  key={f.id}
                  href={`#/findings?selected=${encodeURIComponent(f.id)}`}
                >
                  <span className={`icon-tile ${f.severity === 'high' ? 'red' : 'amber'}`}>
                    <ShieldAlert size={18} />
                  </span>
                  <div>
                    <strong>{f.title}</strong>
                    <small>
                      {f.resource_ids.length} resources · {f.evidence.length} evidence items
                    </small>
                  </div>
                  <Status value={f.severity} />
                  <ArrowRight size={15} />
                </a>
              ))}
            </div>
          ) : (
            <Empty
              title="No findings in this snapshot"
              text="Nyctr does not infer a clean security posture from an empty finding list."
              icon={ShieldAlert}
            />
          )}
        </Card>
        <Card
          title="Review queue"
          action={
            <a className="text-link" href="#/requests">
              All requests
              <ArrowRight size={14} />
            </a>
          }
        >
          {requests.loading ? (
            <Loading />
          ) : requests.error ? (
            <ErrorState message={requests.error} retry={requests.reload} />
          ) : pending.length ? (
            <div className="rows">
              {pending.slice(0, 3).map((request) => (
                <a key={request.id} className="item-row" href="#/requests">
                  <span className="icon-tile">
                    <Inbox size={18} />
                  </span>
                  <div>
                    <strong>{request.domain}</strong>
                    <small>
                      {request.device_name} · {request.duration_minutes} minutes requested
                    </small>
                  </div>
                  <Status value={request.status} />
                </a>
              ))}
            </div>
          ) : (
            <Empty
              title="Your queue is clear"
              text="New access requests will appear here for review."
              icon={Inbox}
            />
          )}
          <div className="card-footnote">
            Reviews are recorded. Infrastructure changes are not enabled in this release.
          </div>
        </Card>
      </div>
      <Card
        title={
          <>
            <Network size={17} /> Network relationships
          </>
        }
        action={
          <a className="text-link" href="#/explorer">
            Explore full graph
            <ArrowRight size={14} />
          </a>
        }
        className="overview-graph"
      >
        {graph.loading ? (
          <Loading text="Loading your network…" />
        ) : graph.error ? (
          <ErrorState message={graph.error} retry={graph.reload} />
        ) : graph.data?.nodes.length ? (
          <NetworkGraph
            graph={graph.data}
            compact
            onSelect={(r) => {
              window.location.hash = `/explorer?focus=${encodeURIComponent(r.id)}`;
            }}
          />
        ) : (
          <Empty
            title="Begin with a connection"
            text="Collect a snapshot from UniFi Network or NextDNS to bring your infrastructure into view."
            icon={Network}
            action={
              <LinkButton href="#/integrations" primary>
                Add integration
              </LinkButton>
            }
          />
        )}
      </Card>
      <div className="overview-columns">
        <Card
          title="Integration coverage"
          action={
            <a className="text-link" href="#/integrations">
              Manage
              <ArrowRight size={14} />
            </a>
          }
        >
          {integrations.loading ? (
            <Loading />
          ) : integrations.error ? (
            <ErrorState message={integrations.error} retry={integrations.reload} />
          ) : integrations.data?.length ? (
            <div className="rows">
              {integrations.data.map((integration) => (
                <a key={integration.id} className="item-row" href="#/integrations">
                  <span className="icon-tile">
                    <PlugZap size={18} />
                  </span>
                  <div>
                    <strong>{integration.name}</strong>
                    <small>
                      {integration.capabilities?.length || 0} supported capabilities ·{' '}
                      {relativeTime(integration.last_sync)}
                    </small>
                  </div>
                  <Status value={integration.status} />
                </a>
              ))}
            </div>
          ) : (
            <Empty
              title="No sources connected"
              text="Add your first source to begin collecting evidence."
              icon={PlugZap}
            />
          )}
          <div className="card-footnote">
            Collection coverage is specific to each provider and API.
          </div>
        </Card>
        <Card
          title="Recent activity"
          action={
            <a className="text-link" href="#/activity">
              View audit trail
              <ArrowRight size={14} />
            </a>
          }
        >
          {audit.loading ? (
            <Loading />
          ) : audit.error ? (
            <ErrorState message={audit.error} retry={audit.reload} />
          ) : audit.data?.length ? (
            <div className="rows">
              {audit.data.slice(0, 5).map((event) => (
                <div className="item-row" key={event.id}>
                  <CircleDot size={14} className="muted" />
                  <div>
                    <strong>{label(event.action)}</strong>
                    <small>
                      {event.actor_id === user?.id ? 'You' : event.actor_id || 'System'}
                    </small>
                  </div>
                  <span className="tiny muted nowrap">{relativeTime(event.created_at)}</span>
                </div>
              ))}
            </div>
          ) : (
            <Empty
              title="A fresh start"
              text="Sign-ins, collections, requests, and reviews will build your audit trail."
            />
          )}
        </Card>
      </div>
      <div className="page-footer">
        <span>Nyctr · Network security workspace</span>
        <Badge tone="blue">Read-only infrastructure access</Badge>
      </div>
    </>
  );
}
