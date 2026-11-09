import { useState } from 'react';
import {
  ArrowRight,
  Bot,
  Check,
  ClipboardList,
  FileCheck2,
  Fingerprint,
  LockKeyhole,
  Network,
  SearchCheck,
  ShieldCheck,
  Users,
} from 'lucide-react';
import { dateTime, label, stringify, useApi } from '../api';
import { useAuth } from '../auth';
import type { AuditEvent } from '../types';
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  Loading,
  Notice,
  PageHeader,
  SearchInput,
} from '../components/ui';

export function Activity() {
  const result = useApi<AuditEvent[]>('/audit');
  const [search, setSearch] = useState('');
  const items = (result.data || []).filter((event) =>
    `${event.action} ${event.actor_id} ${event.target_id}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  return (
    <>
      <PageHeader
        eyebrow="Accountability"
        title="Activity"
        description="A server-recorded trail of sign-ins, collections, requests, and review decisions."
      />
      <Card>
        <div className="table-toolbar">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search actions, actors, or targets…"
          />
          <Badge>{items.length} events</Badge>
        </div>
        {result.loading ? (
          <Loading />
        ) : result.error ? (
          <ErrorState message={result.error} retry={result.reload} />
        ) : !items.length ? (
          <Empty
            icon={ClipboardList}
            title="No matching activity"
            text="Events appear as the workspace is used. Try clearing your search."
          />
        ) : (
          <div className="table-scroll">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Target & details</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => (
                  <tr key={event.id}>
                    <td>
                      <span className="audit-action">
                        <FileCheck2 size={15} />
                        {label(event.action)}
                      </span>
                    </td>
                    <td className="mono small-text">{event.actor_id || 'System'}</td>
                    <td>
                      <span className="mono tiny">{event.target_id || '—'}</span>
                      {Object.keys(event.details || {}).length > 0 && (
                        <details>
                          <summary>Event details</summary>
                          <pre className="evidence-json">{stringify(event.details)}</pre>
                        </details>
                      )}
                    </td>
                    <td className="muted tiny nowrap">{dateTime(event.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}

export function AIProvider() {
  return (
    <>
      <PageHeader
        eyebrow="Manage workspace"
        title="AI provider"
        description="Your provider, your network context, and a clear boundary around authority."
      />
      <div className="roadmap-hero card">
        <span className="icon-tile large">
          <Bot size={30} />
        </span>
        <Badge tone="blue">Planned capability</Badge>
        <h2>Analysis with your model provider</h2>
        <p>
          The provider interface will support your LiteLLM gateway and future Spektr routing. This
          release does not call a model or assign AI-generated risk scores.
        </p>
      </div>
      <div className="feature-grid">
        <Card>
          <span className="icon-tile">
            <SearchCheck size={22} />
          </span>
          <h3>Grounded in evidence</h3>
          <p>
            Explanations will reference collected observations, configuration, source timestamps,
            and known gaps.
          </p>
        </Card>
        <Card>
          <span className="icon-tile">
            <LockKeyhole size={22} />
          </span>
          <h3>Read-only model access</h3>
          <p>
            The model will receive authorized context and propose actions. Infrastructure
            credentials stay outside the model’s tools.
          </p>
        </Card>
        <Card>
          <span className="icon-tile">
            <Fingerprint size={22} />
          </span>
          <h3>Explicit authorization</h3>
          <p>
            Future execution will require approval of an exact plan, or an administrator-authored
            policy for a bounded temporary exception.
          </p>
        </Card>
      </div>
      <Notice>
        AI analysis, the external MCP interface, and change execution are separate milestones. No
        model connection is active in this foundation.
      </Notice>
    </>
  );
}

export function Changes() {
  return (
    <>
      <PageHeader
        eyebrow="Controlled execution"
        title="Changes"
        description="Exact scope, explicit approval, and a record of what changed."
      />
      <Card>
        <Empty
          icon={ShieldCheck}
          title="Infrastructure execution is not enabled"
          text="This foundation can collect read-only evidence and record access reviews. A future executor will validate approvals, detect configuration drift, verify outcomes, and reconcile expiry before writes are enabled."
          action={
            <a className="button secondary" href="#/requests">
              Review access requests
              <ArrowRight size={15} />
            </a>
          }
        />
      </Card>
      <div className="feature-grid">
        <Card>
          <h3>1. Propose</h3>
          <p>Bind the target, expected state, scope, and lifetime to one reviewable change.</p>
        </Card>
        <Card>
          <h3>2. Authorize</h3>
          <p>Verify the administrator’s approval or a precisely bounded preauthorized policy.</p>
        </Card>
        <Card>
          <h3>3. Verify & reconcile</h3>
          <p>
            Record source changes, check outcomes, and safely remove only Nyctr-owned temporary
            exceptions.
          </p>
        </Card>
      </div>
    </>
  );
}

export function Settings({ members = false }: { members?: boolean }) {
  const { user } = useAuth();
  const config = useApi<{ mode: string; local_enabled: boolean; oidc_enabled: boolean }>(
    '/auth/config',
  );
  return (
    <>
      <PageHeader
        eyebrow="Workspace configuration"
        title={members ? 'Members & roles' : 'Settings'}
        description={
          members
            ? 'Authentication and permissions are enforced by the API.'
            : 'The operating mode, identity settings, and implementation boundaries of your workspace.'
        }
      />
      <div className="overview-columns">
        <Card
          title={
            <>
              <Fingerprint size={18} /> Your session
            </>
          }
        >
          <dl className="settings-list">
            <div>
              <dt>Name</dt>
              <dd>{user?.name}</dd>
            </div>
            <div>
              <dt>Email</dt>
              <dd>{user?.email}</dd>
            </div>
            <div>
              <dt>Role</dt>
              <dd>
                <Badge tone="blue">{label(user?.role)}</Badge>
              </dd>
            </div>
            <div>
              <dt>Mode</dt>
              <dd>
                <Badge tone={user?.mode === 'demo' ? 'amber' : 'green'}>{label(user?.mode)}</Badge>
              </dd>
            </div>
          </dl>
        </Card>
        <Card
          title={
            <>
              <LockKeyhole size={18} /> Authentication
            </>
          }
        >
          {config.loading ? (
            <Loading />
          ) : config.error ? (
            <ErrorState message={config.error} retry={config.reload} />
          ) : (
            <dl className="settings-list">
              <div>
                <dt>Local sign-in</dt>
                <dd>{config.data?.local_enabled ? 'Enabled' : 'Disabled'}</dd>
              </div>
              <div>
                <dt>OpenID Connect</dt>
                <dd>{config.data?.oidc_enabled ? 'Configured' : 'Not configured'}</dd>
              </div>
              <div>
                <dt>Session storage</dt>
                <dd>Server managed</dd>
              </div>
              <div>
                <dt>State changes</dt>
                <dd>CSRF protected</dd>
              </div>
            </dl>
          )}
        </Card>
      </div>
      {members ? (
        <>
          <Notice>
            Account provisioning, trusted OIDC group mapping, and bootstrap credentials are
            configured by the server operator. The member-management interface and device-assignment
            editor are planned.
          </Notice>
          <div className="feature-grid two">
            <Card>
              <span className="icon-tile">
                <ShieldCheck size={21} />
              </span>
              <h3>Administrators</h3>
              <p>
                Inspect workspace evidence, collect supported source snapshots, review access
                requests, and read the audit trail.
              </p>
            </Card>
            <Card>
              <span className="icon-tile">
                <Users size={21} />
              </span>
              <h3>Members</h3>
              <p>
                See fresh observations on authorized personal or shared devices and submit requests.
                Other users’ devices and infrastructure stay outside their view.
              </p>
            </Card>
          </div>
        </>
      ) : (
        <>
          <Card title="Foundation capabilities">
            <div className="settings-capabilities">
              {[
                'Persistent resource and relationship model',
                'Authenticated administrator and member views',
                'Evidence-aware network exploration',
                'Read-only UniFi Network and NextDNS adapters',
                'Fresh block inbox and retained access requests',
                'Server-side review decisions and audit records',
              ].map((text) => (
                <div key={text}>
                  <Check size={16} />
                  <span>{text}</span>
                </div>
              ))}
            </div>
          </Card>
          <div className="section-heading">
            <h2>Next milestones</h2>
            <Badge>Not active yet</Badge>
          </div>
          <div className="feature-grid">
            <Card>
              <span className="icon-tile">
                <Network size={21} />
              </span>
              <h3>Broader collection</h3>
              <p>
                Fabric with Site Manager, Proxmox, cloud networking, and firewall event ingestion.
              </p>
            </Card>
            <Card>
              <span className="icon-tile">
                <Bot size={21} />
              </span>
              <h3>Evidence-led analysis</h3>
              <p>
                Posture rules, source attribution, configurable model providers, and scoped MCP
                access.
              </p>
            </Card>
            <Card>
              <span className="icon-tile">
                <ShieldCheck size={21} />
              </span>
              <h3>Controlled changes</h3>
              <p>
                Exact-plan approval, durable temporary grants, expiry reconciliation, and verified
                outcomes.
              </p>
            </Card>
          </div>
        </>
      )}
      <div className="page-footer">
        <span>Nyctr 0.1.0-alpha.1</span>
        <a
          href="https://github.com/homelab-0/nyctr"
          target="_blank"
          rel="noreferrer"
          className="text-link"
        >
          Project repository
          <ArrowRight size={14} />
        </a>
      </div>
    </>
  );
}
