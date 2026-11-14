import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthProvider, useAuth } from '../auth';
import { setCsrfToken } from '../api';
import { scheduleFixture, scheduleOff } from '../test/schedule';
import type {
  CollectionSchedule,
  Catalog,
  Integration,
  IntegrationDiagnosticsReport,
  Mode,
  Role,
  User,
} from '../types';
import Integrations from './Integrations';

const originalShowModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal');
const originalClose = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'close');

/** Supplies only native dialog open state missing from jsdom; browser focus behavior stays unmocked in QA. */
function showModal(this: HTMLDialogElement) {
  this.setAttribute('open', '');
}

/** Mirrors dialog closure so the real modal component can clean up between test cases. */
function closeDialog(this: HTMLDialogElement) {
  this.removeAttribute('open');
}

/** Installs the minimal platform shim without replacing application modal or diagnostic logic. */
beforeAll(() => {
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', {
    configurable: true,
    value: showModal,
  });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', {
    configurable: true,
    value: closeDialog,
  });
});

/** Restores any native implementations to keep the shim local to this suite. */
afterAll(() => {
  if (originalShowModal)
    Object.defineProperty(HTMLDialogElement.prototype, 'showModal', originalShowModal);
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal');
  if (originalClose) Object.defineProperty(HTMLDialogElement.prototype, 'close', originalClose);
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'close');
});

const connection: Integration = {
  id: 'test-nextdns',
  provider: 'nextdns',
  name: 'Test DNS connection',
  status: 'configured',
  last_sync: null,
  last_error: null,
  config: { profile_id: 'abc123' },
  secret_ref: 'NYCTR_CONNECTOR_SECRET_TEST_DNS',
  capabilities: ['profile_configuration', 'blocked_queries'],
  provider_name: 'NextDNS',
  provides: ['dns.blocks', 'dns.exceptions'],
};

/** A fabricated catalog: one DNS integration that can open addresses and one that only reads. */
const catalog: Catalog = {
  capabilities: [
    { id: 'dns.blocks', name: 'Blocked lookups', changes_provider: false },
    { id: 'dns.exceptions', name: 'Open a blocked address for a while', changes_provider: true },
    { id: 'guest.passes', name: 'Guest passes', changes_provider: true },
  ],
  providers: [
    {
      id: 'nextdns',
      name: 'NextDNS',
      summary: 'One DNS profile.',
      letter: 'N',
      tone: 'teal',
      status: 'stable',
      secret_hint: 'An API key.',
      fields: [
        {
          key: 'profile_id',
          label: 'Profile',
          hint: 'Six characters.',
          placeholder: 'abc123',
          kind: 'text',
          required: true,
        },
      ],
      provides: [
        { id: 'dns.blocks', name: 'Blocked lookups', changes_provider: false },
        {
          id: 'dns.exceptions',
          name: 'Open a blocked address for a while',
          changes_provider: true,
        },
      ],
      reads: [{ id: 'profile:read', label: 'DNS profile configuration' }],
      changes: ['Open a blocked address for a while'],
      write_mode: 'disabled',
    },
    {
      id: 'acme_resolver',
      name: 'Acme Resolver',
      summary: 'A made-up resolver that only reports blocks.',
      letter: 'A',
      tone: 'rose',
      status: 'experimental',
      secret_hint: 'A password.',
      fields: [
        {
          key: 'base_url',
          label: 'Address',
          hint: 'Over HTTPS.',
          placeholder: 'https://resolver.example',
          kind: 'url',
          required: true,
        },
        {
          key: 'lookback_hours',
          label: 'Hours to read',
          hint: 'Between 1 and 72.',
          placeholder: '24',
          kind: 'number',
          required: false,
        },
      ],
      provides: [{ id: 'dns.blocks', name: 'Blocked lookups', changes_provider: false }],
      reads: [{ id: 'blocked_dns_logs:read', label: 'Recent blocked DNS queries' }],
      changes: [],
      write_mode: 'none',
    },
  ],
};

const partialReport: IntegrationDiagnosticsReport = {
  integration_id: connection.id,
  provider: connection.provider,
  checked_at: '2026-01-01T12:00:00Z',
  duration_ms: 450,
  outcome: 'partial',
  summary: 'Profile configuration was read; query evidence could not be verified.',
  read_only: true,
  checks: [
    {
      id: 'configuration',
      label: 'Configuration',
      status: 'passed',
      category: 'configuration',
      summary: 'Saved configuration is valid.',
      guidance: null,
    },
    {
      id: 'secret',
      label: 'Credential reference',
      status: 'passed',
      category: 'secret',
      summary: 'A configured server credential is available.',
      guidance: null,
    },
    {
      id: 'connectivity',
      label: 'Connectivity',
      status: 'passed',
      category: 'transport',
      summary: 'The provider API responded.',
      guidance: null,
    },
    {
      id: 'tls',
      label: 'TLS verification',
      status: 'passed',
      category: 'tls',
      summary: 'The provider certificate was verified.',
      guidance: null,
    },
    {
      id: 'authentication',
      label: 'Provider authentication',
      status: 'passed',
      category: 'authentication',
      summary: 'The credential was accepted for the supported read.',
      guidance: null,
    },
    {
      id: 'provider_contract',
      label: 'Provider response format',
      status: 'unknown',
      category: 'provider_contract',
      summary: 'Query response coverage was not verified.',
      guidance: 'Review the logging configuration and required provider permissions.',
    },
  ],
  capabilities: [
    {
      id: 'profile_configuration',
      label: 'Profile configuration',
      implementation: 'implemented',
      verification: 'verified',
      summary: 'The saved profile configuration was read.',
    },
    {
      id: 'blocked_queries',
      label: 'Blocked query observations',
      implementation: 'implemented',
      verification: 'unavailable',
      summary: 'Query logging is disabled for this profile.',
    },
    {
      id: 'identity',
      label: 'User attribution',
      implementation: 'not_implemented',
      verification: 'unknown',
      summary: 'A shared upstream profile does not identify a person.',
    },
  ],
  evidence_gaps: [
    {
      id: 'logs',
      title: 'Query logs unavailable',
      summary: 'No DNS block visibility was established by this run.',
    },
    {
      id: 'identity',
      title: 'Device-to-user identity is unverified',
      summary:
        'Do not assign upstream DNS observations to a family member without reliable device evidence.',
    },
  ],
  snapshot_counts: { resources: 1, relationships: 0, observations: 0 },
};

/** Models the app's session boundary so a real API 401 removes the integration view. */
function SessionGate() {
  const { user, loading, error } = useAuth();
  if (loading) return <p>Loading session</p>;
  if (!user)
    return (
      <>
        <p>Signed out</p>
        {error && <p role="alert">{error}</p>}
      </>
    );
  return <Integrations />;
}

/** Creates synthetic transport responses while preserving production API and auth behavior. */
function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Holds a response open to verify pending, cancellation, and stale-result behavior deterministically. */
function deferredResponse() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

/**
 * Renders a real authenticated integrations view with fabricated provider diagnostics.
 * No provider traffic is sent; only fetch is replaced, leaving CSRF and expiry intact.
 */
async function openIntegrations({
  mode = 'live',
  role = 'admin',
  diagnose = async () => jsonResponse(partialReport),
  source = connection,
  partial,
  schedule = scheduleFixture(),
  save = async () => jsonResponse(source),
  others = [],
  removal = async (method: string) => jsonResponse(method === 'GET' ? plan : {}),
}: {
  mode?: Mode;
  role?: Role;
  diagnose?: () => Promise<Response>;
  source?: Integration;
  partial?: boolean;
  schedule?: CollectionSchedule;
  save?: (path: string) => Promise<Response>;
  others?: Integration[];
  removal?: (method: string) => Promise<Response>;
} = {}) {
  const user: User = {
    id: 'test-user',
    email: 'test@example.test',
    name: 'Test user',
    role,
    mode,
    csrf_token: 'fabricated-diagnostics-csrf',
  };
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input, options) => {
    const path = String(input);
    if (path === '/api/auth/me') return jsonResponse(user);
    if (path === '/api/integrations') return jsonResponse([source, ...others]);
    if (path === '/api/integrations/catalog') return jsonResponse(catalog);
    if (path === '/api/collection') return jsonResponse(schedule);
    if (path === `/api/integrations/${connection.id}/diagnostics`) return diagnose();
    if (path.startsWith('/api/integrations/') && options?.method === 'PUT') return save(path);
    if (path === `/api/integrations/${source.id}/removal`) return removal('GET');
    if (path === `/api/integrations/${source.id}` && options?.method === 'DELETE') {
      return removal('DELETE');
    }
    if (path === `/api/integrations/${connection.id}/sync`) {
      return jsonResponse({ ok: true, resource_count: 1, observation_count: 0, partial });
    }
    throw new Error(`Unexpected synthetic request: ${options?.method || 'GET'} ${path}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  render(
    <AuthProvider>
      <SessionGate />
    </AuthProvider>,
  );
  await screen.findByRole('heading', { name: connection.name });
  return { fetchMock, interaction: userEvent.setup(), user };
}

/** Removes session state and mounted dialogs between authorization and transport scenarios. */
afterEach(() => {
  cleanup();
  setCsrfToken('');
});

beforeEach(() => {
  setCsrfToken('');
  window.location.hash = '/integrations';
});

/** Covers diagnostic authorization, evidence limits, and the separation from snapshot collection. */
describe('integration connection diagnostics', () => {
  /** Partial reads must retain unknown/disabled coverage and expose no raw diagnostic payloads. */
  it('shows partial coverage, guidance, and identity gaps without importing a snapshot', async () => {
    const response = deferredResponse();
    const { fetchMock, interaction, user } = await openIntegrations({
      diagnose: () => response.promise,
    });
    await interaction.click(screen.getByRole('button', { name: 'Run diagnostics' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connection diagnostics' });
    expect(within(dialog).getByText('Checking connection…')).toBeDefined();
    expect(within(dialog).getByRole('button', { name: 'Checking…' })).toHaveProperty(
      'disabled',
      true,
    );

    response.resolve(
      jsonResponse({
        ...partialReport,
        credential: 'must-not-render-secret',
        raw_logs: ['private-browsing.example.test'],
      }),
    );
    await within(dialog).findByRole('heading', { name: 'Partial verification' });
    expect(
      within(dialog).getByText(
        'Review the logging configuration and required provider permissions.',
      ),
    ).toBeDefined();
    expect(within(dialog).getByRole('columnheader', { name: 'Adapter support' })).toBeDefined();
    expect(within(dialog).getByRole('columnheader', { name: 'This check' })).toBeDefined();
    const blockedRow = within(dialog).getByRole('row', { name: /Blocked query observations/ });
    expect(within(blockedRow).getByText('Implemented')).toBeDefined();
    expect(within(blockedRow).getByText('Unavailable')).toBeDefined();
    expect(
      within(blockedRow).getByText('Query logging is disabled for this profile.'),
    ).toBeDefined();
    const identityRow = within(dialog).getByRole('row', { name: /User attribution/ });
    expect(within(identityRow).getByText('Not implemented')).toBeDefined();
    expect(within(identityRow).getByText('Unknown')).toBeDefined();
    expect(within(dialog).getByText('Device-to-user identity is unverified')).toBeDefined();
    expect(within(dialog).getByText('No snapshot was imported into your workspace.')).toBeDefined();
    expect(within(dialog).getByText(/does not establish network safety/)).toBeDefined();
    expect(screen.queryByText('must-not-render-secret')).toBeNull();
    expect(screen.queryByText('private-browsing.example.test')).toBeNull();
    const posts = fetchMock.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe(`/api/integrations/${connection.id}/diagnostics`);
    expect(posts[0][1]?.credentials).toBe('same-origin');
    expect(posts[0][1]?.body).toBeUndefined();
    expect(new Headers(posts[0][1]?.headers).get('X-CSRF-Token')).toBe(user.csrf_token);
  });

  /** Read verification cannot erase the provider's independent log/identity coverage limitations. */
  it('keeps evidence gaps visible when supported reads are verified', async () => {
    const { interaction } = await openIntegrations({
      diagnose: async () =>
        jsonResponse({
          ...partialReport,
          outcome: 'verified',
          summary: 'The supported bounded reads completed.',
          checks: partialReport.checks.map((check) => ({
            ...check,
            status: 'passed',
            guidance: null,
          })),
          capabilities: partialReport.capabilities.map((capability) =>
            capability.id === 'blocked_queries'
              ? {
                  ...capability,
                  verification: 'verified',
                  summary: 'The query endpoint was read; no blocked queries were returned.',
                }
              : capability,
          ),
          evidence_gaps: [
            {
              id: 'firewall_events',
              title: 'Firewall events are not collected',
              summary: 'No firewall block visibility was established by this run.',
            },
            partialReport.evidence_gaps[1],
          ],
        }),
    });
    await interaction.click(screen.getByRole('button', { name: 'Run diagnostics' }));
    await screen.findByRole('heading', { name: 'Supported reads verified' });
    expect(screen.getByRole('heading', { name: 'Remaining evidence gaps' })).toBeDefined();
    expect(
      screen.getByText('No firewall block visibility was established by this run.'),
    ).toBeDefined();
    expect(screen.queryByText(/^Healthy$|^Safe$/i)).toBeNull();
  });

  /** Diagnosed provider failures use a completed report, not a fabricated success or transport error. */
  it('shows failed and unavailable checks with their remediation guidance', async () => {
    const { interaction } = await openIntegrations({
      diagnose: async () =>
        jsonResponse({
          ...partialReport,
          outcome: 'failed',
          summary: 'The credential could not be used for a supported read.',
          checks: [
            {
              ...partialReport.checks[4],
              status: 'failed',
              summary: 'The provider rejected authentication.',
              guidance:
                'Replace the server credential with one permitted to read the configured source.',
            },
            {
              ...partialReport.checks[5],
              status: 'unavailable',
              summary: 'Response format was not checked after authentication failed.',
              guidance: null,
            },
          ],
          capabilities: partialReport.capabilities.map((capability) => ({
            ...capability,
            verification: 'unknown',
          })),
          snapshot_counts: null,
        }),
    });
    await interaction.click(screen.getByRole('button', { name: 'Run diagnostics' }));
    await screen.findByRole('heading', { name: 'Checks need attention' });
    expect(screen.getByText('The provider rejected authentication.')).toBeDefined();
    expect(
      screen.getByText(
        'Replace the server credential with one permitted to read the configured source.',
      ),
    ).toBeDefined();
    expect(
      screen.getByText('Response format was not checked after authentication failed.'),
    ).toBeDefined();
    expect(screen.queryByText('Records examined')).toBeNull();
  });

  /** Rejected diagnostics must stay errors and cannot reuse an older successful result. */
  it.each([403, 404, 409, 500])(
    'reports HTTP %s without inventing a diagnostic outcome',
    async (status) => {
      const { interaction } = await openIntegrations({
        diagnose: async () =>
          jsonResponse({ detail: `Diagnostic request rejected (${status}).` }, status),
      });
      await interaction.click(screen.getByRole('button', { name: 'Run diagnostics' }));
      expect((await screen.findByRole('alert')).textContent).toContain(
        `Diagnostic request rejected (${status}).`,
      );
      expect(screen.queryByRole('heading', { name: 'Capability coverage' })).toBeNull();
      expect(screen.getByRole('button', { name: 'Run again' })).toHaveProperty('disabled', false);
      expect(screen.queryByText('Signed out')).toBeNull();
    },
  );

  /** HTTP success cannot make an incomplete or incorrectly scoped body safe for the report renderer. */
  it.each([
    ['null body', null],
    ['empty object', {}],
    ['missing checks', { ...partialReport, checks: null }],
    ['wrong connection', { ...partialReport, integration_id: 'another-connection' }],
    ['wrong provider', { ...partialReport, provider: 'unifi_network' }],
    ['write-capable result', { ...partialReport, read_only: false }],
    ['oversized text', { ...partialReport, summary: 'x'.repeat(4001) }],
    [
      'oversized section',
      {
        ...partialReport,
        checks: Array.from({ length: 33 }, (_, id) => ({
          ...partialReport.checks[0],
          id: `check-${id}`,
        })),
      },
    ],
  ])('rejects a malformed HTTP 200 report: %s', async (_label, body) => {
    const { interaction } = await openIntegrations({ diagnose: async () => jsonResponse(body) });
    await interaction.click(screen.getByRole('button', { name: 'Run diagnostics' }));
    expect((await screen.findByRole('alert')).textContent).toContain(
      'Nyctr returned an invalid diagnostic report.',
    );
    expect(screen.getByRole('dialog', { name: 'Connection diagnostics' })).toBeDefined();
    expect(screen.queryByRole('heading', { name: 'Capability coverage' })).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Partial verification' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Run again' })).toHaveProperty('disabled', false);
  });

  /** Protected API expiry must remove the report and invalidate the real shared session. */
  it('signs out on HTTP 401 instead of leaving diagnostic evidence in the view', async () => {
    const { interaction } = await openIntegrations({
      diagnose: async () => jsonResponse({ detail: 'Session expired' }, 401),
    });
    await interaction.click(screen.getByRole('button', { name: 'Run diagnostics' }));
    await screen.findByText('Signed out');
    expect(screen.getByRole('alert').textContent).toContain(
      'Your session expired. Sign in to continue.',
    );
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  /** A failed rerun must clear the previous report immediately, including verified capability badges. */
  it('clears stale results while rerunning and preserves a real network failure', async () => {
    const retry = deferredResponse();
    const diagnose = vi
      .fn<() => Promise<Response>>()
      .mockResolvedValueOnce(jsonResponse(partialReport))
      .mockImplementationOnce(() => retry.promise)
      .mockRejectedValueOnce(new TypeError('Network connection failed'));
    const { interaction } = await openIntegrations({ diagnose });
    await interaction.click(screen.getByRole('button', { name: 'Run diagnostics' }));
    await screen.findByRole('heading', { name: 'Partial verification' });
    await interaction.click(screen.getByRole('button', { name: 'Run again' }));
    expect(screen.getByText('Checking connection…')).toBeDefined();
    expect(screen.queryByRole('heading', { name: 'Partial verification' })).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Capability coverage' })).toBeNull();
    retry.resolve(jsonResponse({ detail: 'The source is busy. Try again shortly.' }, 409));
    await screen.findByRole('alert');
    await interaction.click(screen.getByRole('button', { name: 'Run again' }));
    await waitFor(() =>
      expect(screen.getByRole('alert').textContent).toContain('Network connection failed'),
    );
    expect(screen.queryByRole('heading', { name: 'Capability coverage' })).toBeNull();
  });

  /** Even a transport that ignores cancellation cannot reopen a closed report with stale evidence. */
  it('aborts a closed report and ignores its late response', async () => {
    const response = deferredResponse();
    const { fetchMock, interaction } = await openIntegrations({ diagnose: () => response.promise });
    await interaction.click(screen.getByRole('button', { name: 'Run diagnostics' }));
    await interaction.click(screen.getByRole('button', { name: 'Close report' }));
    const request = fetchMock.mock.calls.find(([path]) => String(path).endsWith('/diagnostics'))!;
    expect(request[1]?.signal?.aborted).toBe(true);
    await act(async () => response.resolve(jsonResponse(partialReport)));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Partial verification' })).toBeNull();
  });

  /** Demonstration accounts must not be able to trigger real saved-source checks. */
  it('disables diagnostics in demo mode and explains why', async () => {
    const { fetchMock, interaction } = await openIntegrations({ mode: 'demo' });
    const button = screen.getByRole('button', { name: 'Run diagnostics' });
    expect(button).toHaveProperty('disabled', true);
    expect(
      screen.getByText(/Live connection diagnostics and collection are disabled/),
    ).toBeDefined();
    await interaction.click(button);
    expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith('/diagnostics'))).toBe(
      false,
    );
  });

  /** An accidentally mounted admin view still exposes no diagnostic action to a member. */
  it('hides diagnostics from members', async () => {
    const { fetchMock } = await openIntegrations({ role: 'member' });
    expect(screen.queryByRole('button', { name: 'Run diagnostics' })).toBeNull();
    expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith('/diagnostics'))).toBe(
      false,
    );
  });

  /** Collection remains an independent POST; diagnostics never silently replaces or invokes it. */
  it('retains the separate Collect snapshot action', async () => {
    const { fetchMock, interaction } = await openIntegrations();
    await interaction.click(screen.getByRole('button', { name: 'Collect snapshot' }));
    await screen.findByText('Snapshot collected: 1 resources and 0 observations.');
    const posts = fetchMock.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(posts.map(([path]) => path)).toEqual([`/api/integrations/${connection.id}/sync`]);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText(/Only the most recent blocked lookups/)).toBeNull();
  });

  /** The confirmation must not read as a complete collection when the source held more than was read. */
  it('says so right after collecting when only the most recent blocked lookups were read', async () => {
    const { interaction } = await openIntegrations({ partial: true });
    await interaction.click(screen.getByRole('button', { name: 'Collect snapshot' }));
    await screen.findByText(
      "Snapshot collected: 1 resources and 0 observations. Only the most recent blocked lookups were read. Older ones in this source's time window were not.",
    );
  });
});

/** The page is built from the server's catalog, so an integration this app has never heard of still works. */
describe('integrations add capabilities', () => {
  /** Features are rows, integrations are columns, and a feature without a connected source says so. */
  it('says in plain words when only the most recent blocked lookups were read', async () => {
    await openIntegrations({
      source: { ...connection, status: 'partial', last_sync: '2026-11-09T12:00:00Z' },
    });
    expect(
      screen.getByText(
        /Only the most recent blocked lookups were read\. Older ones in this source's time window were not\./,
      ),
    ).toBeTruthy();
    expect(screen.getByText('Partial')).toBeTruthy();
    expect(screen.queryByText('Error')).toBeNull();
    expect(screen.queryByText('Connected')).toBeNull();
  });

  it('shows no partial note for a source that was read completely', async () => {
    await openIntegrations({ source: { ...connection, status: 'connected' } });
    expect(screen.getByText('Connected')).toBeTruthy();
    expect(screen.queryByText(/Only the most recent blocked lookups/)).toBeNull();
  });

  it('says on the source card when it is next collected, or that it is only on request', async () => {
    await openIntegrations();
    expect((await screen.findByText('Next collection')).parentElement!.textContent).toBe(
      'Next collectionin 12 min',
    );
    cleanup();
    await openIntegrations({ schedule: scheduleOff() });
    expect(await screen.findByText('Only when you press Collect')).toBeDefined();
  });

  it('counts the next collection down on the source card while the page stays open', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      await openIntegrations();
      const card = (await screen.findByText('Next collection')).parentElement!;
      expect(card.textContent).toBe('Next collectionin 12 min');
      await act(() => vi.advanceTimersByTimeAsync(5 * 60_000));
      expect(card.textContent).toBe('Next collectionin 7 min');
    } finally {
      vi.useRealTimers();
    }
  });

  it('shows what each integration adds and which features have a connected source', async () => {
    await openIntegrations();
    const table = screen.getByRole('table');
    expect(within(table).getByRole('columnheader', { name: /Acme Resolver/ })).toBeDefined();
    const open = within(table).getByRole('row', { name: /Open a blocked address for a while/ });
    expect(within(open).getByText(/Working: a connected source offers it/)).toBeDefined();
    expect(within(open).getByText(/Changes the source/)).toBeDefined();
    expect(within(open).getAllByText('Yes')).toHaveLength(1);
    expect(within(open).getAllByText('No')).toHaveLength(1);
    const passes = within(table).getByRole('row', { name: /Guest passes/ });
    expect(within(passes).getByText(/No connected source offers it/)).toBeDefined();
    expect(within(passes).queryByText('Yes')).toBeNull();
    expect(screen.getByText('Reads only')).toBeDefined();
  });

  /** The connect form asks for exactly the fields the chosen integration declares. */
  it('builds the connection form from the chosen integration and sends only its fields', async () => {
    const { fetchMock, interaction } = await openIntegrations();
    fetchMock.mockImplementationOnce(async () => jsonResponse({ id: 'new' }, 201));
    await interaction.click(screen.getByRole('button', { name: /Add connection/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect a source' });
    expect(within(dialog).getByLabelText(/^Profile/)).toBeDefined();
    await interaction.selectOptions(within(dialog).getByLabelText(/^Integration/), 'acme_resolver');
    expect(within(dialog).queryByLabelText(/^Profile/)).toBeNull();
    await interaction.type(within(dialog).getByLabelText(/^Connection name/), 'Branch resolver');
    await interaction.type(within(dialog).getByLabelText(/^Address/), 'https://resolver.example');
    await interaction.type(within(dialog).getByLabelText(/^Hours to read/), '12');
    await interaction.type(
      within(dialog).getByLabelText(/^Credential environment reference/),
      'NYCTR_CONNECTOR_SECRET_BRANCH',
    );
    await interaction.click(within(dialog).getByRole('button', { name: /Save connection/ }));
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([path, options]) => path === '/api/integrations' && options?.method === 'POST',
        ),
      ).toBe(true),
    );
    const sent = fetchMock.mock.calls.find(
      ([path, options]) => path === '/api/integrations' && options?.method === 'POST',
    )!;
    expect(JSON.parse(String(sent[1]?.body))).toEqual({
      provider: 'acme_resolver',
      name: 'Branch resolver',
      config: { base_url: 'https://resolver.example', lookback_hours: 12 },
      secret_ref: 'NYCTR_CONNECTOR_SECRET_BRANCH',
    });
  });
});

/** A fabricated saved source of the made-up resolver kind, collected once. */
const resolver: Integration = {
  ...connection,
  provider: 'acme_resolver',
  provider_name: 'Acme Resolver',
  status: 'connected',
  last_sync: '2026-01-01T12:00:00Z',
  config: { base_url: 'https://resolver.example/api', lookback_hours: 24 },
  secret_ref: 'NYCTR_CONNECTOR_SECRET_RESOLVER',
};

/** Covers the edit form: what it shows, what it sends, how a refusal reads, and where focus lands. */
describe('editing a saved source', () => {
  it("opens the form filled in, keeps the kind and a collected source's address fixed, and saves a number", async () => {
    const { fetchMock, interaction, user } = await openIntegrations({ source: resolver });
    const button = screen.getByRole('button', { name: 'Edit' });
    button.focus();
    await interaction.keyboard('{Enter}');
    const dialog = await screen.findByRole('dialog', { name: 'Edit source' });
    expect(within(dialog).getByLabelText(/^Integration/)).toHaveProperty('disabled', true);
    expect(within(dialog).getByLabelText(/^Integration/)).toHaveProperty('value', 'acme_resolver');
    expect(within(dialog).getByText(/kind of source cannot be changed/)).toBeDefined();
    expect(within(dialog).getByLabelText(/^Connection name/)).toHaveProperty(
      'value',
      resolver.name,
    );
    expect(within(dialog).getByLabelText(/^Address/)).toHaveProperty(
      'value',
      'https://resolver.example/api',
    );
    expect(within(dialog).getByLabelText(/^Credential environment reference/)).toHaveProperty(
      'value',
      'NYCTR_CONNECTOR_SECRET_RESOLVER',
    );
    // It has collected, so where it reads is fixed and the form says why; numbers stay editable.
    expect(within(dialog).getByLabelText(/^Address/)).toHaveProperty('readOnly', true);
    expect(within(dialog).getByLabelText(/^Credential environment reference/)).toHaveProperty(
      'readOnly',
      true,
    );
    expect(within(dialog).getByText(/already collected, so where it reads/)).toBeDefined();
    const hours = within(dialog).getByLabelText(/^Hours to read/);
    expect(hours).toHaveProperty('value', '24');
    expect(hours).toHaveProperty('readOnly', false);
    await interaction.clear(hours);
    await interaction.type(hours, '6');
    await interaction.click(within(dialog).getByRole('button', { name: /Save changes/ }));
    await screen.findByText('Changes saved.');
    expect(screen.queryByRole('dialog')).toBeNull();
    const sent = fetchMock.mock.calls.find(([, options]) => options?.method === 'PUT')!;
    expect(sent[0]).toBe(`/api/integrations/${resolver.id}`);
    expect(new Headers(sent[1]?.headers).get('X-CSRF-Token')).toBe(user.csrf_token);
    expect(JSON.parse(String(sent[1]?.body))).toEqual({
      name: resolver.name,
      config: { base_url: 'https://resolver.example/api', lookback_hours: 6 },
      secret_ref: 'NYCTR_CONNECTOR_SECRET_RESOLVER',
    });
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Edit' }));
  });

  it('lets every field of a source that has not collected yet be corrected', async () => {
    const { interaction } = await openIntegrations({
      source: { ...resolver, status: 'error', last_sync: null, last_error: 'Unreachable.' },
    });
    await interaction.click(screen.getByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit source' });
    expect(within(dialog).getByLabelText(/^Address/)).toHaveProperty('readOnly', false);
    expect(within(dialog).getByLabelText(/^Credential environment reference/)).toHaveProperty(
      'readOnly',
      false,
    );
    expect(within(dialog).getByText(/has not collected yet, so every field/)).toBeDefined();
    expect(within(dialog).queryByText(/already collected/)).toBeNull();
  });

  it('keeps a source shut while its save is unfinished, and a late save closes no other form', async () => {
    const response = deferredResponse();
    const { interaction } = await openIntegrations({
      source: resolver,
      save: () => response.promise,
    });
    await interaction.click(screen.getByRole('button', { name: 'Edit' }));
    const first = await screen.findByRole('dialog', { name: 'Edit source' });
    await interaction.click(within(first).getByRole('button', { name: /Save changes/ }));
    await interaction.click(within(first).getByRole('button', { name: 'Cancel' }));
    // Reopening now would fill the form with the values from before the save and could undo it.
    await interaction.click(screen.getByRole('button', { name: 'Edit' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.getByRole('button', { name: 'Edit' }).getAttribute('aria-disabled')).toBe('true');
    await interaction.click(screen.getByRole('button', { name: /Add connection/ }));
    const other = await screen.findByRole('dialog', { name: 'Connect a source' });
    await interaction.type(within(other).getByLabelText(/^Connection name/), 'Second');
    await act(async () => response.resolve(jsonResponse(resolver)));
    await screen.findByText('Changes saved.');
    expect(within(other).getByLabelText(/^Connection name/)).toHaveProperty('value', 'Second');
    await interaction.click(within(other).getByRole('button', { name: 'Cancel' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Edit' }).getAttribute('aria-disabled')).toBe(
        'false',
      ),
    );
    await interaction.click(screen.getByRole('button', { name: 'Edit' }));
    expect(await screen.findByRole('dialog', { name: 'Edit source' })).toBeDefined();
  });

  it('keeps each of two sources shut for its own unfinished save', async () => {
    const saves = { first: deferredResponse(), second: deferredResponse() };
    const { interaction } = await openIntegrations({
      source: resolver,
      others: [{ ...resolver, id: 'second', name: 'Second resolver' }],
      save: (path) => (path.endsWith('/second') ? saves.second : saves.first).promise,
    });
    const edits = () => screen.getAllByRole('button', { name: 'Edit' });
    const shut = () => edits().map((button) => button.getAttribute('aria-disabled'));
    for (const index of [0, 1]) {
      await interaction.click(edits()[index]);
      const form = await screen.findByRole('dialog', { name: 'Edit source' });
      await interaction.click(within(form).getByRole('button', { name: /Save changes/ }));
      await interaction.click(within(form).getByRole('button', { name: 'Cancel' }));
    }
    // The second save must not take over the first one's mark.
    expect(shut()).toEqual(['true', 'true']);
    await act(async () => saves.first.resolve(jsonResponse(resolver)));
    // The first is read back and opens again; its reload must not open the second.
    await waitFor(() => expect(shut()).toEqual(['false', 'true']));
    await interaction.click(edits()[1]);
    expect(screen.queryByRole('dialog')).toBeNull();
    await act(async () => saves.second.resolve(jsonResponse(resolver)));
    await waitFor(() => expect(shut()).toEqual(['false', 'false']));
  });

  it('hides Edit and Remove from members and disables them in the demo workspace', async () => {
    await openIntegrations({ role: 'member' });
    expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Remove' })).toBeNull();
    cleanup();
    await openIntegrations({ mode: 'demo' });
    expect(screen.getByRole('button', { name: 'Edit' })).toHaveProperty('disabled', true);
    expect(screen.getByRole('button', { name: 'Remove' })).toHaveProperty('disabled', true);
  });
});

/** Server counts for removing the fabricated source. */
const plan = {
  name: connection.name,
  remove: {
    devices: 2,
    networks: 1,
    rules: 0,
    other_items: 0,
    lookups: 5,
    assignments: 1,
    links: 0,
  },
  keep: { requests: 1, exceptions: 0, passes: 0 },
  refusal: null,
  notice: null,
};

describe('removing a saved source', () => {
  it('states what goes and stays, and removes only once the name is typed', async () => {
    const { fetchMock, interaction } = await openIntegrations();
    await interaction.click(screen.getByRole('button', { name: 'Remove' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove source' });
    expect(
      await within(dialog).findByText(
        /2 devices, 1 network, 5 blocked lookups, 1 device assignment to a person/,
      ),
    ).toBeDefined();
    expect(within(dialog).getByText(/1 request, the activity history/)).toBeDefined();
    const confirm = within(dialog).getByRole('button', { name: 'Remove source' });
    expect(confirm).toHaveProperty('disabled', true);
    await interaction.type(within(dialog).getByLabelText(/^Type/), connection.name);
    await interaction.click(confirm);
    await screen.findByText(`${connection.name} was removed.`);
    expect(screen.queryByRole('dialog')).toBeNull();
    const sent = fetchMock.mock.calls.find(([, options]) => options?.method === 'DELETE')!;
    expect(JSON.parse(String(sent[1]?.body))).toEqual({ name: connection.name });
    // Its card is gone, so the keyboard lands on Add connection.
    expect(document.activeElement).toBe(screen.getByRole('button', { name: /Add connection/ }));
  });

  it('says why a source cannot be removed yet and offers no way to confirm', async () => {
    const refusal =
      'Not removed. Nyctr still has 1 open exception (end under Open now) at this source.';
    const { interaction } = await openIntegrations({
      removal: async () => jsonResponse({ ...plan, refusal }),
    });
    await interaction.click(screen.getByRole('button', { name: 'Remove' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove source' });
    expect(await within(dialog).findByText(refusal)).toBeDefined();
    expect(within(dialog).queryByLabelText(/^Type/)).toBeNull();
    expect(within(dialog).getByRole('button', { name: 'Remove source' })).toHaveProperty(
      'disabled',
      true,
    );
    await interaction.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Remove' }));
  });

  it('warns that guests Nyctr let on stay on, and still lets the source be removed', async () => {
    const notice = '1 guest Nyctr let on stays let on at this source until its time ends.';
    const { interaction } = await openIntegrations({
      removal: async () => jsonResponse({ ...plan, notice }),
    });
    await interaction.click(screen.getByRole('button', { name: 'Remove' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove source' });
    expect(await within(dialog).findByText(notice)).toBeDefined();
    expect(within(dialog).getByLabelText(/^Type/)).toBeDefined();
  });
});
