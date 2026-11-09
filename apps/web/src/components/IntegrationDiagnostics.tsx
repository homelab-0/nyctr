import { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  CircleHelp,
  Clock3,
  Database,
  LockKeyhole,
  MinusCircle,
  RefreshCw,
  ScanLine,
  ShieldQuestion,
} from 'lucide-react';
import { api, dateTime, label } from '../api';
import type {
  Integration,
  IntegrationDiagnosticCapability,
  IntegrationDiagnosticCheck,
  IntegrationDiagnosticsReport,
} from '../types';
import { Badge, Loading, Modal, Notice } from './ui';
import { isDiagnosticReport } from './diagnostic-report';

interface DiagnosticsState {
  integration: Integration;
  pending: boolean;
  report: IntegrationDiagnosticsReport | null;
  error: string | null;
}

const outcomes = {
  verified: { label: 'Supported reads verified', tone: 'blue', icon: CheckCircle2 },
  partial: { label: 'Partial verification', tone: 'amber', icon: CircleHelp },
  failed: { label: 'Checks need attention', tone: 'red', icon: AlertCircle },
};

const checkStates = {
  passed: { label: 'Passed', tone: 'green', icon: CheckCircle2 },
  failed: { label: 'Failed', tone: 'red', icon: AlertCircle },
  unknown: { label: 'Unknown', tone: 'amber', icon: CircleHelp },
  unavailable: { label: 'Unavailable', tone: '', icon: MinusCircle },
};

const verificationStates = {
  verified: { label: 'Verified read', tone: 'blue' },
  unavailable: { label: 'Unavailable', tone: '' },
  unknown: { label: 'Unknown', tone: 'amber' },
};

/**
 * Runs explicit diagnostics with the shared session/CSRF boundary, never source imports.
 * Every run clears the previous report. Closing, rerunning, or losing permission
 * aborts the active request; an identity check also rejects late responses from a
 * transport that cannot be canceled. Results remain in component memory only.
 */
export function useIntegrationDiagnostics(enabled: boolean) {
  const [state, setState] = useState<DiagnosticsState | null>(null);
  const active = useRef<AbortController | null>(null);

  /** Discards local results and prevents an outstanding response from reopening the report. */
  const close = useCallback(() => {
    active.current?.abort();
    active.current = null;
    setState(null);
  }, []);

  /** Cancels the probe when the view unmounts; no provider work is started by an effect. */
  useEffect(() => () => active.current?.abort(), []);

  /** Removes diagnostic evidence when the current session loses administrator/live access. */
  useEffect(() => {
    if (!enabled) close();
  }, [enabled, close]);

  /** Executes one saved connection's bounded read checks and preserves genuine API failures. */
  const run = useCallback(
    async (integration: Integration) => {
      if (!enabled || integration.provider === 'demo') return;
      active.current?.abort();
      const controller = new AbortController();
      active.current = controller;
      setState({ integration, pending: true, report: null, error: null });
      try {
        const report = await api<unknown>(
          `/integrations/${encodeURIComponent(integration.id)}/diagnostics`,
          { method: 'POST', signal: controller.signal },
        );
        if (active.current !== controller || controller.signal.aborted) return;
        if (!isDiagnosticReport(report, integration)) {
          throw new Error(
            'Nyctr returned an invalid diagnostic report. No results were accepted. Run the checks again.',
          );
        }
        setState({ integration, pending: false, report, error: null });
      } catch (error) {
        if (active.current !== controller || controller.signal.aborted) return;
        setState({
          integration,
          pending: false,
          report: null,
          error: error instanceof Error ? error.message : 'Unable to complete diagnostics.',
        });
      }
    },
    [enabled],
  );

  return { state, run, close };
}

/** Shows a check's explicit outcome and source-independent remediation guidance. */
function DiagnosticCheck({ check }: { check: IntegrationDiagnosticCheck }) {
  const status = checkStates[check.status] ?? checkStates.unknown;
  const Icon = status.icon;
  return (
    <li className={`diagnostic-check ${status.tone}`}>
      <span className="diagnostic-check-icon" aria-hidden="true">
        <Icon size={19} />
      </span>
      <div>
        <div className="diagnostic-check-heading">
          <h4>{check.label}</h4>
          <Badge tone={status.tone}>{status.label}</Badge>
        </div>
        <p>{check.summary}</p>
        {check.guidance && (
          <div className="diagnostic-guidance">
            <strong>Guidance</strong>
            <p>{check.guidance}</p>
          </div>
        )}
      </div>
    </li>
  );
}

/** Keeps static adapter support separate from the read evidence obtained during this run. */
function DiagnosticCapability({ capability }: { capability: IntegrationDiagnosticCapability }) {
  const verification = verificationStates[capability.verification] ?? verificationStates.unknown;
  return (
    <tr>
      <td>
        <strong>{capability.label}</strong>
        <p>{capability.summary}</p>
      </td>
      <td>
        <Badge>
          {capability.implementation === 'implemented' ? 'Implemented' : 'Not implemented'}
        </Badge>
      </td>
      <td>
        <Badge tone={verification.tone}>{verification.label}</Badge>
      </td>
    </tr>
  );
}

/**
 * Presents sanitized diagnostic fields, coverage limits, and guidance without raw payloads.
 * A verified result describes bounded reads only; unsupported logs, identity, and
 * other evidence gaps stay visible. Import remains a separate collection action.
 */
export function IntegrationDiagnostics({
  state,
  onClose,
  onRun,
}: {
  state: DiagnosticsState;
  onClose: () => void;
  onRun: () => void;
}) {
  const { integration, pending, report, error } = state;
  const outcome = report ? (outcomes[report.outcome] ?? outcomes.partial) : null;
  const OutcomeIcon = outcome?.icon || CircleHelp;

  return (
    <Modal title="Connection diagnostics" onClose={onClose} className="diagnostics-modal">
      <div className="modal-body diagnostics-body">
        <div className="diagnostics-source">
          <span className="icon-tile large">
            <ScanLine size={23} />
          </span>
          <div>
            <h3>{integration.name}</h3>
            <p>{label(integration.provider)}</p>
          </div>
          <Badge tone="blue">
            <LockKeyhole size={11} />
            Read-only checks
          </Badge>
        </div>
        <p className="diagnostics-intro">
          Test the saved connection and supported reads. Diagnostics do not import a snapshot or
          change network policies. Credentials stay on the server.
        </p>

        {pending && (
          <div className="diagnostics-progress">
            <Loading text="Checking connection…" />
            <p>Verifying configuration, credentials, transport, and supported provider reads.</p>
          </div>
        )}

        {error && (
          <div className="diagnostics-error" role="alert">
            <AlertCircle size={21} />
            <div>
              <h3>Diagnostics could not complete</h3>
              <p>{error}</p>
              <small>
                No new diagnostic result is available. Resolve the issue and run the checks again.
              </small>
            </div>
          </div>
        )}

        {report && outcome && (
          <>
            <section
              className={`diagnostics-outcome ${outcome.tone}`}
              aria-label="Diagnostic outcome"
            >
              <OutcomeIcon size={24} />
              <div>
                <h3>{outcome.label}</h3>
                <p>{report.summary}</p>
                <span className="diagnostics-time">
                  <Clock3 size={12} />
                  Checked {dateTime(report.checked_at)} · {(report.duration_ms / 1000).toFixed(1)} s
                </span>
              </div>
            </section>

            <section className="diagnostics-section" aria-labelledby="diagnostic-checks-title">
              <div className="diagnostics-section-heading">
                <h3 id="diagnostic-checks-title">Connection checks</h3>
                <span>{report.checks.length} checks</span>
              </div>
              <ol className="diagnostic-checks">
                {report.checks.map((check) => (
                  <DiagnosticCheck key={check.id} check={check} />
                ))}
              </ol>
            </section>

            <section
              className="diagnostics-section"
              aria-labelledby="diagnostic-capabilities-title"
            >
              <div className="diagnostics-section-heading">
                <h3 id="diagnostic-capabilities-title">Capability coverage</h3>
              </div>
              <p className="diagnostics-section-description">
                Adapter support describes what is implemented. Verification describes only the reads
                confirmed during this check.
              </p>
              <div className="table-scroll diagnostic-capabilities">
                <table>
                  <thead>
                    <tr>
                      <th>Capability</th>
                      <th>Adapter support</th>
                      <th>This check</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.capabilities.map((capability) => (
                      <DiagnosticCapability key={capability.id} capability={capability} />
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            {report.evidence_gaps.length > 0 && (
              <section className="diagnostic-gaps" aria-labelledby="diagnostic-gaps-title">
                <div className="diagnostics-section-heading">
                  <h3 id="diagnostic-gaps-title">
                    <ShieldQuestion size={17} /> Remaining evidence gaps
                  </h3>
                </div>
                <ul>
                  {report.evidence_gaps.map((gap) => (
                    <li key={gap.id}>
                      <strong>{gap.title}</strong>
                      <p>{gap.summary}</p>
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {report.snapshot_counts && (
              <div className="diagnostic-counts">
                <Database size={16} />
                <div>
                  <strong>Records examined</strong>
                  <p>
                    {report.snapshot_counts.resources} resources ·{' '}
                    {report.snapshot_counts.relationships} relationships ·{' '}
                    {report.snapshot_counts.observations} observations
                  </p>
                  <small>No snapshot was imported into your workspace.</small>
                </div>
              </div>
            )}
            <Notice>
              A working API connection does not establish network safety, traffic reachability, or
              complete block visibility. Use Collect snapshot on the connection card when you are
              ready to import supported evidence.
            </Notice>
          </>
        )}

        <div className="modal-actions diagnostics-actions">
          <button className="button secondary" onClick={onClose}>
            Close report
          </button>
          <button className="button primary" disabled={pending} onClick={onRun}>
            <RefreshCw size={15} className={pending ? 'spin' : ''} />
            {pending ? 'Checking…' : 'Run again'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
