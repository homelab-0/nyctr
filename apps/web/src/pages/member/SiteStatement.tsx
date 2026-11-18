import { useEffect, useRef, useState, type FormEvent } from 'react';
import { InlineError } from '../../components/ui';
import type { KeptStatement, StatementDraft, StatementFlight } from './useStatementRequests';

/**
 * The site a member types.
 * Mount this under the component that calls useStatementRequests, and pass that
 * hook's callbacks through. The visit opens in a passive effect so the controller's
 * layout pass can close the previous member's visit first. A render that is thrown
 * away does not open, edit, or close a visit. The page does not mount this yet.
 */
export function SiteStatement({
  userId,
  deviceId,
  ask,
  notice,
  draft,
  openForm,
  closeForm,
  editDraft,
  onFile,
}: {
  userId: string;
  deviceId: string;
  ask: StatementFlight | null;
  notice: KeptStatement | null;
  draft: { current: StatementDraft };
  openForm: () => number;
  closeForm: (formId: number) => void;
  editDraft: (site: string) => number;
  onFile: (site: string, revision: number, formId: number) => void;
}) {
  const [site, setSite] = useState('');
  const typed = useRef('');
  const member = useRef<string | null>(null);
  // A new visit opens after commit. The same member keeps the name already typed.
  // A different member starts from a blank field.
  useEffect(() => {
    const switched = member.current !== null && member.current !== userId;
    member.current = userId;
    const id = openForm();
    if (switched) {
      typed.current = '';
      setSite('');
    } else if (typed.current !== '') editDraft(typed.current);
    return () => closeForm(id);
  }, [closeForm, deviceId, editDraft, openForm, userId]);
  const current = draft.current;
  const sameAsk =
    !!ask &&
    ask.userId === userId &&
    ask.deviceId === deviceId &&
    ask.formId === current.formId &&
    ask.revision === current.revision &&
    ask.site === current.site;
  const asking = sameAsk && ask.phase === 'pending';
  const message = sameAsk && ask.phase === 'settled' ? ask.message : null;
  const earlier =
    notice &&
    notice.userId === userId &&
    notice.deviceId === deviceId &&
    (notice.parked || notice.formId !== current.formId || notice.revision !== current.revision)
      ? notice
      : null;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const filed = draft.current;
    onFile(filed.site, filed.revision, filed.formId);
  };
  return (
    <form className="m-card pad form-stack" onSubmit={submit}>
      <h2>A site did not open</h2>
      <p className="aside">
        Type the site's name. Nyctr checks whether that name was blocked in the last few minutes,
        then files a request for this device.
      </p>
      <label className="field">
        <span>Site name</span>
        <input
          type="text"
          value={site}
          onChange={(event) => {
            const next = event.target.value;
            typed.current = next;
            setSite(next);
            editDraft(next);
          }}
          placeholder="example.com"
          aria-label="Site that did not open"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
        />
      </label>
      <InlineError message={message} />
      {earlier && (
        <p className="aside" role="status">
          Nyctr filed your request for <span className="dom">{earlier.request.domain}</span>.{' '}
          <a href={`#/portal?request=${earlier.request.id}`}>Open that request</a>
        </p>
      )}
      <button className="button primary large full" type="submit" disabled={asking || !site.trim()}>
        {asking ? 'Asking…' : 'Ask about this site'}
      </button>
    </form>
  );
}
