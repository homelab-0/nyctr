import { useEffect, useMemo, useState } from 'react';
import { Play } from 'lucide-react';
import { post } from '../api';
import { InlineError, Panel, Seg } from '../components/ui';

interface TypeRef {
  name: string | null;
  kind: string;
  ofType?: TypeRef | null;
}
interface SchemaField {
  name: string;
  description: string | null;
  args: { name: string; type: TypeRef }[];
  type: TypeRef;
}
interface SchemaType {
  name: string;
  kind: string;
  description: string | null;
  fields: SchemaField[] | null;
}
interface Result {
  data: Record<string, unknown> | null;
  errors?: { message: string }[];
}

const INTROSPECTION = `{ __schema { types { name kind description fields { name description
  args { name type { ...T } } type { ...T } } } } }
fragment T on __Type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }`;

const SAVED = [
  {
    name: 'Workloads with the firewall off',
    text: '{\n  workloads(firewall: false) {\n    name\n    attr(key: "vmid")\n    network { name }\n    neighbors(kind: "host") { name }\n  }\n}',
  },
  {
    name: 'Every network and what is on it',
    text: '{\n  networks {\n    name\n    vlan: attr(key: "vlan")\n    neighbors(first: 100) { name kind provider }\n  }\n}',
  },
  {
    name: 'High-risk blocks in the last day',
    text: '{\n  blocks(minScore: 61) {\n    domain\n    riskScore\n    reason\n    deviceName\n    attribution\n  }\n}',
  },
  {
    name: 'Links Nyctr inferred between sources',
    text: '{\n  links(evidence: "inferred") {\n    kind\n    basis\n    source { name provider }\n    target { name provider }\n  }\n}',
  },
  {
    name: 'Guest devices and their lookups',
    text: '{\n  resources(kind: ["client"], where: [{key: "guest", exists: true}]) {\n    name\n    hasAccess: attr(key: "guest.authorized")\n    blocks { domain riskBand }\n  }\n}',
  },
];

/** Writes a GraphQL type reference the way the schema does: [Resource!]! */
function typeText(ref: TypeRef | null | undefined): string {
  if (!ref) return '';
  if (ref.kind === 'NON_NULL') return `${typeText(ref.ofType)}!`;
  if (ref.kind === 'LIST') return `[${typeText(ref.ofType)}]`;
  return ref.name || '';
}

/** Flattens a result row for the table view; nested objects become short text. */
function cell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) return value.map(cell).join(', ');
  if (typeof value === 'object')
    return Object.values(value as Record<string, unknown>)
      .map(cell)
      .filter(Boolean)
      .join(' · ');
  return String(value);
}

/**
 * A read-only GraphQL browser over stored evidence. Nothing can be changed here; the server
 * limits query length, depth and result size.
 */
export default function Queries({ params }: { params: URLSearchParams }) {
  const [text, setText] = useState(params.get('q') || SAVED[0].text);
  const [result, setResult] = useState<Result | null>(null);
  const [schema, setSchema] = useState<SchemaType[]>([]);
  const [open, setOpen] = useState('Query');
  const [view, setView] = useState<'table' | 'json'>('table');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /** Runs the query in the editor and shows data and any GraphQL errors side by side. */
  const run = async (query = text) => {
    setPending(true);
    setError(null);
    try {
      setResult(await post<Result>('/graph/query', { query }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  useEffect(() => {
    post<Result>('/graph/query', { query: INTROSPECTION })
      .then((value) => {
        const types =
          (value.data as { __schema?: { types: SchemaType[] } } | null)?.__schema?.types || [];
        setSchema(types.filter((type) => type.kind === 'OBJECT' && !type.name.startsWith('__')));
      })
      .catch(() => setSchema([]));
    void run();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const tables = useMemo(() => {
    if (!result?.data) return [];
    return Object.entries(result.data).map(([name, value]) => {
      const rows = (Array.isArray(value) ? value : value ? [value] : []) as Record<
        string,
        unknown
      >[];
      const columns = [
        ...new Set(rows.flatMap((row) => (row && typeof row === 'object' ? Object.keys(row) : []))),
      ];
      return { name, rows, columns };
    });
  }, [result]);
  const current = schema.find((type) => type.name === open);
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d2">Queries</h1>
          <p className="lede">
            Ask the inventory precise questions in GraphQL. Read-only: there is nothing here that
            can change your network.
          </p>
        </div>
      </header>
      <div className="gql">
        <Panel title="Schema" flush className="gql-schema">
          <div className="gql-types">
            {schema.map((type) => (
              <button
                key={type.name}
                aria-pressed={open === type.name}
                onClick={() => setOpen(type.name)}
              >
                {type.name}
              </button>
            ))}
          </div>
          <div className="gql-fields">
            {current?.description && <p className="aside">{current.description}</p>}
            {(current?.fields || []).map((field) => (
              <div key={field.name} className="gql-field">
                <code>
                  <b>{field.name}</b>
                  {field.args.length > 0 &&
                    `(${field.args.map((arg) => `${arg.name}: ${typeText(arg.type)}`).join(', ')})`}
                  : <span>{typeText(field.type)}</span>
                </code>
                {field.description && <p>{field.description}</p>}
              </div>
            ))}
            {schema.length === 0 && <p className="aside">The schema could not be loaded.</p>}
          </div>
        </Panel>
        <div className="stack">
          <Panel
            title="Query"
            action={
              <button
                className="button primary small"
                disabled={pending}
                onClick={() => void run()}
              >
                <Play size={14} /> {pending ? 'Running…' : 'Run'} <kbd>⌘↵</kbd>
              </button>
            }
            flush
          >
            <textarea
              className="gql-editor mono"
              spellCheck={false}
              rows={10}
              value={text}
              aria-label="GraphQL query"
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => {
                if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
                  e.preventDefault();
                  void run();
                }
              }}
            />
            <div className="chips pad">
              {SAVED.map((item) => (
                <button
                  key={item.name}
                  className="chip"
                  onClick={() => {
                    setText(item.text);
                    void run(item.text);
                  }}
                >
                  {item.name}
                </button>
              ))}
            </div>
          </Panel>
          <Panel
            title="Result"
            action={
              <Seg
                label="Result view"
                value={view}
                onChange={setView}
                options={[
                  { id: 'table', name: 'Table' },
                  { id: 'json', name: 'JSON' },
                ]}
              />
            }
            flush
          >
            <InlineError message={error} />
            {result?.errors?.map((item) => (
              <div className="inline-error" key={item.message} style={{ margin: 12 }}>
                {item.message}
              </div>
            ))}
            {view === 'json' ? (
              <pre className="gql-json mono">
                {result ? JSON.stringify(result.data, null, 2) : ''}
              </pre>
            ) : (
              tables.map((table) => (
                <div key={table.name}>
                  <div className="gql-table-name">
                    <b>{table.name}</b> <span className="muted">{table.rows.length} rows</span>
                  </div>
                  {table.rows.length === 0 ? (
                    <p className="pad muted">No rows.</p>
                  ) : (
                    <div className="tblwrap">
                      <table className="tbl">
                        <thead>
                          <tr>
                            {table.columns.map((column) => (
                              <th key={column}>{column}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {table.rows.slice(0, 300).map((row, index) => (
                            <tr key={index}>
                              {table.columns.map((column) => (
                                <td key={column}>{cell(row?.[column])}</td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              ))
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
