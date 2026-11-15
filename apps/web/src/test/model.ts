import type { ModelConnection } from '../types';

/** A fabricated installation with no model connected, unless overridden. */
export const modelFixture = (extra: Partial<ModelConnection> = {}): ModelConnection => ({
  connected: false,
  endpoint: '',
  model: '',
  secret_ref: '',
  key: 'none',
  trace: 'proxy',
  timeout_seconds: 60,
  source: 'none',
  problem: null,
  editable: true,
  hosts: ['https://llm.example'],
  styles: ['off', 'standard', 'proxy', 'proxy_body'],
  seconds: [5, 120],
  ...extra,
});

/** The same installation after an administrator connected a model in the Console. */
export const modelConnected = (extra: Partial<ModelConnection> = {}) =>
  modelFixture({
    connected: true,
    endpoint: 'https://llm.example/v1',
    model: 'local/reasoner',
    secret_ref: 'NYCTR_MODEL_SECRET_MAIN',
    key: 'reference',
    source: 'console',
    ...extra,
  });
