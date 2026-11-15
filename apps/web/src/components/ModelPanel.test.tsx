import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { mockApi } from '../test/mock-api';
import { modelConnected, modelFixture } from '../test/model';
import type { ModelConnection, ModelTest } from '../types';
import { ModelPanel } from './ModelPanel';

/** Shows the card over a fabricated connection that a save replaces and a test answers. */
function open(first: ModelConnection, test: ModelTest | { __status: number; detail: string }) {
  let current = first;
  const calls = mockApi({
    'GET /model': () => current,
    'PUT /model': (body: unknown) => {
      current = modelConnected(body as Partial<ModelConnection>);
      return current;
    },
    'POST /model/test': test,
  });
  render(<ModelPanel />);
  return { calls, user: userEvent.setup() };
}

const field = (name: RegExp) => screen.findByLabelText(name) as Promise<HTMLInputElement>;
const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement;

beforeEach(() => setCsrfToken('csrf'));
afterEach(() => {
  cleanup();
  setCsrfToken('');
  vi.unstubAllGlobals();
});

describe('the Model card in Setup', () => {
  it('says the assistant is off when no model is connected, and what the server allows', async () => {
    open(modelFixture(), { outcome: 'reachable', status: null });
    expect((await field(/^Endpoint/)).value).toBe('');
    expect(screen.getByText(/No model is connected, so the assistant is off/)).toBeDefined();
    expect(
      screen.getByText(
        /for example https:\/\/llm\.example\/v1\. .* each exactly as written: https:\/\/llm\.example\./,
      ),
    ).toBeDefined();
    expect(
      screen.getByText('Nothing is set on the server and nothing is saved here.'),
    ).toBeDefined();
    expect(button('Test').disabled).toBe(true);
    expect(button('Save').disabled).toBe(true);
  });

  it('saves the endpoint, the model, the name of the secret, the tracing and the time limit', async () => {
    const { calls, user } = open(modelFixture(), { outcome: 'reachable', status: null });
    await user.type(await field(/^Endpoint/), 'https://llm.example/v1');
    await user.type(await field(/^Model/), 'local/reasoner');
    await user.type(await field(/^Name of the secret/), 'NYCTR_MODEL_SECRET_MAIN');
    const tracing = (await field(/^Tracing/)) as unknown as HTMLSelectElement;
    expect([...tracing.options].map((option) => option.text)).toEqual([
      'Off: nothing extra is sent',
      'A trace number only',
      'For a tracing proxy: what each call is for',
      'For a tracing proxy, also inside the request',
    ]);
    await user.selectOptions(tracing, 'standard');
    await user.clear(await field(/^Time limit/));
    await user.type(await field(/^Time limit/), '30');
    await user.click(button('Save'));
    expect(await screen.findByText(/^Saved\. Press Test/)).toBeDefined();
    expect(calls.filter((call) => call.method === 'PUT').map((call) => call.body)).toEqual([
      {
        endpoint: 'https://llm.example/v1',
        model: 'local/reasoner',
        secret_ref: 'NYCTR_MODEL_SECRET_MAIN',
        trace: 'standard',
        timeout_seconds: 30,
      },
    ]);
    expect(screen.getByText('Saved here. It replaces what was set on the server.')).toBeDefined();
    expect(screen.queryByText(/the assistant is off/)).toBeNull();
    await user.click(button('Test'));
    expect(await screen.findByText('The model answered.')).toBeDefined();
  });

  it('says where a value set on the server comes from, and that its key is the server’s', async () => {
    open(modelConnected({ source: 'deployment', secret_ref: '', key: 'server' }), {
      outcome: 'reachable',
      status: null,
    });
    await field(/^Endpoint/);
    expect(
      screen.getByText(/set on the server with NYCTR_AI_BASE_URL and NYCTR_AI_MODEL/),
    ).toBeDefined();
    expect(
      screen.getByText(/the key set on the server with NYCTR_AI_API_KEY is used/),
    ).toBeDefined();
  });

  it('shows the tracing in force for a value set on the server, and saving keeps it unless another is picked', async () => {
    const { calls, user } = open(
      modelConnected({ source: 'deployment', secret_ref: '', key: 'server', trace: 'off' }),
      { outcome: 'reachable', status: null },
    );
    const tracing = (await field(/^Tracing/)) as unknown as HTMLSelectElement;
    expect(tracing.value).toBe('off');
    expect(tracing.selectedOptions[0].text).toBe('Off: nothing extra is sent');
    expect(
      screen.getByText(/was set on the server \(NYCTR_AI_TRACE\)\. Saving keeps it/),
    ).toBeDefined();
    // Nothing has been changed, so there is nothing to save; what is in force can be tested.
    expect(button('Save').disabled).toBe(true);
    expect(button('Test').disabled).toBe(false);
    await user.type(await field(/^Model/), '-2');
    await user.click(button('Save'));
    expect(await screen.findByText(/^Saved\. Press Test/)).toBeDefined();
    expect(calls.find((call) => call.method === 'PUT')?.body).toMatchObject({
      model: 'local/reasoner-2',
      trace: 'off',
    });
    expect(button('Save').disabled).toBe(true);
  });

  it('says a saved setting that cannot be read must be saved again, not that no model is connected', async () => {
    const problem =
      'The saved model setting cannot be read by this version of Nyctr, so the model is off. Save it again under Setup, This installation.';
    open(modelFixture({ source: 'console', problem }), { outcome: 'reachable', status: null });
    expect((await screen.findByRole('alert')).textContent).toBe(
      `The saved model cannot be used right now. ${problem}`,
    );
    expect(screen.queryByText(/No model is connected/)).toBeNull();
    expect(((await field(/^Tracing/)) as unknown as HTMLSelectElement).value).toBe('proxy');
    expect(button('Test').disabled).toBe(true);
  });

  it('says in the server’s words when the address set on the server cannot be used', async () => {
    const problem =
      "The model's address set on the server (NYCTR_AI_BASE_URL) cannot be used: it names no server, or its port is not a number from 1 to 65535. Whoever runs the Nyctr server corrects it there. Until then the model is off.";
    open(modelFixture({ source: 'deployment', problem }), { outcome: 'reachable', status: null });
    // Not "the saved model": nothing was saved here, and nothing here can correct it.
    expect((await screen.findByRole('alert')).textContent).toBe(problem);
    expect(screen.queryByText(/No model is connected/)).toBeNull();
    expect(button('Test').disabled).toBe(true);
    expect(button('Save').disabled).toBe(true);
  });

  it.each<[ModelTest, RegExp]>([
    [{ outcome: 'refused', status: 401 }, /refused the key \(HTTP 401\)/],
    [
      { outcome: 'refused', status: 307 },
      /sent Nyctr somewhere else \(HTTP 307\)\. Nyctr never follows/,
    ],
    [{ outcome: 'refused', status: 404 }, /does not know that address or that model/],
    [{ outcome: 'refused', status: 503 }, /refused the question \(HTTP 503\)/],
    [{ outcome: 'not_reachable', status: null }, /could not reach the endpoint/],
    [{ outcome: 'wrong_shape', status: null }, /not the way a chat endpoint does/],
    [{ outcome: 'too_slow', status: null }, /No answer came within the time limit/],
  ])('says in plain words what a test found: %o', async (result, words) => {
    const { user } = open(modelConnected(), result);
    await field(/^Endpoint/);
    await user.click(button('Test'));
    expect((await screen.findByRole('alert')).textContent).toMatch(words);
  });

  it('tests only what is saved, and shows a refused save in the server’s own words', async () => {
    const { calls, user } = open(modelConnected(), { outcome: 'reachable', status: null });
    await user.type(await field(/^Model/), '-2');
    expect(button('Test').disabled).toBe(true);
    mockApi({
      'PUT /model': { __status: 422, detail: 'Not saved. That secret is not set on the server.' },
    });
    await user.click(button('Save'));
    expect((await screen.findByRole('alert')).textContent).toBe(
      'Not saved. That secret is not set on the server.',
    );
    expect(((await field(/^Model/)) as HTMLInputElement).value).toBe('local/reasoner-2');
    expect(calls.some((call) => call.path === '/model/test')).toBe(false);
  });

  it('shows why a saved model cannot be used now, and a test the server would not send', async () => {
    const problem = 'That secret is not set on the server.';
    const { user } = open(modelConnected({ problem }), {
      __status: 409,
      detail: `Not sent. ${problem}`,
    });
    expect(
      await screen.findByText(`The saved model cannot be used right now. ${problem}`),
    ).toBeDefined();
    await user.click(button('Test'));
    await waitFor(() => expect(screen.getByText(`Not sent. ${problem}`)).toBeDefined());
  });

  it('cannot be changed in the demo workspace', async () => {
    open(modelFixture({ editable: false, hosts: [] }), { outcome: 'reachable', status: null });
    expect((await field(/^Endpoint/)).disabled).toBe(true);
    expect(
      screen.getByText(
        'This is the demo workspace. It answers from samples, and a model cannot be connected here.',
      ),
    ).toBeDefined();
    // The demo's assistant is not off, and no operator's list applies to it.
    expect(screen.queryByText(/the assistant is off/)).toBeNull();
    expect(document.body.textContent).not.toMatch(/NYCTR_MODEL_HOSTS|has not allowed/);
    expect(button('Save').disabled).toBe(true);
  });
});
