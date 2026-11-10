import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import Assistant from './Assistant';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('assistant drawer', () => {
  it('links only the citations the server returned and labels sample answers', async () => {
    mockApi({
      'GET /assistant': { provider: 'sample', model: '' },
      'POST /assistant/ask': {
        answer: 'Pixel 8 is cut off [[g1]]. Also see [[x9]] this.',
        references: [{ ref: 'g1', kind: 'guest', id: 'guest-pixel', label: 'Pixel 8' }],
        provider: 'sample',
        model: '',
      },
    });
    const user = userEvent.setup();
    render(<Assistant open onClose={() => {}} attention={[]} />);
    await user.click(await screen.findByRole('button', { name: 'Who is on the guest Wi-Fi?' }));
    const link = await screen.findByRole('link', { name: 'Pixel 8' });
    expect(link.getAttribute('href')).toBe('#/guests?id=guest-pixel');
    expect(screen.getAllByRole('link')).toHaveLength(1);
    expect(screen.queryByText(/x9/)).toBeNull();
    expect(screen.getByText('Sample answer. No model was used.')).toBeDefined();
  });

  it('keeps the rule-based list but turns questions off when no model is connected', async () => {
    mockApi({ 'GET /assistant': { provider: 'off', model: '' } });
    render(
      <Assistant
        open
        onClose={() => {}}
        attention={[
          {
            kind: 'request',
            id: 'r1',
            severity: 'high',
            title: 'Sam is waiting on odd.example',
            detail: '',
            at: null,
          },
        ]}
      />,
    );
    expect(await screen.findByText('No model connected')).toBeDefined();
    expect((screen.getByLabelText('Your question') as HTMLTextAreaElement).disabled).toBe(true);
    expect(
      screen.getByRole('link', { name: 'Sam is waiting on odd.example' }).getAttribute('href'),
    ).toBe('#/requests?id=r1');
    expect(screen.queryByRole('button', { name: 'What needs me first?' })).toBeNull();
  });

  it('shows a failed question as an error instead of an invented answer', async () => {
    mockApi({
      'GET /assistant': { provider: 'model', model: 'test-model' },
      'POST /assistant/ask': {
        __status: 502,
        detail: 'The model endpoint did not return a usable answer.',
      },
    });
    const user = userEvent.setup();
    render(<Assistant open onClose={() => {}} attention={[]} />);
    await user.type(await screen.findByLabelText('Your question'), 'What is open?{Enter}');
    expect((await screen.findByRole('alert')).textContent).toContain(
      'did not return a usable answer',
    );
    expect(screen.getByText('What is open?')).toBeDefined();
  });

  it('lets the person turn the A shortcut off, and hides the switch where it does not apply', async () => {
    mockApi({ 'GET /assistant': { provider: 'off', model: '' } });
    const changed = vi.fn();
    const user = userEvent.setup();
    const { unmount } = render(
      <Assistant open onClose={() => {}} attention={[]} shortcut onShortcut={changed} />,
    );
    const toggle = await screen.findByRole('switch', {
      name: 'Open and close the assistant with the A key',
    });
    expect(toggle.getAttribute('aria-checked')).toBe('true');
    await user.click(toggle);
    expect(changed).toHaveBeenCalledWith(false);
    unmount();
    render(<Assistant open onClose={() => {}} attention={[]} />);
    expect(screen.queryByRole('switch')).toBeNull();
  });
});
