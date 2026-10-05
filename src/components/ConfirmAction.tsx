'use client';

import { useState } from 'react';
import { useFormStatus } from 'react-dom';

/**
 * A button that will not fire until you open a modal and type the confirmation text exactly
 * (the mailbox). Two deliberate steps — click, then type — because every action this guards
 * locks a real person out of, or changes, their account, and a stray click must never be
 * enough. The form still posts to a server action, which re-checks the typed value, so the
 * guard is not only client-side.
 */
function Submit({ label, disabled, danger }: { label: string; disabled: boolean; danger: boolean }) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={disabled || pending}
      className={`btn text-sm ${danger ? 'btn-danger' : 'btn-primary'}`}
    >
      {pending ? 'Working…' : label}
    </button>
  );
}

export function ConfirmAction({
  action,
  mailbox,
  actionKey,
  label,
  blurb,
  reversible,
  danger,
  confirmText,
  extraFields,
  requireReason
}: {
  action: (formData: FormData) => void | Promise<void>;
  mailbox: string;
  actionKey: string;
  label: string;
  blurb: string;
  reversible: string;
  danger: boolean;
  /** What must be typed to enable the action — the mailbox. */
  confirmText: string;
  /** Extra hidden fields to post, e.g. the kind/target of a persistence item to remove. */
  extraFields?: Record<string, string>;
  /** Require a non-empty reason, posted as `reason`, before the action can fire. */
  requireReason?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState('');
  const [reason, setReason] = useState('');
  const match =
    typed.trim().toLowerCase() === confirmText.trim().toLowerCase() &&
    (!requireReason || reason.trim().length > 0);

  return (
    <>
      <button
        type="button"
        onClick={() => { setOpen(true); setTyped(''); }}
        className={`btn w-full justify-start text-sm ${danger ? 'btn-danger' : ''}`}
      >
        {label}
      </button>

      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.55)' }}
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-lg border bg-bg-surface p-5 shadow-xl"
            style={danger ? { borderColor: 'rgb(var(--danger) / 0.6)' } : undefined}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-base font-semibold">{label}</h3>
            <p className="mt-1 text-sm text-text-muted">{blurb}</p>
            <div className="mt-3 rounded border px-3 py-2 text-sm">
              <div className="text-text-muted">This will act on</div>
              <div className="mono font-medium">{mailbox}</div>
            </div>
            <p className="mt-3 text-xs text-text-muted">{reversible}</p>

            <form action={action} className="mt-4 space-y-3">
              <input type="hidden" name="action" value={actionKey} />
              <input type="hidden" name="mailbox" value={mailbox} />
              <input type="hidden" name="confirm" value={typed} />
              {extraFields &&
                Object.entries(extraFields).map(([k, v]) => (
                  <input key={k} type="hidden" name={k} value={v} />
                ))}
              {requireReason && (
                <label className="block text-sm">
                  <span className="mb-1 block">Reason / ticket</span>
                  <input
                    name="reason"
                    autoComplete="off"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    className="w-full rounded border bg-bg-elevated px-3 py-2 text-sm"
                    placeholder="why this is being removed"
                  />
                </label>
              )}
              <label className="block text-sm">
                <span className="mb-1 block">
                  Type <span className="mono font-semibold">{confirmText}</span> to confirm
                </span>
                <input
                  autoFocus
                  autoComplete="off"
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                  className="mono w-full rounded border bg-bg-elevated px-3 py-2 text-sm"
                  placeholder={confirmText}
                />
              </label>
              <div className="flex justify-end gap-2">
                <button type="button" onClick={() => setOpen(false)} className="btn text-sm">Cancel</button>
                <Submit label={label} disabled={!match} danger={danger} />
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
