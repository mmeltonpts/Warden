'use client';

import { useFormStatus } from 'react-dom';

/**
 * A submit button that says it is working.
 *
 * Server actions give the page no feedback while they run. For a step that takes up to a
 * minute — Claude triage — the page simply sat there, which reads as "nothing happened"
 * and invites a second click. This disables the button and relabels it until the action
 * returns.
 */
export function PendingButton({
  children,
  pending,
  className = 'btn text-xs',
  disabled,
  name,
  value,
  formAction
}: {
  children: React.ReactNode;
  pending: string;
  className?: string;
  disabled?: boolean;
  /** Sent with the form, so one form can offer two submit buttons that do different things. */
  name?: string;
  value?: string;
  /** A different server action for this button. Unlike name/value, this cannot be lost when the button disables itself. */
  formAction?: (formData: FormData) => void | Promise<void>;
}) {
  const { pending: busy } = useFormStatus();
  return (
    <button className={className} disabled={disabled || busy} aria-busy={busy} name={name} value={value} formAction={formAction}>
      {busy ? pending : children}
    </button>
  );
}
