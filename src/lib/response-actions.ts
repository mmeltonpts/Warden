/**
 * Account response actions — the destructive side GAM can do that Warden otherwise doesn't:
 * sign a user out, revoke their app passwords and OAuth tokens, reset their password, and
 * suspend or un-suspend the account.
 *
 * Pure registry + argument builder, kept apart from the GAM runner and the UI so the mapping
 * from an action name to an exact GAM command is one small, tested thing. Every one of these
 * locks a real person out of, or changes, their account, so the UI requires typing the
 * mailbox to confirm and every run is audited. None of them is ever automatic.
 */
export type ResponseAction = 'signout' | 'deprovision' | 'reset' | 'suspend' | 'unsuspend';

export interface ActionDef {
  key: ResponseAction;
  label: string;
  /** One line shown under the button. */
  blurb: string;
  /** 'high' = red, locks out or changes credentials; 'medium' = amber, disruptive but light. */
  danger: 'high' | 'medium';
  /** Past-tense verb for the confirmation and audit, e.g. "suspended". */
  done: string;
  reversible: string;
}

export const RESPONSE_ACTIONS: Record<ResponseAction, ActionDef> = {
  signout: {
    key: 'signout',
    label: 'Force sign-out',
    blurb: 'Revokes all active session cookies. The attacker is logged out; the real user signs in again normally.',
    danger: 'medium',
    done: 'signed out',
    reversible: 'The user just signs in again — nothing is lost.'
  },
  deprovision: {
    key: 'deprovision',
    label: 'Revoke app passwords & OAuth tokens',
    blurb: 'Deprovisions app passwords, connected OAuth apps and backup codes — the persistence that survives a password reset.',
    danger: 'high',
    done: 'deprovisioned',
    reversible: 'The user re-authorises their own apps (mail on their phone, etc.) afterwards.'
  },
  reset: {
    key: 'reset',
    label: 'Reset password',
    blurb: 'Sets a new random password and forces a change at next sign-in. The new password is shown once, here.',
    danger: 'high',
    done: 'password reset',
    reversible: 'Reset again to issue another password.'
  },
  suspend: {
    key: 'suspend',
    label: 'Suspend account',
    blurb: 'Locks the account entirely: no sign-in, no mail, until un-suspended. The strongest and most disruptive option.',
    danger: 'high',
    done: 'suspended',
    reversible: 'Fully reversible with Un-suspend.'
  },
  unsuspend: {
    key: 'unsuspend',
    label: 'Un-suspend account',
    blurb: 'Restores a suspended account to normal.',
    danger: 'medium',
    done: 'un-suspended',
    reversible: 'Suspend again if needed.'
  }
};

export function isResponseAction(x: unknown): x is ResponseAction {
  return typeof x === 'string' && x in RESPONSE_ACTIONS;
}

/**
 * The exact GAM arguments for an action against a mailbox. Returns null for an unknown
 * action or a mailbox that is not a plausible address — the runner must never be handed a
 * half-formed command.
 */
export function gamArgsForAction(action: ResponseAction, mailbox: string): string[] | null {
  const m = String(mailbox ?? '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(m)) return null;
  switch (action) {
    case 'signout': return ['user', m, 'signout'];
    case 'deprovision': return ['user', m, 'deprovision'];
    case 'reset': return ['update', 'user', m, 'password', 'random', 'changepassword', 'on'];
    case 'suspend': return ['update', 'user', m, 'suspended', 'on'];
    case 'unsuspend': return ['update', 'user', m, 'suspended', 'off'];
    default: return null;
  }
}

/** Pull the generated password out of `gam update user … password random` output. */
export function passwordFromOutput(out: string): string | null {
  return out.match(/\bPassword:\s*([^\s,]+)/)?.[1] ?? null;
}
