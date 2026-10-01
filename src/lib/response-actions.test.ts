import { describe, it, expect } from 'vitest';
import { gamArgsForAction, isResponseAction, passwordFromOutput, RESPONSE_ACTIONS } from './response-actions';

describe('response action argument builder', () => {
  const m = 'jane.doe@example.org';
  it('maps each action to its exact GAM command', () => {
    expect(gamArgsForAction('signout', m)).toEqual(['user', m, 'signout']);
    expect(gamArgsForAction('deprovision', m)).toEqual(['user', m, 'deprovision']);
    expect(gamArgsForAction('reset', m)).toEqual(['update', 'user', m, 'password', 'random', 'changepassword', 'on']);
    expect(gamArgsForAction('suspend', m)).toEqual(['update', 'user', m, 'suspended', 'on']);
    expect(gamArgsForAction('unsuspend', m)).toEqual(['update', 'user', m, 'suspended', 'off']);
  });

  it('refuses a mailbox that is not a real address', () => {
    expect(gamArgsForAction('suspend', 'jane.doe')).toBeNull();
    expect(gamArgsForAction('suspend', 'rm -rf /; user@x')).toBeNull();
    expect(gamArgsForAction('suspend', '')).toBeNull();
  });

  it('lower-cases the mailbox', () => {
    // ['update','user', <mailbox>, 'suspended','on'] — the mailbox is index 2.
    expect(gamArgsForAction('suspend', 'Jane.Doe@Example.org')![2]).toBe('jane.doe@example.org');
    expect(gamArgsForAction('signout', 'Jane.Doe@Example.org')![1]).toBe('jane.doe@example.org');
  });

  it('validates action names', () => {
    expect(isResponseAction('suspend')).toBe(true);
    expect(isResponseAction('delete')).toBe(false);
    expect(isResponseAction(null)).toBe(false);
  });

  it('every action has a definition', () => {
    for (const k of ['signout', 'deprovision', 'reset', 'suspend', 'unsuspend'] as const) {
      expect(RESPONSE_ACTIONS[k].label).toBeTruthy();
    }
  });

  it('reads the generated password from reset output', () => {
    expect(passwordFromOutput('User: jane@example.org, Password: Xy7-kf2Qa9, Must Change Password: True')).toBe('Xy7-kf2Qa9');
    expect(passwordFromOutput('User: jane@example.org, Suspended: True')).toBeNull();
  });
});
