import { describe, it, expect } from 'vitest';
import { gamArgsForAction, isResponseAction, passwordFromOutput, RESPONSE_ACTIONS, gamArgsForRemove, isRemoveKind } from './response-actions';

describe('gamArgsForRemove (kill persistence)', () => {
  const m = 'victim@example.org';
  it('builds the delete/forward commands for each kind', () => {
    expect(gamArgsForRemove('filter', m, 'ANe1Bmg-abc_123')).toEqual(['user', m, 'delete', 'filter', 'ANe1Bmg-abc_123']);
    expect(gamArgsForRemove('forwardingaddress', m, 'Attacker@Evil.test')).toEqual(['user', m, 'delete', 'forwardingaddress', 'attacker@evil.test']);
    expect(gamArgsForRemove('delegate', m, 'spy@evil.test')).toEqual(['user', m, 'delete', 'delegate', 'spy@evil.test']);
    expect(gamArgsForRemove('forward_off', m, '')).toEqual(['user', m, 'forward', 'off']);
  });

  it('rejects a bad mailbox, a bad filter id, or a non-email target', () => {
    expect(gamArgsForRemove('filter', 'not-an-email', 'abc')).toBeNull();
    expect(gamArgsForRemove('filter', m, 'has space')).toBeNull();
    expect(gamArgsForRemove('forwardingaddress', m, 'not-an-email')).toBeNull();
    expect(gamArgsForRemove('delegate', m, '')).toBeNull();
  });

  it('isRemoveKind guards the kind', () => {
    expect(isRemoveKind('filter')).toBe(true);
    expect(isRemoveKind('forward_off')).toBe(true);
    expect(isRemoveKind('suspend')).toBe(false);
    expect(isRemoveKind(null)).toBe(false);
  });
});

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
