import { dig, fieldsIn, isRequired } from '@/lib/settings-form';

/** The input for every field in one section. Values come from masked display settings. */
export function SettingsFields({ section, values }: { section: string; values: Record<string, unknown> }) {
  return (
    <>
      {fieldsIn(section).map((f) => {
        const val = dig(values, f.key);
        const input = 'mono w-full rounded border bg-bg-elevated px-3 py-1.5 text-sm';
        return (
          <div key={f.key} className="card">
            <label className="block text-sm">
              <span className="mb-1 block font-medium">
                {f.label}
                {isRequired(f) && <span className="ml-1 text-xs text-text-muted">(required)</span>}
              </span>
              {f.type === 'boolean' ? (
                <span className="flex items-center gap-2">
                  <input name={f.key} type="checkbox" defaultChecked={Boolean(val)} className="h-4 w-4" />
                  <span className="text-xs text-text-muted">enabled</span>
                </span>
              ) : f.type === 'textarea' ? (
                <textarea
                  name={f.key}
                  rows={Math.min(16, Math.max(3, String(val ?? '').split('\n').length + 1))}
                  defaultValue={val === undefined || val === null ? '' : String(val)}
                  className={input}
                />
              ) : f.type === 'list' ? (
                <textarea
                  name={f.key}
                  rows={Math.min(10, Math.max(3, Array.isArray(val) ? val.length + 1 : 3))}
                  defaultValue={Array.isArray(val) ? val.join('\n') : ''}
                  className={input}
                />
              ) : f.type === 'select' && 'options' in f ? (
                <select name={f.key} defaultValue={String(val ?? '')} className={input}>
                  {(f.options as readonly string[]).map((o) => (
                    <option key={o} value={o}>{o}</option>
                  ))}
                </select>
              ) : (
                <input
                  name={f.key}
                  type={f.type === 'number' ? 'number' : 'text'}
                  required={isRequired(f)}
                  defaultValue={val === undefined || val === null ? '' : String(val)}
                  className={input}
                />
              )}
            </label>
            {'help' in f && f.help && <p className="mt-1.5 text-xs text-text-muted">{f.help}</p>}
          </div>
        );
      })}
    </>
  );
}
