const REDACTED = '[redacted]';
const PUBLIC_FIELDS = new Set(['source', 'origin', 'outcome', 'reason', 'state', 'code', 'session_handle', 'expires_at']);

export function secretForms(secret: string): string[] {
  if (!secret) return [];
  const utf8 = Buffer.from(secret, 'utf8');
  const forms = new Set<string>([
    secret,
    utf8.toString('base64'),
    utf8.toString('base64url'),
    encodeURIComponent(secret),
  ]);
  const json = JSON.stringify(secret).slice(1, -1);
  if (json) forms.add(json);
  return [...forms].filter(form => form.length > 0);
}

export function scrubText(text: string, secret?: string): string {
  if (!secret) return text;
  let out = text;
  for (const form of secretForms(secret)) {
    if (form && out.includes(form)) out = out.split(form).join(REDACTED);
  }
  return out;
}

export function scrubValue(value: unknown, secret?: string, publicField = false): unknown {
  if (!secret) return value;
  if (typeof value === 'string') return publicField ? value : scrubText(value, secret);
  if (Array.isArray(value)) return value.map(item => scrubValue(item, secret));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      out[publicField ? key : scrubText(key, secret)] = scrubValue(nested, secret, PUBLIC_FIELDS.has(key));
    }
    return out;
  }
  return value;
}

export function writeScrubbed(stream: NodeJS.WritableStream, chunk: string, secret?: string): void {
  stream.write(scrubText(chunk, secret));
}
