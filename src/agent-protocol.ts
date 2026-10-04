export const BOOTSTRAP_TYPE = 'stackey-request+jwt';
export const RESPONSE_TYPE = 'stackey-response+jwt';
export const issuer = (nodeId: string) => `urn:stackey:node:${nodeId}`;
export const isUuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
