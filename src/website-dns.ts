import { isIPv4, isIPv6, isIP } from 'node:net';
import { promises as dns } from 'node:dns';
import { AppError } from './contracts.js';

function ipv4Octets(host: string): number[] | undefined {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) && !isIPv4(host)) return;
  const parts = host.split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return;
  return parts;
}

function mappedIpv4(host: string): string | undefined {
  const match = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/iu.exec(host);
  if (match) return match[1];
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/iu.exec(host);
  if (!mapped) return;
  const hi = Number.parseInt(mapped[1]!, 16);
  const lo = Number.parseInt(mapped[2]!, 16);
  return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
}

export function isPrivateOrLocalAddress(host: string): boolean {
  const mapped = mappedIpv4(host);
  if (mapped) return isPrivateOrLocalAddress(mapped);
  const octets = ipv4Octets(host);
  if (octets) {
    const [a, b] = octets;
    return a === 0 || a === 10 || a === 127 || a === 224 || a === 255 ||
      (a === 169 && b === 254) || (a === 172 && (b ?? 0) >= 16 && (b ?? 0) <= 31) ||
      (a === 192 && b === 168) || (a === 100 && (b ?? 0) >= 64 && (b ?? 0) <= 127);
  }
  if (!isIPv6(host) && !host.includes(':')) return false;
  const ip = host.toLowerCase();
  return ip === '::' || ip === '::1' || ip.startsWith('fe8') || ip.startsWith('fe9') ||
    ip.startsWith('fea') || ip.startsWith('feb') || ip.startsWith('fc') || ip.startsWith('fd');
}

export type HostLookup = (host: string) => Promise<string[]>;

export const defaultLookup: HostLookup = async host => {
  const rows = await dns.lookup(host, { all: true, verbatim: true });
  return rows.map(row => row.address);
};

export async function assertPublicHost(host: string, lookup: HostLookup = defaultLookup): Promise<string[]> {
  const addresses = await lookup(host);
  if (!addresses.length) throw new AppError('origin_not_allowed', 'Website origin is not on this credential allowlist.', 403, 3, 'permission_denied');
  for (const address of addresses) {
    if (!isIP(address) || isPrivateOrLocalAddress(address)) {
      throw new AppError('origin_not_allowed', 'Website origin is not on this credential allowlist.', 403, 3, 'permission_denied');
    }
  }
  return addresses;
}
