export type ServerType = 'node' | 'server';

const BASE = '';

export async function fetchServerType(): Promise<ServerType> {
  const res = await fetch(`${BASE}/type`, { headers: { Accept: 'text/plain' } });
  if (!res.ok) throw new Error(`/type: ${res.status}`);
  const text = await res.text();
  const t = text.trim().toLowerCase();
  if (t === 'node' || t === 'server') return t as ServerType;
  return 'node';
}

export async function fetchInfo<T = unknown>(): Promise<T> {
  const res = await fetch(`${BASE}/info`);
  if (!res.ok) throw new Error(`/info: ${res.status}`);
  return res.json();
}
