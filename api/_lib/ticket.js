import { createHmac } from 'node:crypto';

// Tiket akses untuk DB Fonxz. Identitas = username saja (tanpa domain apa pun).
//   payload = <username>|<role>|<epoch expires_at>    signature = HMAC-SHA256(payload, BRIDGE_SECRET)
// Dipakai /api/bot/ticket (browser memanggil Fonxz langsung) dan /api/bot/rpc (jalur fallback).
export function makeTicket(user, ttlSec = 120) {
  const secret = process.env.BRIDGE_SECRET;
  if (!secret) throw new Error('BRIDGE_SECRET is not set in the server environment.');
  const expiresSec = Math.floor(Date.now() / 1000) + ttlSec;
  // Postgres >= 14 (Supabase) menulis extract(epoch ...)::text dengan 6 desimal.
  const payload = `${user.username}|${user.role}|${expiresSec}.000000`;
  return {
    email: user.username,                       // NAMA FIELD lama; isinya username
    role: user.role,
    expires_at: new Date(expiresSec * 1000).toISOString(),
    signature: createHmac('sha256', secret).update(payload).digest('hex')
  };
}
