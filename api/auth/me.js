import { getSessionUser, clearSessionCookie, allow } from '../_lib/session.js';

// Dipakai front-end untuk memulihkan sesi saat refresh (cookie httpOnly tidak bisa dibaca JS).
export default async function handler(req, res) {
  if (!allow(req, res, 'GET')) return;
  const user = await getSessionUser(req);
  if (!user) { clearSessionCookie(res); return res.status(401).json({ error: 'You are not signed in.' }); }
  return res.status(200).json(user);
}
