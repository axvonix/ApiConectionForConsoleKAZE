import { clearSessionCookie, allow } from '../_lib/session.js';

export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  clearSessionCookie(res);
  return res.status(200).json({ ok: true });
}
