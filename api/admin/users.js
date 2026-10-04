import { db, requireManager, allow } from '../_lib/session.js';

export default async function handler(req, res) {
  if (!allow(req, res, 'GET')) return;
  if (!(await requireManager(req, res))) return;
  // password_hash TIDAK PERNAH dikirim ke browser.
  const { data, error } = await db().from('users').select('username, display_name, role, expired_at').order('username');
  if (error) return res.status(500).json({ error: 'Could not load the user list.' });
  return res.status(200).json({ users: data });
}
