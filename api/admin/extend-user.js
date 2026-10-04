import { db, requireManager, allow, readBody, cleanUsername } from '../_lib/session.js';
import { canTouch } from '../_lib/roles.js';

export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  const me = await requireManager(req, res);
  if (!me) return;

  const body = readBody(req);
  const username = cleanUsername(body.username);
  const addDays = Math.floor(Number(body.add_days));
  if (!username) return res.status(400).json({ error: 'Username is required.' });
  if (!Number.isFinite(addDays) || addDays < 1 || addDays > 3650) return res.status(400).json({ error: 'Days must be between 1 and 3650.' });

  const { data: target } = await db().from('users').select('username, role, expired_at').eq('username', username).maybeSingle();
  if (!target) return res.status(404).json({ error: 'User not found. Check the username spelling.' });
  if (!canTouch(me.role, target.role)) return res.status(403).json({ error: 'Your role cannot change this user.' });

  const base = Math.max(target.expired_at ? new Date(target.expired_at).getTime() : 0, Date.now());
  const expired_at = new Date(base + addDays * 86400000).toISOString();
  const { error } = await db().from('users').update({ expired_at }).eq('username', username);
  if (error) return res.status(500).json({ error: 'Failed to extend the duration.' });
  return res.status(200).json({ ok: true, username, expired_at });
}
