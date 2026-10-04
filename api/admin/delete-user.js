import { db, requireManager, allow, readBody, cleanUsername } from '../_lib/session.js';
import { canTouch } from '../_lib/roles.js';

export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  const me = await requireManager(req, res);
  if (!me) return;

  const username = cleanUsername(readBody(req).username);
  if (!username) return res.status(400).json({ error: 'Username is required.' });
  if (username === me.username) return res.status(400).json({ error: 'You cannot delete your own account.' });

  const { data: target } = await db().from('users').select('username, role').eq('username', username).maybeSingle();
  if (!target) return res.status(404).json({ error: 'User not found. Check the username spelling.' });
  if (!canTouch(me.role, target.role)) return res.status(403).json({ error: 'Your role cannot delete this user.' });

  if (target.role === 'developer') {
    const { count } = await db().from('users').select('username', { count: 'exact', head: true }).eq('role', 'developer');
    if ((count || 0) <= 1) return res.status(400).json({ error: 'You cannot delete the last Developer account.' });
  }

  const { error } = await db().from('users').delete().eq('username', username);
  if (error) return res.status(500).json({ error: 'Failed to delete the user.' });
  return res.status(200).json({ ok: true, username });
}
