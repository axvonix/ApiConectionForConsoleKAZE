import { db, requireManager, allow, readBody, cleanUsername } from '../_lib/session.js';
import { RULES, isRole, canTouch } from '../_lib/roles.js';

export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  const me = await requireManager(req, res);
  if (!me) return;
  if (!RULES[me.role].changeRole) return res.status(403).json({ error: 'Your role is not allowed to change user roles.' });

  const body = readBody(req);
  const username = cleanUsername(body.username);
  const role = body.role;
  if (!username) return res.status(400).json({ error: 'Username is required.' });
  if (!isRole(role)) return res.status(400).json({ error: 'Select a valid role.' });
  if (username === me.username) return res.status(400).json({ error: 'You cannot change your own role.' });

  const { data: target } = await db().from('users').select('username, role').eq('username', username).maybeSingle();
  if (!target) return res.status(404).json({ error: 'User not found. Check the username spelling.' });
  if (!canTouch(me.role, target.role) || !canTouch(me.role, role)) {
    return res.status(403).json({ error: 'Your role cannot assign this change.' });
  }

  if (target.role === 'developer' && role !== 'developer') {
    const { count } = await db().from('users').select('username', { count: 'exact', head: true }).eq('role', 'developer');
    if ((count || 0) <= 1) return res.status(400).json({ error: 'You cannot demote the last Developer account.' });
  }

  const { error } = await db().from('users').update({ role }).eq('username', username);
  if (error) return res.status(500).json({ error: 'Failed to change the role.' });
  return res.status(200).json({ ok: true, username, role });
}
