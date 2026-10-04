import { randomBytes } from 'node:crypto';
import { db, requireManager, allow, readBody } from '../_lib/session.js';
import { RULES, KEY_ROLES } from '../_lib/roles.js';

export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  const me = await requireManager(req, res);
  if (!me) return;
  if (!RULES[me.role].issueKeys) return res.status(403).json({ error: 'Your role is not allowed to issue access keys.' });

  const forRole = readBody(req).for_role;
  if (!KEY_ROLES.includes(forRole)) return res.status(400).json({ error: 'The target role does not need an access key.' });

  const key = randomBytes(16).toString('hex');
  const { error } = await db().from('access_keys').insert({ key_code: key, for_role: forRole, issued_by: me.username });
  if (error) return res.status(500).json({ error: 'Failed to create the access key.' });
  return res.status(201).json({ ok: true, key, for_role: forRole });
}
