import bcrypt from 'bcryptjs';
import { db, requireManager, allow, readBody, cleanUsername, USERNAME_RE } from '../_lib/session.js';
import { RULES, isRole } from '../_lib/roles.js';

export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  const me = await requireManager(req, res);
  if (!me) return;
  const rule = RULES[me.role];

  const body = readBody(req);
  const display_name = typeof body.display_name === 'string' ? body.display_name.trim() : '';
  const username = cleanUsername(body.username);
  const password = typeof body.password === 'string' ? body.password : '';
  const role = body.role;
  const days = Number.isFinite(Number(body.duration_days)) ? Math.floor(Number(body.duration_days)) : 30;
  const accessKey = typeof body.access_key === 'string' ? body.access_key.trim() : '';

  if (!display_name || display_name.length > 50) return res.status(400).json({ error: 'Name is required (max 50 characters).' });
  if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'Username must be 3-32 characters: letters, numbers, dots and underscores only (no spaces).' });
  if (password.length < 6 || password.length > 72) return res.status(400).json({ error: 'Password must be 6-72 characters.' });
  if (!isRole(role)) return res.status(400).json({ error: 'Select a valid role.' });
  if (days < 1 || days > 3650) return res.status(400).json({ error: 'Duration must be between 1 and 3650 days.' });
  if (!rule.generate.includes(role)) return res.status(403).json({ error: 'Your role cannot create this role.' });
  if (rule.needsKey && !accessKey) return res.status(400).json({ error: 'Your role needs an Access Key to create users.' });

  const { data: taken } = await db().from('users').select('username').eq('username', username).maybeSingle();
  if (taken) return res.status(409).json({ error: 'Username is already taken, choose another one.' });

  // Pakai key (atomik: hanya satu request yang bisa memakai key yang sama).
  let keyUsed = null;
  if (rule.needsKey) {
    const { data: rows, error: kErr } = await db().from('access_keys')
      .update({ used_by: me.username, used_at: new Date().toISOString() })
      .eq('key_code', accessKey).eq('for_role', role).is('used_by', null).select('key_code');
    if (kErr) return res.status(500).json({ error: 'Could not verify the access key.' });
    if (!rows || !rows.length) return res.status(400).json({ error: 'Access key is invalid, already used, or not valid for the target role.' });
    keyUsed = accessKey;
  }

  const password_hash = await bcrypt.hash(password, 10);
  const expired_at = new Date(Date.now() + days * 86400000).toISOString();
  const { error } = await db().from('users').insert({
    username, password_hash, role, display_name, expired_at, created_by: me.username
  });

  if (error) {
    // Kembalikan key supaya tidak hangus kalau pembuatan user gagal.
    if (keyUsed) await db().from('access_keys').update({ used_by: null, used_at: null }).eq('key_code', keyUsed);
    if (error.code === '23505') return res.status(409).json({ error: 'Username is already taken, choose another one.' });
    return res.status(500).json({ error: 'Failed to create the user.' });
  }
  return res.status(201).json({ ok: true, username, display_name, role, expired_at });
}
