import bcrypt from 'bcryptjs';
import { db, signSession, setSessionCookie, isExpired, allow, readBody, cleanUsername } from '../_lib/session.js';
import { isRole } from '../_lib/roles.js';

// Hash palsu: waktu respon tetap mirip saat username tidak ada.
const DUMMY_HASH = bcrypt.hashSync('kazexone-dummy', 10);

export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  const body = readBody(req);
  const username = cleanUsername(body.username);
  const password = typeof body.password === 'string' ? body.password : '';
  const portal = body.portal === 'admin' ? 'admin' : 'member';

  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });

  const { data: user, error } = await db().from('users')
    .select('username, password_hash, role, display_name, expired_at').eq('username', username).maybeSingle();
  if (error) return res.status(500).json({ error: 'Could not read the database.' });

  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok || !isRole(user.role)) return res.status(401).json({ error: 'Wrong username or password.' });

  if (isExpired(user)) {
    return res.status(403).json({ code: 'EXPIRED', error: 'Your access has expired. Contact the staff to extend it.' });
  }
  if (portal === 'admin' && user.role !== 'developer') {
    return res.status(403).json({ code: 'NOT_DEV', error: 'This is not a Developer account. Use the "Public" tab.' });
  }

  const token = await signSession({ username: user.username, role: user.role });
  setSessionCookie(res, token);
  return res.status(200).json({
    ok: true, username: user.username, role: user.role,
    display_name: user.display_name || user.username, expired_at: user.expired_at || null
  });
}
