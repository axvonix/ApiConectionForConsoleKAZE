// Helper bersama semua endpoint /api. Auth MANUAL: tidak ada supabase.auth.* sama sekali.
import { SignJWT, jwtVerify } from 'jose';
import { createClient } from '@supabase/supabase-js';
import { RULES, isRole } from './roles.js';

export const COOKIE_NAME = 'kazexone_session';
export const MAX_AGE = 60 * 60 * 24 * 7; // 7 hari

function secretKey() {
  const s = process.env.JWT_SECRET;
  if (!s || s.length < 32) throw new Error('JWT_SECRET is missing or shorter than 32 characters');
  return new TextEncoder().encode(s);
}

let _db = null;
export function db() {
  if (!_db) {
    _db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
    });
  }
  return _db;
}

export async function signSession({ username, role }) {
  return new SignJWT({ username, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(MAX_AGE + 's')
    .sign(secretKey());
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
function cookieAttrs(maxAge) {
  const secure = process.env.VERCEL_ENV || process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}
export function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}${cookieAttrs(MAX_AGE)}`);
}
export function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${cookieAttrs(0)}`);
}

// Akun 'developer' tidak pernah dikunci oleh expired (supaya sistem tidak bisa terkunci total).
export function isExpired(u) {
  return u.role !== 'developer' && !!u.expired_at && new Date(u.expired_at).getTime() < Date.now();
}

// Verifikasi JWT, lalu cek ulang ke tabel users: user yang dihapus / expired / diubah role-nya
// langsung kehilangan akses (tidak menunggu JWT kedaluwarsa).
export async function getSessionUser(req) {
  const token = readCookie(req, COOKIE_NAME);
  if (!token) return null;
  let payload;
  try {
    ({ payload } = await jwtVerify(token, secretKey(), { algorithms: ['HS256'] }));
  } catch { return null; }
  if (typeof payload.username !== 'string') return null;
  const { data, error } = await db().from('users')
    .select('username, role, display_name, expired_at').eq('username', payload.username).maybeSingle();
  if (error || !data || !isRole(data.role) || isExpired(data)) return null;
  return { username: data.username, role: data.role, display_name: data.display_name || data.username, expired_at: data.expired_at || null };
}

// Dipakai endpoint /api/admin/*: harus login & role boleh membuka Access Management.
export async function requireManager(req, res) {
  const user = await getSessionUser(req);
  if (!user) { res.status(401).json({ error: 'You are not signed in.' }); return null; }
  if (!RULES[user.role].manage) { res.status(403).json({ error: 'Your role is not allowed to manage users.' }); return null; }
  return user;
}

export function readBody(req) {
  const b = req.body;
  if (!b) return {};
  if (typeof b === 'string') { try { return JSON.parse(b); } catch { return {}; } }
  return b;
}

export function allow(req, res, method) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== method) {
    res.setHeader('Allow', method);
    res.status(405).json({ error: 'Method not allowed' });
    return false;
  }
  return true;
}

export const USERNAME_RE = /^[a-z0-9_.]{3,32}$/;
export const cleanUsername = v => (typeof v === 'string' ? v.trim().toLowerCase() : '');
