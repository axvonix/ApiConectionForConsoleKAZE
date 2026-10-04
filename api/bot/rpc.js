import { createClient } from '@supabase/supabase-js';
import { getSessionUser, allow, readBody } from '../_lib/session.js';
import { makeTicket } from '../_lib/ticket.js';

// JALUR FALLBACK: dipakai front-end saat browser TIDAK bisa menjangkau DB Fonxz / Registry
// (mis. domain supabase.co diblokir ISP). Server Vercel yang memanggil Fonxz, lalu meneruskan hasilnya.
// Dipakai untuk penautan (tambah/hapus/restart session), kirim perintah, status, plugin, dan statistik.
//
// Keamanan:
//  - hanya fungsi di daftar putih di bawah (nilai = butuh tiket / login);
//  - tiket dibuat SERVER dari sesi cookie -- p_email/p_role/p_expires/p_signature kiriman klien dibuang;
//  - fungsi bot_* (pakai bridge secret) TIDAK PERNAH bisa dipanggil lewat sini.
// Env: FONXZ_URL, FONXZ_ANON_KEY (anon/publishable key project Fonxz -- sama dengan yang dipakai browser).
const FUNCTIONS = {
  list_bot_sessions: true,
  admin_add_bot_session: true,
  admin_delete_bot_session: true,
  admin_restart_bot_session: true,
  list_plugins: true,
  admin_add_plugin: true,
  admin_toggle_plugin: true,
  admin_delete_plugin: true,
  send_bot_command: true,
  get_command_status: true,
  get_bot_public_stats: false // angka agregat publik, tanpa login/tiket
};
const TICKET_KEYS = new Set(['p_email', 'p_role', 'p_expires', 'p_signature']);
const MAX_ARGS_BYTES = 300000;
const TIMEOUT_MS = 8000;

let _fonxz = null;
function fonxz() {
  if (!_fonxz) {
    _fonxz = createClient(process.env.FONXZ_URL, process.env.FONXZ_ANON_KEY, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
    });
  }
  return _fonxz;
}

const fail = (res, status, message, extra = {}) => res.status(status).json({ error: { message, ...extra } });

export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  const body = readBody(req);
  const fn = body.fn;

  if (typeof fn !== 'string' || !Object.prototype.hasOwnProperty.call(FUNCTIONS, fn)) {
    return fail(res, 400, 'Function is not allowed through the fallback endpoint.');
  }
  if (!process.env.FONXZ_URL || !process.env.FONXZ_ANON_KEY) {
    return fail(res, 500, 'Fallback is not configured on the server (FONXZ_URL / FONXZ_ANON_KEY).');
  }

  // Argumen dari klien: hanya object datar berkunci p_*, tanpa kunci tiket.
  const rawArgs = body.args && typeof body.args === 'object' && !Array.isArray(body.args) ? body.args : {};
  let size = 0;
  try { size = JSON.stringify(rawArgs).length; } catch { return fail(res, 400, 'Invalid arguments.'); }
  if (size > MAX_ARGS_BYTES) return fail(res, 413, 'Arguments are too large.');
  const params = {};
  for (const [k, v] of Object.entries(rawArgs)) {
    if (/^p_[a-z0-9_]+$/.test(k) && !TICKET_KEYS.has(k)) params[k] = v;
  }

  if (FUNCTIONS[fn]) {
    const user = await getSessionUser(req);
    if (!user) return fail(res, 401, 'You must sign in first.');
    try {
      const t = makeTicket(user);
      params.p_email = t.email; params.p_role = t.role; params.p_expires = t.expires_at; params.p_signature = t.signature;
    } catch (e) {
      return fail(res, 500, e.message);
    }
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fonxz().rpc(fn, params).abortSignal(ctrl.signal);
    if (r.error) {
      const unreachable = !r.status || r.status >= 500;
      if (unreachable) return fail(res, 502, 'The bot database is unreachable right now.');
      // Kesalahan "bisnis" dari fungsi SQL (mis. tidak punya akses): teruskan apa adanya.
      return fail(res, 400, r.error.message || 'Request rejected.', { code: r.error.code || null, hint: r.error.hint || null });
    }
    return res.status(200).json({ data: r.data });
  } catch (e) {
    return fail(res, 502, 'The bot database is unreachable right now.');
  } finally {
    clearTimeout(timer);
  }
}
