import { getSessionUser, allow } from '../_lib/session.js';
import { makeTicket } from '../_lib/ticket.js';

// Pengganti issue_access_ticket() Supabase Auth (sudah dimatikan). Untuk SEMUA role.
// Pembeda hak (Sender Global) ditentukan DB Fonxz dari role di tiket -- lihat sql/FULL_6_FONXZ_ROLES_PATCH.sql.
export default async function handler(req, res) {
  if (!allow(req, res, 'POST')) return;
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'You must sign in first.' });
  try {
    return res.status(200).json(makeTicket(user));
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
