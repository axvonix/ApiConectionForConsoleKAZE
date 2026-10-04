// Aturan role di SERVER (sumber kebenaran). Samakan dengan CFG.roles di assets/js/config.js.
// Role di database = key di bawah ini.
export const ROLES = ['developer','assistant_dev','moderator','ceo','owner','vip','admin','member'];

export const RULES = {
  // Dev & Asisten Dev: all in
  developer:     { manage:true,  issueKeys:true,  needsKey:false, changeRole:true,  globalSender:true,  generate:['developer','assistant_dev','moderator','ceo','owner','vip','admin','member'] },
  assistant_dev: { manage:true,  issueKeys:true,  needsKey:false, changeRole:true,  globalSender:true,  generate:['developer','assistant_dev','moderator','ceo','owner','vip','admin','member'] },
  // "Pro" pada daftar Moderator dianggap = CEO
  moderator:     { manage:true,  issueKeys:true,  needsKey:false, changeRole:true,  globalSender:true,  generate:['ceo','vip','admin','member'] },
  ceo:           { manage:true,  issueKeys:false, needsKey:true,  changeRole:false, globalSender:true,  generate:['vip','admin','member'] },
  owner:         { manage:true,  issueKeys:false, needsKey:true,  changeRole:false, globalSender:true,  generate:['admin','vip','member'] },
  vip:           { manage:true,  issueKeys:false, needsKey:true,  changeRole:false, globalSender:true,  generate:['member'] },
  admin:         { manage:false, issueKeys:false, needsKey:false, changeRole:false, globalSender:true,  generate:[] },
  member:        { manage:false, issueKeys:false, needsKey:false, changeRole:false, globalSender:false, generate:[] }
};

// Role tujuan yang boleh dibuatkan Access Key (gabungan daftar generate role yang butuh key).
export const KEY_ROLES = ['vip','admin','member'];

export const isRole = r => typeof r === 'string' && ROLES.includes(r);
// Pemanggil hanya boleh menyentuh (hapus/extend/ubah) user yang role-nya ada di daftar generate-nya.
export const canTouch = (actorRole, targetRole) => !!RULES[actorRole] && RULES[actorRole].generate.includes(targetRole);
