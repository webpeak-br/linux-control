// Diagnóstico de um servidor a partir das métricas e do inventário.
// evaluate() -> { status: ok|warn|crit|offline|pending, label, issues: [{level, area, text, code, see?}] }
// code identifica o problema: ações do agente que declaram esse código em "fixes" viram o botão Resolver.
// see é a aba do servidor onde o problema aparece em detalhe.
// Os limites ficam aqui; a interface recebe os níveis prontos e só pinta.
'use strict';

const LIMITS = {
  disk: { warn: 80, crit: 90 },
  inode: { crit: 90 },
  mem: { warn: 85, crit: 95 },
  swap: { warn: 80 },
  cpu: { warn: 90 },
  loadPerCore: { warn: 1.2, crit: 2 },
};
const CERT_WARN_DAYS = 14;
const LABELS = { ok: 'Saudável', warn: 'Atenção', crit: 'Crítico', offline: 'Offline', pending: 'Aguardando' };

const certLevel = c => (c.days_left < 0 ? 'crit' : c.days_left < CERT_WARN_DAYS ? 'warn' : 'ok');
// Em SSH só "yes" é problema; qualquer outro valor (no, prohibit-password…) é aceitável.
const sshLevel = (key, value) => (value !== 'yes' ? 'ok' : key === 'permitrootlogin' ? 'warn' : 'info');

function metricLevel(kind, value) {
  const l = LIMITS[kind];
  if (!l || value == null) return 'ok';
  if (l.crit != null && value >= l.crit) return 'crit';
  if (l.warn != null && value >= l.warn) return 'warn';
  return 'ok';
}

function evaluate(srv, now = Date.now() / 1000) {
  const issues = [];
  const add = (level, area, text, code, see) => issues.push({ level, area, text, code, ...(see && { see }) });

  if (!srv.last_seen) return { status: 'pending', label: LABELS.pending, issues: [{ level: 'info', area: 'agente', text: 'Aguardando o primeiro contato do agente.', code: 'pending' }] };

  const interval = srv.interval || 30;
  const age = now - srv.last_seen;
  const offline = age > Math.max(90, interval * 3);
  if (offline) add('crit', 'agente', `Sem contato há ${fmtAge(age)}.`, 'offline');

  const m = srv.metrics || {};
  const inv = srv.inventory || {};
  const sys = inv.system || {};

  const addLevel = (kind, value, area, text, code) => { const lv = metricLevel(kind, value); if (lv !== 'ok') add(lv, area, text, code); };
  for (const d of m.disks || []) {
    addLevel('disk', d.pct, 'disco', `Disco ${d.mount} com ${d.pct}% de uso.`, 'disk_full');
    addLevel('inode', d.inode_pct, 'disco', `Inodes de ${d.mount} em ${d.inode_pct}% (muitos arquivos pequenos).`, 'inode_full');
  }
  if (m.mem) {
    addLevel('mem', m.mem.pct, 'memória', `Memória em ${m.mem.pct}%.`, 'mem_high');
    addLevel('swap', m.mem.swap_pct, 'memória', `Swap em ${m.mem.swap_pct}% (servidor pode estar lento).`, 'swap_high');
  }
  if (m.load && m.ncpu) addLevel('loadPerCore', m.load[1] / m.ncpu, 'cpu', `Carga média (5 min) ${m.load[1]} para ${m.ncpu} núcleos.`, 'load_high');
  addLevel('cpu', m.cpu, 'cpu', `CPU em ${m.cpu}% agora.`, 'cpu_high');
  if (m.procs && m.procs.zombies > 5) add('info', 'cpu', `${m.procs.zombies} processos zumbis.`, 'zombies', 'processes');

  const units = (inv.services && inv.services.units) || [];
  const failed = units.filter(u => u.active === 'failed');
  if (failed.length) add('warn', 'serviços', `${failed.length} serviço(s) com falha: ${failed.slice(0, 5).map(u => u.name.replace(/\.service$/, '')).join(', ')}${failed.length > 5 ? '…' : ''}.`, 'services_failed', 'services');

  const sec = inv.security || {};
  if (sec.reboot_required) add('warn', 'sistema', 'Reinício pendente para concluir atualizações.', 'reboot_required');
  if (sys.ntp_synced === false) add('warn', 'sistema', 'Relógio não sincronizado (NTP).', 'ntp_off');
  if (sys.is_root === false) add('info', 'agente', 'Agente rodando sem root: firewall, SSH e algumas ações ficam limitados.', 'agent_not_root', 'settings');

  const pk = srv.packages;
  if (pk && pk.updates) {
    const secu = pk.updates.filter(u => u.security).length;
    if (secu) add('warn', 'segurança', `${secu} atualização(ões) de segurança pendente(s).`, 'updates_security', 'software');
    else if (pk.updates.length) add('info', 'segurança', `${pk.updates.length} atualização(ões) disponível(is).`, 'updates_available', 'software');
  }
  if (sys.is_root !== false) {
    if (sec.firewall && !sec.firewall.active) add('warn', 'segurança', 'Nenhum firewall ativo detectado.', 'firewall_off', 'security');
    const ssh = sec.ssh || {};
    if (sshLevel('permitrootlogin', ssh.permitrootlogin) !== 'ok') add('warn', 'segurança', 'SSH permite login direto como root com senha.', 'ssh_root_password', 'security');
    if (sshLevel('passwordauthentication', ssh.passwordauthentication) !== 'ok') add('info', 'segurança', 'SSH aceita login por senha (prefira chaves).', 'ssh_password_auth', 'security');
  }
  if (sec.failed_logins_24h >= 50) add(sec.failed_logins_24h >= 1000 ? 'warn' : 'info', 'segurança', `${sec.failed_logins_24h} tentativas de login SSH falhas em 24h.`, 'ssh_bruteforce', 'security');
  if (sec.auto_updates === false) add('info', 'segurança', 'Atualizações automáticas de segurança desativadas.', 'auto_updates_off');

  for (const c of inv.certificates || []) {
    const lv = certLevel(c);
    if (lv !== 'ok') add(lv, 'certificados', c.days_left < 0 ? `Certificado ${c.name} expirou.` : `Certificado ${c.name} expira em ${c.days_left} dia(s).`, 'cert_expiring', 'security');
  }
  const dk = inv.docker;
  if (dk && dk.containers) {
    const bad = dk.containers.filter(c => c.docker_state === 'restarting' || (c.docker_state === 'exited' && !/Exited \(0\)/.test(c.status || '')));
    if (bad.length) add('info', 'docker', `${bad.length} container(s) parado(s) com erro: ${bad.slice(0, 4).map(c => c.name).join(', ')}.`, 'docker_failed', 'docker');
  }

  const order = { crit: 0, warn: 1, info: 2 };
  issues.sort((a, b) => order[a.level] - order[b.level]);
  let status = 'ok';
  if (offline) status = 'offline';
  else if (issues.some(i => i.level === 'crit')) status = 'crit';
  else if (issues.some(i => i.level === 'warn')) status = 'warn';
  return { status, label: LABELS[status], issues };
}

function fmtAge(s) {
  if (s < 120) return `${Math.round(s)} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} dias`;
}

module.exports = { evaluate, metricLevel, certLevel, sshLevel, LABELS };
