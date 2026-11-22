// Avalia a saúde de um servidor a partir das métricas e do inventário.
// Retorna { status: ok|warn|crit|offline|pending, issues: [{level, area, text}] }
'use strict';

function evaluate(srv, now = Date.now() / 1000) {
  const issues = [];
  const add = (level, area, text) => issues.push({ level, area, text });

  if (!srv.last_seen) return { status: 'pending', issues: [{ level: 'info', area: 'agente', text: 'Aguardando o primeiro contato do agente.' }] };

  const interval = srv.interval || 30;
  const age = now - srv.last_seen;
  const offline = age > Math.max(90, interval * 3);
  if (offline) add('crit', 'agente', `Sem contato há ${fmtAge(age)}.`);

  const m = srv.metrics || {};
  const inv = srv.inventory || {};
  const sys = inv.system || {};

  for (const d of m.disks || []) {
    if (d.pct >= 90) add('crit', 'disco', `Disco ${d.mount} com ${d.pct}% de uso.`);
    else if (d.pct >= 80) add('warn', 'disco', `Disco ${d.mount} com ${d.pct}% de uso.`);
    if (d.inode_pct >= 90) add('crit', 'disco', `Inodes de ${d.mount} em ${d.inode_pct}% (muitos arquivos pequenos).`);
  }
  if (m.mem) {
    if (m.mem.pct >= 95) add('crit', 'memória', `Memória em ${m.mem.pct}%.`);
    else if (m.mem.pct >= 85) add('warn', 'memória', `Memória em ${m.mem.pct}%.`);
    if (m.mem.swap_pct >= 80) add('warn', 'memória', `Swap em ${m.mem.swap_pct}% (servidor pode estar lento).`);
  }
  if (m.load && m.ncpu) {
    const r = m.load[1] / m.ncpu;
    if (r >= 2) add('crit', 'cpu', `Carga média (5 min) ${m.load[1]} para ${m.ncpu} núcleos.`);
    else if (r >= 1.2) add('warn', 'cpu', `Carga média (5 min) ${m.load[1]} para ${m.ncpu} núcleos.`);
  }
  if (m.cpu >= 90) add('warn', 'cpu', `CPU em ${m.cpu}% agora.`);
  if (m.procs && m.procs.zombies > 5) add('info', 'cpu', `${m.procs.zombies} processos zumbis.`);

  const units = (inv.services && inv.services.units) || [];
  const failed = units.filter(u => u.active === 'failed');
  if (failed.length) add('warn', 'serviços', `${failed.length} serviço(s) com falha: ${failed.slice(0, 5).map(u => u.name.replace(/\.service$/, '')).join(', ')}${failed.length > 5 ? '…' : ''}.`);

  const sec = inv.security || {};
  if (sec.reboot_required) add('warn', 'sistema', 'Reinício pendente para concluir atualizações.');
  if (sys.ntp_synced === false) add('warn', 'sistema', 'Relógio não sincronizado (NTP).');
  if (sys.is_root === false) add('info', 'agente', 'Agente rodando sem root: firewall, SSH e algumas ações ficam limitados.');

  const pk = srv.packages;
  if (pk && pk.updates) {
    const secu = pk.updates.filter(u => u.security).length;
    if (secu) add('warn', 'segurança', `${secu} atualização(ões) de segurança pendente(s).`);
    else if (pk.updates.length) add('info', 'segurança', `${pk.updates.length} atualização(ões) disponível(is).`);
  }
  if (sys.is_root !== false) {
    if (sec.firewall && !sec.firewall.active) add('warn', 'segurança', 'Nenhum firewall ativo detectado.');
    const ssh = sec.ssh || {};
    if (ssh.permitrootlogin === 'yes') add('warn', 'segurança', 'SSH permite login direto como root com senha.');
    if (ssh.passwordauthentication === 'yes') add('info', 'segurança', 'SSH aceita login por senha (prefira chaves).');
  }
  if (sec.failed_logins_24h >= 50) add(sec.failed_logins_24h >= 1000 ? 'warn' : 'info', 'segurança', `${sec.failed_logins_24h} tentativas de login SSH falhas em 24h.`);
  if (sec.auto_updates === false) add('info', 'segurança', 'Atualizações automáticas de segurança desativadas.');

  for (const c of inv.certificates || []) {
    if (c.days_left < 0) add('crit', 'certificados', `Certificado ${c.name} expirou.`);
    else if (c.days_left < 14) add('warn', 'certificados', `Certificado ${c.name} expira em ${c.days_left} dia(s).`);
  }
  const dk = inv.docker;
  if (dk && dk.containers) {
    const bad = dk.containers.filter(c => c.state === 'restarting' || (c.state === 'exited' && !/Exited \(0\)/.test(c.status || '')));
    if (bad.length) add('info', 'docker', `${bad.length} container(s) parado(s) com erro: ${bad.slice(0, 4).map(c => c.name).join(', ')}.`);
  }

  const order = { crit: 0, warn: 1, info: 2 };
  issues.sort((a, b) => order[a.level] - order[b.level]);
  let status = 'ok';
  if (offline) status = 'offline';
  else if (issues.some(i => i.level === 'crit')) status = 'crit';
  else if (issues.some(i => i.level === 'warn')) status = 'warn';
  return { status, issues };
}

function fmtAge(s) {
  if (s < 120) return `${Math.round(s)} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} dias`;
}

module.exports = { evaluate };
