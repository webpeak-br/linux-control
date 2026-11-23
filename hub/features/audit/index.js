'use strict';
// Trilha de auditoria: quem fez o quê, de onde. Os eventos possíveis e seus rótulos ficam só aqui.

const migrations = [{ name: 'audit:1', sql: 'CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip TEXT, event TEXT, detail TEXT)' }];
const RETENTION_DAYS = 180;
const LIST_LIMIT = 300;

const EVENTS = {
  login: 'Login', login_falhou: 'Login falhou', configuracao_inicial: 'Configuração inicial', senha_alterada: 'Senha alterada',
  registro: 'Registro da instalação', acao: 'Ação', servidor_criado: 'Servidor criado', servidor_removido: 'Servidor removido',
  token_regenerado: 'Token regenerado', alertas_configurados: 'Alertas configurados',
  atualizacao_hub: 'Atualização do painel', atualizacao_agente: 'Atualização de agente',
  chave_ssh_cadastrada: 'Chave SSH cadastrada', chave_ssh_removida: 'Chave SSH removida',
  terminal_aberto: 'Terminal aberto', terminal_fechado: 'Terminal fechado', terminal_gravacao_baixada: 'Gravação de terminal baixada',
};

function create({ db, now }) {
  return {
    record(ip, event, detail = '') {
      if (!EVENTS[event]) throw new Error(`evento de auditoria desconhecido: ${event}`);
      db.prepare('INSERT INTO audit(ts,ip,event,detail) VALUES(?,?,?,?)').run(now(), ip, event, String(detail).slice(0, 500));
    },
    routes(router) {
      router.add('GET /api/audit', () => ({
        limit: LIST_LIMIT,
        events: db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT ?').all(LIST_LIMIT).map(e => ({ ...e, label: EVENTS[e.event] || e.event })),
      }));
    },
    jobs: [{ name: 'audit-prune', everyMs: 3600_000, run: () => db.prepare('DELETE FROM audit WHERE ts < ?').run(now() - RETENTION_DAYS * 86400) }],
  };
}

module.exports = { migrations, create };
