"""Testes de comportamento do agente. Rodar: python3 -m unittest discover -s test/agent"""
import importlib.util
import os
import re
import tempfile
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
spec = importlib.util.spec_from_file_location("agent", os.path.join(ROOT, "agent", "linux-control-agent.py"))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class Catalogo(unittest.TestCase):
    def test_toda_acao_tem_execucao_e_nivel_valido(self):
        for a in agent.ACTIONS:
            self.assertIn(a["level"], ("read", "change", "danger", "admin"), a["id"])
            self.assertTrue("run" in a or "sh" in a, a["id"])

    def test_acao_com_alvo_declara_um_campo_que_existe_no_formulario(self):
        for a in agent.ACTIONS:
            if "target" in a:
                self.assertIn(a["target_field"], [f["name"] for f in a.get("fields", [])], a["id"])
                self.assertIsInstance(a["when"], list, a["id"])

    def test_acoes_de_usuario_nunca_valem_para_contas_de_sistema(self):
        for a in agent.ACTIONS:
            if a.get("target") == "user":
                self.assertIn("person", a["when"], a["id"])

    def test_modo_padrao_nao_libera_acoes_de_admin(self):
        ids = {a["id"] for a in agent.allowed_actions("all")}
        self.assertIn("system.reboot", ids)
        self.assertNotIn("users.create", ids)
        self.assertNotIn("cron.add", ids)
        self.assertIn("users.create", {a["id"] for a in agent.allowed_actions("admin")})

    def test_somente_leitura_so_libera_leitura(self):
        self.assertTrue(all(a["level"] == "read" for a in agent.allowed_actions("readonly")))
        self.assertEqual(agent.allowed_actions("none"), [])

    def test_catalogo_publicado_nao_expoe_comandos(self):
        for a in agent.action_catalog("admin"):
            self.assertNotIn("sh", a)
            self.assertNotIn("run", a)

    def test_padroes_dos_campos_compilam(self):
        for a in agent.ACTIONS:
            for f in a.get("fields", []):
                if f.get("pattern"):
                    re.compile(f["pattern"])


class Validacao(unittest.TestCase):
    def action(self, aid):
        return agent.ACTIONS_BY_ID[aid]

    def test_campos_nao_declarados_sao_descartados(self):
        p, err = agent.validate_params(self.action("service.restart"), {"name": "nginx", "extra": "; rm -rf /"})
        self.assertIsNone(err)
        self.assertEqual(p, {"name": "nginx"})

    def test_nome_de_servico_comecando_com_hifen_e_recusado(self):
        _, err = agent.validate_params(self.action("service.status"), {"name": "-Hroot@evil"})
        self.assertIsNotNone(err)

    def test_servico_sempre_vira_unidade_service(self):
        self.assertEqual(agent.unit_name({"name": "reboot.target"}), "reboot.target.service")
        self.assertEqual(agent.unit_name({"name": "nginx.service"}), "nginx.service")

    def test_select_so_aceita_opcoes_declaradas(self):
        _, err = agent.validate_params(self.action("apps.install"), {"app": "metasploit"})
        self.assertIsNotNone(err)

    def test_booleano_so_e_verdadeiro_com_true(self):
        p, _ = agent.validate_params(self.action("users.create"), {"name": "ana", "shell": "/bin/bash", "sudo": "yes"})
        self.assertFalse(p["sudo"])

    def test_chave_ssh_com_quebra_de_linha_e_recusada(self):
        key = "ssh-ed25519 " + "A" * 68 + "\nssh-rsa " + "B" * 68
        _, err = agent.validate_params(self.action("users.add_key"), {"name": "ana", "ssh_key": key})
        self.assertIsNotNone(err)

    def test_quebra_de_linha_no_fim_nao_passa_pelo_cifrao(self):
        _, err = agent.validate_params(self.action("cron.remove"), {"id": "abcdef12\n00"})
        self.assertIsNotNone(err)
        _, err = agent.validate_params(self.action("cron.add"), {"schedule": "0 3 * *\n* *", "user": "root", "command": "true"})
        self.assertIsNotNone(err)

    def test_cron_aceita_expressoes_comuns_e_recusa_lixo(self):
        a = self.action("cron.add")
        for ok in ("*/5 * * * *", "0 3 * * 1-5", "@daily", "30 2 1 * *"):
            self.assertIsNone(agent.validate_params(a, {"schedule": ok, "user": "root", "command": "true"})[1], ok)
        for bad in ("* * *", "rm -rf / #", "@sometimes"):
            self.assertIsNotNone(agent.validate_params(a, {"schedule": bad, "user": "root", "command": "true"})[1], bad)

    def test_acao_fora_do_modo_nao_executa(self):
        rc, out = agent.execute_action({"action": "users.create", "params": {"name": "x"}}, "all", {})
        self.assertEqual(rc, 126)


class Cron(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.file = os.path.join(self.dir, "linux-control")
        self.patch = mock.patch.object(agent, "CRON_FILE", self.file)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_cria_e_remove_so_pelo_id(self):
        rc, out = agent.run_cron_add({"schedule": "0 3 * * *", "user": "root", "command": "date +%F", "description": "teste"}, {})
        self.assertEqual(rc, 0, out)
        cid = re.search(r"id ([0-9a-f]{8})", out).group(1)
        with open(self.file) as f:
            content = f.read()
        self.assertIn("date +\\%F", content)
        self.assertIn("# lctl:%s" % cid, content)
        self.assertEqual(agent.run_cron_remove({"id": "00000000"}, {})[0], 1)
        self.assertEqual(agent.run_cron_remove({"id": cid}, {})[0], 0)
        with open(self.file) as f:
            self.assertNotIn(cid, f.read())


class ChaveSSH(unittest.TestCase):
    def test_recusa_pasta_ssh_que_e_link_simbolico(self):
        home = tempfile.mkdtemp()
        alvo = tempfile.mkdtemp()
        os.symlink(alvo, os.path.join(home, ".ssh"))
        pw = mock.Mock(pw_dir=home, pw_uid=os.getuid(), pw_gid=os.getgid())
        out = agent.install_ssh_key(pw, "ssh-ed25519 " + "A" * 68)
        self.assertIn("Recusado", out)
        self.assertEqual(os.listdir(alvo), [])

    def test_recusa_authorized_keys_que_e_link_simbolico(self):
        home = tempfile.mkdtemp()
        os.mkdir(os.path.join(home, ".ssh"))
        alvo = os.path.join(tempfile.mkdtemp(), "shadow")
        open(alvo, "w").close()
        os.symlink(alvo, os.path.join(home, ".ssh", "authorized_keys"))
        pw = mock.Mock(pw_dir=home, pw_uid=os.getuid(), pw_gid=os.getgid())
        with self.assertRaises(OSError):
            agent.install_ssh_key(pw, "ssh-ed25519 " + "A" * 68)
        self.assertEqual(os.path.getsize(alvo), 0)

    def test_nao_duplica_chave_ja_autorizada(self):
        home = tempfile.mkdtemp()
        pw = mock.Mock(pw_dir=home, pw_uid=os.getuid(), pw_gid=os.getgid())
        key = "ssh-ed25519 " + "B" * 68 + " ana@notebook"
        self.assertEqual(agent.install_ssh_key(pw, key), "Chave SSH autorizada.")
        self.assertEqual(agent.install_ssh_key(pw, key), "Chave já estava autorizada.")


class Segredos(unittest.TestCase):
    def test_mascara_senhas_e_tokens(self):
        for raw, leaked in (("mysql --password=S3cr3t", "S3cr3t"), ("app --token abc123", "abc123"),
                            ("PGPASSWORD=foo psql", "foo"), ("curl https://u:pw@h/x", "pw@"), ("redis-server --requirepass x1", "x1")):
            self.assertNotIn(leaked, agent.mask_secrets(raw), raw)

    def test_nao_mascara_o_que_nao_e_segredo(self):
        self.assertEqual(agent.mask_secrets("python app.py --port 80"), "python app.py --port 80")


if __name__ == "__main__":
    unittest.main()


class CorrecoesDoDiagnostico(unittest.TestCase):
    ACCOUNTS = [{"name": "root", "uid": 0, "sudo": True, "locked": False, "ssh_keys": 0},
                {"name": "ana", "uid": 1000, "sudo": False, "locked": False, "ssh_keys": 0}]

    def test_nao_desliga_senha_se_nenhum_admin_tem_chave(self):
        with mock.patch.object(agent, "users", return_value={"accounts": self.ACCOUNTS}), \
             mock.patch.object(agent, "sshd_effective", return_value={"permitrootlogin": "yes"}), \
             mock.patch.object(agent, "sshd_apply") as apply:
            rc, out = agent.run_ssh_password_off({}, {})
        self.assertEqual(rc, 1)
        apply.assert_not_called()

    def test_root_com_login_proibido_nao_conta_como_quem_entra_por_chave(self):
        accounts = [dict(self.ACCOUNTS[0], ssh_keys=1)]
        with mock.patch.object(agent, "users", return_value={"accounts": accounts}), \
             mock.patch.object(agent, "sshd_effective", return_value={"permitrootlogin": "no"}):
            self.assertEqual(agent.admins_with_keys()[0], [])

    def test_nao_bloqueia_senha_do_root_sem_chave_nem_outro_admin(self):
        with mock.patch.object(agent, "users", return_value={"accounts": self.ACCOUNTS}), \
             mock.patch.object(agent, "sshd_effective", return_value={}), \
             mock.patch.object(agent, "sshd_apply") as apply:
            rc, _ = agent.run_ssh_root_password({}, {})
        self.assertEqual(rc, 1)
        apply.assert_not_called()

    def test_root_com_chave_pode_ter_a_senha_bloqueada(self):
        accounts = [dict(self.ACCOUNTS[0], ssh_keys=1)]
        with mock.patch.object(agent, "users", return_value={"accounts": accounts}), \
             mock.patch.object(agent, "sshd_effective", return_value={}), \
             mock.patch.object(agent, "sshd_apply", return_value=(0, "ok")) as apply:
            rc, _ = agent.run_ssh_root_password({}, {})
        self.assertEqual(rc, 0)
        apply.assert_called_once_with("PermitRootLogin", "prohibit-password")

    def test_firewall_novo_mantem_ssh_e_portas_publicas_mas_nao_loopback(self):
        listening = [{"proto": "tcp", "addr": "0.0.0.0", "port": 443}, {"proto": "tcp", "addr": "127.0.0.1", "port": 7420},
                     {"proto": "udp", "addr": "[::]", "port": 51820}, {"proto": "tcp", "addr": "[::1]", "port": 5432},
                     {"proto": "tcp", "addr": "[::ffff:127.0.0.1]", "port": 6379}]
        with mock.patch.object(agent, "ports", return_value=listening), mock.patch.object(agent, "ssh_ports", return_value={2222}):
            self.assertEqual(agent.public_listeners(), {(443, "tcp"), (51820, "udp"), (2222, "tcp")})

    def test_toda_acao_que_altera_pede_recoleta_do_inventario(self):
        state = {}
        def during(*a, **k):
            self.assertFalse(state.get("force_inventory"))  # não recoleta enquanto a ação roda
            return 0, ""
        with mock.patch.object(agent, "run", side_effect=during), mock.patch.object(agent, "log"):
            agent.run_command({"action": "cleanup.tmp", "params": {}}, "all", state)
        self.assertTrue(state.get("force_inventory"))
        state2 = {}
        with mock.patch.object(agent, "run", return_value=(0, "")), mock.patch.object(agent, "log"):
            agent.run_command({"action": "health.overview", "params": {}}, "all", state2)
        self.assertFalse(state2.get("force_inventory"))

    def test_correcoes_publicam_os_codigos_que_resolvem(self):
        cat = {a["id"]: a for a in agent.action_catalog("all")}
        self.assertIn("ssh_password_auth", cat["fix.ssh_password_off"]["fixes"])
        self.assertIn("updates_security", cat["security.apply_security"]["fixes"])

    def test_nao_afrouxa_root_que_ja_esta_restrito(self):
        with mock.patch.object(agent, "sshd_effective", return_value={"permitrootlogin": "no"}), \
             mock.patch.object(agent, "sshd_apply") as apply:
            rc, _ = agent.run_ssh_root_password({}, {})
        self.assertEqual(rc, 0)
        apply.assert_not_called()

    def test_nao_desliga_senha_com_login_por_chave_desligado(self):
        accounts = [dict(self.ACCOUNTS[0], ssh_keys=1)]
        with mock.patch.object(agent, "users", return_value={"accounts": accounts}), \
             mock.patch.object(agent, "sshd_effective", return_value={"pubkeyauthentication": "no"}), \
             mock.patch.object(agent, "sshd_apply") as apply:
            rc, _ = agent.run_ssh_password_off({}, {})
        self.assertEqual(rc, 1)
        apply.assert_not_called()

    def test_admin_fora_do_allowusers_nao_conta(self):
        self.assertFalse(agent.ssh_user_allowed({"allowusers": "deploy"}, "root"))
        self.assertTrue(agent.ssh_user_allowed({"allowusers": "root@10.0.0.*"}, "root"))

    def test_le_sshd_t_com_chaves_maiusculas_do_openssh_10(self):
        out = "Port 2222\nPermitRootLogin yes\nPasswordAuthentication yes\nAllowUsers ana\nAllowUsers root\n"
        with mock.patch.object(agent, "which", return_value="/usr/sbin/sshd"), mock.patch.object(agent, "run", return_value=(0, out)):
            eff = agent.sshd_effective()
            self.assertEqual(agent.ssh_ports(), {2222})
        self.assertEqual(eff["permitrootlogin"], "yes")
        self.assertEqual(eff["allowusers"], "ana root")


class Datacenter(unittest.TestCase):
    def setUp(self):
        agent._cloud_cache.clear()

    def test_vultr_pela_regiao_dos_metadados(self):
        dmi = {"/sys/class/dmi/id/sys_vendor": "Vultr"}
        meta = '{"region": {"regioncode": "SAO", "countrycode": "BR"}}'
        with mock.patch.object(agent, "read", side_effect=lambda p, d="": dmi.get(p, "")), \
             mock.patch.object(agent, "meta_get", return_value=meta):
            self.assertEqual(agent.cloud_info(), {"provider": "Vultr", "region": "SAO", "city": "São Paulo", "country": "BR"})

    def test_maquina_sem_provedor_conhecido_nao_consulta_a_rede(self):
        with mock.patch.object(agent, "read", return_value="QEMU"), mock.patch.object(agent, "meta_get") as mg:
            self.assertIsNone(agent.cloud_info())
        mg.assert_not_called()

    def test_metadados_fora_do_ar_mantem_o_provedor(self):
        with mock.patch.object(agent, "read", side_effect=lambda p, d="": "DigitalOcean" if p.endswith("sys_vendor") else ""), \
             mock.patch.object(agent, "meta_get", side_effect=OSError("timeout")):
            self.assertEqual(agent.cloud_info(), {"provider": "DigitalOcean"})


class SaudeDosDiscos(unittest.TestCase):
    SATA = {"model_name": "WDC WD40", "user_capacity": {"bytes": 4000787030016}, "rotation_rate": 5400, "device": {"protocol": "ATA"},
            "smart_status": {"passed": True}, "temperature": {"current": 38}, "power_on_time": {"hours": 30000},
            "ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 8}}, {"id": 197, "raw": {"value": 3}}, {"id": 9, "raw": {"value": 1}}]},
            "ata_smart_self_test_log": {"standard": {"table": [{"type": {"string": "Extended offline"}, "status": {"string": "Completed: read failure", "passed": False}, "lifetime_hours": 29990}]}}}

    def test_le_setores_e_ultimo_teste_do_smart(self):
        with mock.patch.object(agent, "run", return_value=(4, agent.json.dumps(self.SATA))):
            d = agent.smart_device("/dev/sda", "sat")
        self.assertEqual((d["reallocated"], d["pending"], d["rotational"]), (8, 3, True))
        self.assertFalse(d["last_test"]["passed"])

    def test_nvme_traz_erros_de_midia_e_desgaste(self):
        nv = {"model_name": "Samsung 980", "device": {"protocol": "NVMe"}, "smart_status": {"passed": True},
              "nvme_smart_health_information_log": {"media_errors": 2, "critical_warning": 0, "percentage_used": 91, "available_spare": 100}}
        with mock.patch.object(agent, "run", return_value=(0, agent.json.dumps(nv))):
            d = agent.smart_device("/dev/nvme0", "nvme")
        self.assertEqual((d["media_errors"], d["wear_pct"]), (2, 91))

    def test_erros_do_kernel_ignoram_loop_e_cdrom(self):
        log = "\n".join(["2026-11-23 kernel: blk_update_request: I/O error, dev sda, sector 1234 op 0x0:(READ)",
                         "2026-11-23 kernel: Buffer I/O error on dev loop3, logical block 0",
                         "2026-11-23 kernel: sr0: I/O error, dev sr0",
                         "2026-11-23 kernel: ata1.00: failed command: READ FPDMA QUEUED",
                         "2026-11-23 kernel: EXT4-fs error (device sda1): ext4_find_entry",
                         "2026-11-23 kernel: eth0: link up"])
        with mock.patch.object(agent, "which", return_value="/bin/journalctl"), mock.patch.object(agent, "run", return_value=(0, log)):
            n, lines = agent.kernel_io_errors(24)
        self.assertEqual(n, 3)

    def test_chave_so_para_root_ou_pessoa(self):
        sysacct = agent.pwd.struct_passwd(("www-data", "x", 33, 33, "", "/var/www", "/usr/sbin/nologin"))
        with mock.patch.object(agent, "existing_user", return_value=sysacct), mock.patch.object(agent, "install_ssh_key") as inst:
            rc, _ = agent.run_authorize_key({"user": "www-data", "ssh_key": "x"}, {})
        self.assertEqual(rc, 1)
        inst.assert_not_called()


class CatalogoDinamico(unittest.TestCase):
    def test_instalar_monitor_some_quando_ja_instalado(self):
        with mock.patch.object(agent, "which", return_value="/usr/sbin/smartctl"):
            self.assertNotIn("fix.smartmontools", {a["id"] for a in agent.action_catalog("all")})
        with mock.patch.object(agent, "which", return_value=None):
            self.assertIn("fix.smartmontools", {a["id"] for a in agent.action_catalog("all")})


class Fail2ban(unittest.TestCase):
    def test_le_contadores_do_jail_sshd(self):
        out = "Status for the jail: sshd\n|  |- Currently failed:\t4\n|  |- Total failed:\t120\n   |- Currently banned:\t3\n   |- Total banned:\t17\n"
        with mock.patch.object(agent, "run", return_value=(0, out)):
            self.assertEqual(agent.fail2ban_sshd(), {"active": True, "banned_now": 3, "banned_total": 17, "failed_total": 120})

    def test_jail_desligado_devolve_none(self):
        with mock.patch.object(agent, "run", return_value=(255, "Sorry but the jail 'sshd' does not exist")):
            self.assertIsNone(agent.fail2ban_sshd())


class AcoesDeEstado(unittest.TestCase):
    def test_repetiveis_nao_tem_estado_e_de_estado_informam_se_ja_aplicadas(self):
        with mock.patch.object(agent, "firewall_status", return_value={"active": True}), \
             mock.patch.object(agent, "sshd_effective", return_value={"permitrootlogin": "yes", "passwordauthentication": "yes"}), \
             mock.patch.object(agent, "which", return_value=None), mock.patch.object(agent, "run", return_value=(0, "no")), \
             mock.patch.object(agent, "auto_updates_enabled", return_value=True):
            cat = {a["id"]: a for a in agent.action_catalog("all")}
        self.assertNotIn("done", cat["cleanup.tmp"])
        self.assertNotIn("done", cat["security.apply_all"])
        self.assertTrue(cat["fix.firewall"]["done"])
        self.assertFalse(cat["fix.ssh_root_password"]["done"])
        self.assertFalse(cat["fix.fail2ban"]["done"])
        self.assertTrue(cat["fix.auto_updates"]["done"])
        self.assertFalse(cat["fix.ntp"]["done"])

    def test_falha_ao_conferir_estado_nao_derruba_o_catalogo(self):
        a = {"id": "x.y", "done": lambda: 1 / 0}
        self.assertEqual(agent.action_state(a), {"done": False, "done_label": "já aplicado"})


class Fail2banInstalacao(unittest.TestCase):
    def test_jail_que_nao_sobe_vira_falha_com_explicacao(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(agent, "F2B_JAIL", os.path.join(d, "zz.local")), \
             mock.patch.object(agent.os, "makedirs"), mock.patch.object(agent.os.path, "exists", return_value=False), \
             mock.patch.object(agent, "which", return_value="/usr/bin/fail2ban-client"), \
             mock.patch.object(agent, "ssh_ports", return_value={22}), mock.patch.object(agent.time, "sleep"), \
             mock.patch.object(agent, "fail2ban_sshd", return_value=None), \
             mock.patch.object(agent, "run", return_value=(0, "Jail list:\tsippro-anon")):
            rc, out = agent.run_fail2ban({}, {})
            self.assertIn("enabled = true", open(os.path.join(d, "zz.local")).read())
        self.assertEqual(rc, 1)
        self.assertIn("sippro-anon", out)

    def test_jail_que_sobe_informa_os_contadores(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(agent, "F2B_JAIL", os.path.join(d, "zz.local")), \
             mock.patch.object(agent.os, "makedirs"), mock.patch.object(agent.os.path, "exists", return_value=True), \
             mock.patch.object(agent.os, "remove"), mock.patch.object(agent, "which", return_value="/usr/bin/fail2ban-client"), \
             mock.patch.object(agent, "ssh_ports", return_value={22}), mock.patch.object(agent.time, "sleep"), \
             mock.patch.object(agent, "fail2ban_sshd", return_value={"active": True, "banned_now": 2, "banned_total": 2, "failed_total": 9}), \
             mock.patch.object(agent, "run", return_value=(0, "")):
            rc, out = agent.run_fail2ban({}, {})
        self.assertEqual(rc, 0)
        self.assertIn("2 IP(s) bloqueado(s)", out)
