"""
Tests des 4 stratégies d'exploitation.
 
Chaque test mock subprocess.run pour simuler la sortie réelle
des outils (bloodyAD / impacket-secretsdump) sans lab GOAD actif.
 
Lancer :
    python -m pytest tests/test_strategies.py -v
ou directement :
    python tests/test_strategies.py
"""
 
import sys
import os
import unittest
from unittest.mock import MagicMock, patch
 
# ── Stubs minimaux pour éviter d'importer le projet entier ──────────────────
 
class FakeNode:
    def __init__(self, label):
        self.label = label
 
class FakeEdge:
    def __init__(self, source_label, goal_label):
        self.source_node = FakeNode(source_label)
        self.goal_node   = FakeNode(goal_label)
 
# Injecte les stubs dans sys.modules avant tout import de stratégie
edge_mod    = MagicMock(); edge_mod.Edge = FakeEdge
entities_mod = MagicMock(); entities_mod.edge = edge_mod
sys.modules.setdefault("entities",      entities_mod)
sys.modules.setdefault("entities.edge", edge_mod)
 
# Stub du package strategies (pour les imports relatifs)
strat_pkg = MagicMock()
sys.modules.setdefault("strategies", strat_pkg)
 
# Import direct des fichiers corrigés
import importlib.util, pathlib
 
def _load(path):
    class _Base:
        def exploit(self, *a, **kw): ...
        def describe(self, *a, **kw): ...
 
    # Stub de exploit_strategy pour les imports relatifs
    strat_base = MagicMock()
    strat_base.ExploitStrategy = _Base
    sys.modules["strategies.exploit_strategy"] = strat_base
 
    # Nom de module unique par fichier
    mod_name = f"strategies.{path.stem}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod  = importlib.util.module_from_spec(spec)
    mod.__package__ = "strategies"
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod
 
BASE = pathlib.Path(__file__).parent.parent / "strategies"
 
ReadLAPSStrategy  = _load(BASE / "read_laps.py").ReadLAPSStrategy
AdminToStrategy   = _load(BASE / "admin_to.py").AdminToStrategy
HasSessionStrategy= _load(BASE / "has_session.py").HasSessionStrategy
DCSyncStrategy    = _load(BASE / "dc_sync.py").DCSyncStrategy
 
 
# ── Helpers ──────────────────────────────────────────────────────────────────
 
def _make_proc(stdout="", stderr="", returncode=0):
    """Crée un objet subprocess.CompletedProcess simulé."""
    p = MagicMock()
    p.stdout     = stdout
    p.stderr     = stderr
    p.returncode = returncode
    return p
 
CREDS = dict(
    username="joffrey",
    password="Joffrey1!",
    domain="sevenkingdoms.local",
    dc_ip="192.168.56.10",
)
 
 
# ════════════════════════════════════════════════════════════════════════════
# 1. ReadLAPSStrategy
# ════════════════════════════════════════════════════════════════════════════
 
class TestReadLAPS(unittest.TestCase):
 
    def _edge(self):
        return FakeEdge(
            source_label="JOFFREY@SEVENKINGDOMS.LOCAL",
            goal_label  ="KINGSLANDING.SEVENKINGDOMS.LOCAL",
        )
 
    # ── describe ──────────────────────────────────────────────────────────
 
    def test_describe(self):
        s = ReadLAPSStrategy()
        out = s.describe(self._edge())
        self.assertIn("ReadLAPS",      out)
        self.assertIn("JOFFREY",       out)
        self.assertIn("KINGSLANDING",  out)
        print(f"\n[ReadLAPS] describe → {out}")
 
    # ── succès FQDN ───────────────────────────────────────────────────────
 
    def test_exploit_success_fqdn(self):
        """bloodyAD retourne ms-Mcs-AdmPwd avec le mot de passe LAPS."""
        stdout = (
            "distinguishedName: CN=KINGSLANDING,OU=Domain Controllers,...\n"
            "ms-Mcs-AdmPwd: S3cr3tL4ps!\n"
        )
        s = ReadLAPSStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout=stdout)) as mock_run:
            result = s.exploit(self._edge(), **CREDS)
 
        print(f"[ReadLAPS] commande : {mock_run.call_args_list[0][0][0]}")
        print(f"[ReadLAPS] résultat : {result}")
 
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["credentials"])
        self.assertEqual(result["credentials"]["password"], "S3cr3tL4ps!")
        self.assertEqual(result["credentials"]["username"], "Administrator")
        self.assertEqual(result["credentials"]["type"],    "local_admin")
 
    # ── fallback nom court ─────────────────────────────────────────────────
 
    def test_exploit_fallback_short_name(self):
        """Si le FQDN échoue, le nom court doit être tenté."""
        empty   = _make_proc(stdout="")
        success = _make_proc(stdout="ms-Mcs-AdmPwd: FallbackPass99\n")
 
        s = ReadLAPSStrategy()
        with patch("subprocess.run", side_effect=[empty, success]) as mock_run:
            result = s.exploit(self._edge(), **CREDS)
 
        calls = [c[0][0] for c in mock_run.call_args_list]
        targets = [cmd[cmd.index("object") + 1] for cmd in calls]
        print(f"[ReadLAPS] targets testés : {targets}")
 
        self.assertIn("KINGSLANDING.SEVENKINGDOMS.LOCAL", targets)
        self.assertIn("KINGSLANDING", targets)
        self.assertTrue(result["success"])
        self.assertEqual(result["credentials"]["password"], "FallbackPass99")
 
    # ── pas de mot de passe dans la sortie ────────────────────────────────
 
    def test_exploit_no_password(self):
        stdout = "distinguishedName: CN=KINGSLANDING,...\n"
        s = ReadLAPSStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout=stdout)):
            result = s.exploit(self._edge(), **CREDS)
 
        print(f"[ReadLAPS] sans mot de passe → {result}")
        self.assertFalse(result["success"])
        self.assertIsNone(result["credentials"])
 
    # ── outil absent ───────────────────────────────────────────────────────
 
    def test_exploit_tool_missing(self):
        s = ReadLAPSStrategy()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = s.exploit(self._edge(), **CREDS)
 
        print(f"[ReadLAPS] outil absent → {result['output']}")
        self.assertFalse(result["success"])
        self.assertIn("bloodyAD", result["output"])
 
    # ── timeout ───────────────────────────────────────────────────────────
 
    def test_exploit_timeout(self):
        import subprocess
        s = ReadLAPSStrategy()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 15)):
            result = s.exploit(self._edge(), **CREDS)
 
        print(f"[ReadLAPS] timeout → {result['output']}")
        self.assertFalse(result["success"])
        self.assertEqual(result["output"], "Timeout")
 
 
# ════════════════════════════════════════════════════════════════════════════
# 2. AdminToStrategy
# ════════════════════════════════════════════════════════════════════════════
 
class TestAdminTo(unittest.TestCase):
 
    def _edge(self):
        return FakeEdge(
            source_label="JOFFREY@SEVENKINGDOMS.LOCAL",
            goal_label  ="KINGSLANDING.SEVENKINGDOMS.LOCAL",
        )
 
    HASHES_OUTPUT = (
        "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
        "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "[*] Dumping cached domain logon information\n"
    )
 
    def test_describe(self):
        out = AdminToStrategy().describe(self._edge())
        self.assertIn("AdminTo", out)
        self.assertIn("admin local", out)
        print(f"\n[AdminTo] describe → {out}")
 
    def test_exploit_success(self):
        """stdout contient des hashes NTLM (pas de -outputfile)."""
        s = AdminToStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout=self.HASHES_OUTPUT)) as mock_run:
            result = s.exploit(self._edge(), **CREDS)
 
        cmd = mock_run.call_args[0][0]
        print(f"[AdminTo] commande : {cmd}")
        # Vérifie qu'on n'utilise PAS -outputfile
        self.assertNotIn("-outputfile", cmd)
        # Vérifie -target-ip présent
        self.assertIn("-target-ip", cmd)
 
        print(f"[AdminTo] hashes trouvés : {result['credentials']['hashes']}")
        self.assertTrue(result["success"])
        self.assertEqual(result["credentials"]["type"], "ntlm_hashes")
        self.assertEqual(len(result["credentials"]["hashes"]), 2)
        self.assertIn("Administrator:500:", result["credentials"]["hashes"][0])
 
    def test_exploit_no_hashes(self):
        stdout = "[*] Something went wrong\nError: access denied\n"
        s = AdminToStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout=stdout)):
            result = s.exploit(self._edge(), **CREDS)
 
        print(f"[AdminTo] sans hashes → {result}")
        self.assertFalse(result["success"])
        self.assertIsNone(result["credentials"])
 
    def test_exploit_tool_missing(self):
        s = AdminToStrategy()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = s.exploit(self._edge(), **CREDS)
 
        self.assertFalse(result["success"])
        self.assertIn("impacket", result["output"])
 
    def test_exploit_timeout(self):
        import subprocess
        s = AdminToStrategy()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            result = s.exploit(self._edge(), **CREDS)
 
        self.assertFalse(result["success"])
        self.assertEqual(result["output"], "Timeout")
 
 
# ════════════════════════════════════════════════════════════════════════════
# 3. HasSessionStrategy
# ════════════════════════════════════════════════════════════════════════════
 
class TestHasSession(unittest.TestCase):
 
    def _edge(self):
        # Machine --HasSession--> User
        return FakeEdge(
            source_label="KINGSLANDING.SEVENKINGDOMS.LOCAL",
            goal_label  ="CERSEI@SEVENKINGDOMS.LOCAL",
        )
 
    LSASS_OUTPUT = (
        "[*] Dumping lsass secrets\n"
        "SEVENKINGDOMS\\CERSEI:1108:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::\n"
        "SEVENKINGDOMS\\JOFFREY:1109:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
    )
 
    def test_describe(self):
        out = HasSessionStrategy().describe(self._edge())
        self.assertIn("HasSession", out)
        # CERSEI est l'utilisateur (goal_node)
        self.assertIn("CERSEI", out)
        # KINGSLANDING est la machine (source_node)
        self.assertIn("KINGSLANDING", out)
        print(f"\n[HasSession] describe → {out}")
 
    def test_exploit_success_target_found(self):
        """CERSEI est trouvée dans le dump LSASS."""
        s = HasSessionStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout=self.LSASS_OUTPUT)) as mock_run:
            result = s.exploit(self._edge(), **CREDS)
 
        cmd = mock_run.call_args[0][0]
        print(f"[HasSession] commande : {cmd}")
        # Cible = machine (source_node), pas l'utilisateur
        self.assertIn("KINGSLANDING", cmd[1])
        self.assertIn("-target-ip", cmd)
 
        print(f"[HasSession] target_hash : {result['credentials']['target_hash']}")
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["credentials"]["target_hash"])
        self.assertIn("CERSEI", result["credentials"]["target_hash"])
        self.assertEqual(len(result["credentials"]["all_hashes"]), 2)
 
    def test_exploit_success_target_not_in_dump(self):
        """Dump réussi mais utilisateur cible absent des sessions actives."""
        stdout = (
            "[*] Dumping lsass\n"
            "SEVENKINGDOMS\\TYWIN:1110:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::\n"
        )
        s = HasSessionStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout=stdout)):
            result = s.exploit(self._edge(), **CREDS)
 
        print(f"[HasSession] cible absente → target_hash={result['credentials']['target_hash']}")
        # success=True car des hashes existent, mais target_hash=None
        self.assertTrue(result["success"])
        self.assertIsNone(result["credentials"]["target_hash"])
        self.assertEqual(len(result["credentials"]["all_hashes"]), 1)
 
    def test_exploit_empty_dump(self):
        s = HasSessionStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout="[*] No secrets found\n")):
            result = s.exploit(self._edge(), **CREDS)
 
        self.assertFalse(result["success"])
        self.assertIsNone(result["credentials"])
 
    def test_exploit_timeout(self):
        import subprocess
        s = HasSessionStrategy()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            result = s.exploit(self._edge(), **CREDS)
 
        self.assertFalse(result["success"])
 
 
# ════════════════════════════════════════════════════════════════════════════
# 4. DCSyncStrategy
# ════════════════════════════════════════════════════════════════════════════
 
class TestDCSync(unittest.TestCase):
 
    def _edge(self):
        return FakeEdge(
            source_label="DOMAIN ADMINS@SEVENKINGDOMS.LOCAL",
            goal_label  ="SEVENKINGDOMS.LOCAL",
        )
 
    DCSYNC_OUTPUT = (
        "[*] Using the DRSUAPI method to get NTDS.DIT secrets\n"
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d61acea0f8b60b93862e8d04a23ceedf:::\n"
        "JOFFREY:1104:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::\n"
        "CERSEI:1108:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::\n"
        "[*] Cleaning up...\n"
    )
 
    def test_describe(self):
        out = DCSyncStrategy().describe(self._edge())
        self.assertIn("DCSync", out)
        self.assertIn("NTLM", out)
        print(f"\n[DCSync] describe → {out}")
 
    def test_exploit_success_krbtgt_found(self):
        """krbtgt trouvé = domaine totalement compromis."""
        s = DCSyncStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout=self.DCSYNC_OUTPUT)) as mock_run:
            result = s.exploit(self._edge(), **CREDS)
 
        cmd = mock_run.call_args[0][0]
        print(f"[DCSync] commande : {cmd}")
 
        # Vérifications sur la commande
        self.assertIn("-just-dc", cmd)
        self.assertNotIn("-outputfile", cmd)   # FIX validé
        self.assertIn(CREDS["dc_ip"], " ".join(cmd))
 
        print(f"[DCSync] krbtgt_hash : {result['credentials']['krbtgt_hash']}")
        print(f"[DCSync] total hashes : {len(result['credentials']['all_hashes'])}")
 
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["credentials"]["krbtgt_hash"])
        self.assertIn("krbtgt", result["credentials"]["krbtgt_hash"])
        self.assertEqual(result["credentials"]["type"], "dcsync")
        self.assertEqual(len(result["credentials"]["all_hashes"]), 4)
 
    def test_exploit_no_krbtgt(self):
        """Des hashes trouvés mais pas krbtgt → success=False (compromission partielle)."""
        stdout = (
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
        )
        s = DCSyncStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout=stdout)):
            result = s.exploit(self._edge(), **CREDS)
 
        print(f"[DCSync] sans krbtgt → {result}")
        self.assertFalse(result["success"])
        self.assertIsNone(result["credentials"])
 
    def test_exploit_empty_output(self):
        s = DCSyncStrategy()
        with patch("subprocess.run", return_value=_make_proc(stdout="")):
            result = s.exploit(self._edge(), **CREDS)
 
        self.assertFalse(result["success"])
 
    def test_exploit_timeout(self):
        import subprocess
        s = DCSyncStrategy()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 60)):
            result = s.exploit(self._edge(), **CREDS)
 
        self.assertFalse(result["success"])
        self.assertIn("60s", result["output"])
 
    def test_exploit_tool_missing(self):
        s = DCSyncStrategy()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = s.exploit(self._edge(), **CREDS)
 
        self.assertFalse(result["success"])
        self.assertIn("impacket", result["output"])
 
 
# ════════════════════════════════════════════════════════════════════════════
 
if __name__ == "__main__":
    unittest.main(verbosity=2)