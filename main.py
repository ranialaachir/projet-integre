# main.py

import sys
from dotenv import load_dotenv

from entities.node import Node
from entities.node_kind import NodeKind

from utils.platform import BACKEND

from repositories.pathfinding_repository import PathfindingRepository
from services.printing import *
from services.reporting import *
from services.parse_objects import *
from repositories.enumeration_repository import EnumerationRepository
from services.scoring import path_cost
from repositories.strategy_runner_repository import StrategyRunnerRepository, StrategyTestResult

from strategies import STRATEGY_REGISTRY

from exceptions.no_path_error import NoPathError
from exceptions.auto_pwn_exception import AutoPwnException
from exceptions.config_error import ConfigError

from references.privilege_levels import classify, PrivilegeLevel
from exceptions.api_error import ApiError

from repositories.bloodhound_repository import BloodHoundRepository

load_dotenv()

# ─── 1. Load credentials ────────────────────────────────────────────────────
try:
    repo = BloodHoundRepository()
    print_check(f"Credentials loaded — connecting to bloodhound...")
# ─── 2. Connectivity check ───────────────────────────────────────────────────
    print_title("Step 1 — Checking API connectivity")
    result = repo.connectivity_check()
    print_check(f"Connected. Token belongs to: {result.get('data', {}).get('principal_name', '?')}")
except ConfigError as e:
    print_error(str(e))
    sys.exit(1)
except ApiError as e:
    print_error(str(e))
    sys.exit(1)
except RuntimeError as e:
    print_error(str(e))
    sys.exit(1)

# ─── 3. Raw Cypher query — list domains ──────────────────────────────────────
# Sanity check that the Neo4j data is populated and the Cypher endpoint works.

print_title("Step 2 — Querying domains in Neo4j")
try:
    enum = EnumerationRepository()
    
    print_info("List of All Domains : ")
    domains = enum.get_domains()
    print_check(f"Found {len(domains.keys())} domain(s):")
    print_dict_node(domains)

    print_info("List of All Users")
    users = enum.get_users()
    print_dict_node(users)

    print_info("List of All Groups")
    groups = enum.get_groups()
    print_dict_node(groups)
except ApiError as e:
    print_error(str(e))
    sys.exit(1)
except RuntimeError as e:
    print_error(str(e))
    sys.exit(1)

# ─── 4. Find a Kerberoastable user ───────────────────────────────────────────

# ─── 5. Find Domain Admins group objectId ────────────────────────────────────
print_title("\nStep 4 — Locating Domain Admins group")
try:
    da_node = enum.locate_domain_admins_group()
    print_node(da_node)
except ApiError as e:
    print_error(str(e))
    sys.exit(1)
except RuntimeError as e:
    print_error(str(e))
    sys.exit(1)

# ─── 6. Find a user to path from ─────────────────────────────────────────────
print_title("Step 5 — Finding a user to path from")

try:
    enabled_user_nodes = enum.get_enabled_users()
    print_check(f"Found {len(enabled_user_nodes)} enabled user(s):")
    print_dict_node(enabled_user_nodes)
except ApiError as e:
    print_error(str(e))
    sys.exit(1)
except RuntimeError as e:
    print_error(str(e))
    sys.exit(1)

# ─── 7. Shortest path to Domain Admins ───────────────────────────────────────
pthfinding = PathfindingRepository()
print_title("Step 6 — Shortest path to Domain Admins")
path_found = False
for source in enabled_user_nodes.values():
    print_check(f"Trying: {source.label} → {da_node.label}")
    try:
        print(1)
        path = pthfinding.get_path(source, da_node)
        path.edges = [e for e in path.edges if e is not None]
        if not path.edges:
            print_warning(f"Path found but all edges were unknown kinds, skipping.")
            continue
        print_check(f"Path found! Length: {path.length} hop(s)")
        print_path(path, index=1)
        path_found = True
        break
    except NoPathError:
        print_warning(f"No path from {source.label}, trying next...")
    except AutoPwnException as e:
        print_error(f"Tool error: {e}")

if not path_found:
    print_warning("No path found from any of the sampled users.")

# ─── 8. Test ALL strategies on matching edges ─────────────────────────────
strat_runner_repo = StrategyRunnerRepository()

print_title("Step 7 — Testing ALL exploit strategies")

if BACKEND.name == "none":
    print_error(
        "No backend available. Install bloodyAD (Linux) "
        "or bloodyAD in WSL (Windows)."
    )
    sys.exit(1)

print_check(f"Backend detected: {BACKEND.name}")
all_results: list[StrategyTestResult] = []

for strategy_cls, relationship, src_label, dst_label in STRATEGY_REGISTRY:
    print_title(f"Testing: {strategy_cls.__name__}  (edge: {relationship})")

    entries = strat_runner_repo.run_single_strategy(
        strategy_cls=strategy_cls,
        relationship=relationship,
        src_label=src_label,
        dst_label=dst_label,
        limit=3,
        dry_run=False,
    )

    for entry in entries:
        all_results.append(entry)

        if entry.skipped:
            print_warning(f"  SKIP — {entry.skip_reason}")
            continue

        edge = entry.edge
        src = edge.source_node.label if edge else "?"
        dst = edge.goal_node.label   if edge else "?"

        if entry.error:
            print_error(f"  FAIL — {src} → {dst}")
            print_error(f"         {entry.error}")
            continue

        res = entry.result
        if res and res.success:
            print_done(f"  OK   — {src} → {dst}  [{res.technique}]")
            if res.notes:
                for line in res.notes.splitlines():
                    print_check(f"         {line}")
            if hasattr(res, "print_next_steps"):
                res.print_next_steps()
        elif res and res.success is None:
            print_warning(f"  DRY  — {src} → {dst}  (success=None)")
        else:
            print_warning(f"  FAIL — {src} → {dst}  (success=False)")

# ── Summary ──────────────────────────────────────────────────────────
print_title("Summary")

total    = len(all_results)
passed   = sum(1 for r in all_results if r.success)
failed   = sum(1 for r in all_results if r.error)
skipped  = sum(1 for r in all_results if r.skipped)

print_check(f"Total:   {total}")
print_done( f"Passed:  {passed}")
if failed:
    print_error(f"Failed:  {failed}")
if skipped:
    print_warning(f"Skipped: {skipped}")

print()
header = f"{'Strategy':<35} {'Edge':<20} {'Source → Target':<45} {'Result':<10}"
print(header)
print("─" * len(header))

for r in all_results:
    name  = r.strategy_name[:34]
    rel   = r.relationship[:19]

    if r.edge:
        pair = f"{r.edge.source_node.label} → {r.edge.goal_node.label}"
    else:
        pair = "—"
    pair = pair[:44]

    if r.skipped:
        status = "SKIP"
    elif r.error:
        status = "FAIL"
    elif r.success:
        status = "OK"
    else:
        status = "FAIL"

    print(f"{name:<35} {rel:<20} {pair:<45} {status:<10}")

# ─── 10. High-value targets ───────────────────────────────────────────────────
# We need : a reference table or lookup catalog
print_title("Step 9 — High-value targets")
tz_nodes = {}
try:
    tz_nodes = enum.get_high_value_nodes()
    print_dict_node(tz_nodes)
except ApiError as e:
    print_error(str(e))
except RuntimeError as e:
    print_error(str(e))

# ──────────────────────────────────────────────────────────
# Step 11 — Define owned nodes (hardcoded for v1)
# ──────────────────────────────────────────────────────────

print_title("Step 10 — Owned nodes")
owned_nodes: list[Node] = [
    Node(
        objectid="S-1-5-21-4100227132-2050190331-2295276406-1000",
        kind=NodeKind.USER,
        label="VAGRANT@SEVENKINGDOMS.LOCAL",
        properties={"owned": True}
    )
]

for node in owned_nodes:
    print_node(node,"Owned") #success


# ──────────────────────────────────────────────────────────
# Step 12 — Classify targets by privilege level
# ──────────────────────────────────────────────────────────

print_title("Step 11 — Classify targets")
# Group targets by privilege level and sort (most critical first)
classified: dict[PrivilegeLevel, list[Node]] = {}
for node in tz_nodes.values():
    level = classify(node)
    if level not in classified.keys():
        classified[level] = [node]
    else:
        classified[level].append(node)

for level, nodes in classified.items():
    print_level(level)
    for node in nodes:
        print_node(node)

# ──────────────────────────────────────────────────────────
# Step 13 — Find paths from owned → targets
# ──────────────────────────────────────────────────────────

print_title("Step 12 — Attack paths")

results = []

for level, targets in classified.items():  # ?? We'll print all paths, but later only the best (!!)
    for source in owned_nodes:
        for target in targets:
            # Skip if source IS the target
            if source.objectid == target.objectid:
                continue
            try:
                path = pthfinding.get_path(source, target)
                cost = path_cost(path.edges)
                results.append({
                    "source": source,
                    "target": target,
                    "privilege_level": level,
                    "path": path,
                    "cost": cost,
                })
                print_check(
                    f"{source.label} → {target.label} "
                    f"[{level.name}] cost={cost} hops={len(path.edges)}"
                )
            except NoPathError:
                print_warning(f"No path: {source.label} → {target.label}")
            except Exception as e:
                print_warning(f"Error: {source.label} → {target.label}: {e}")

# ──────────────────────────────────────────────────────────
# Step 14 — Rank and display best attack paths
# ──────────────────────────────────────────────────────────

print_title("Step 13 — Best attack paths")

if not results:
    print_warning("No attack paths found from owned nodes.")
else:
    # Sort: most critical target first, then cheapest path
    results.sort(key=lambda r: (r["privilege_level"], r["cost"]))

    for i, r in enumerate(results, 1):
        panel = format_path(
            path=r["path"],
            index=i,
            privilege_level=r["privilege_level"],
        )
        console.print(panel)