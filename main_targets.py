# main_targets.py
#
# Searches for the shortest attack paths to high-value targets,
# stopping as soon as at least one path is found at the highest tier.

import sys
from dotenv import load_dotenv

from entities.node import Node
from entities.node_kind import NodeKind

from repositories.pathfinding_repository import PathfindingRepository
from repositories.enumeration_repository import EnumerationRepository
from repositories.bloodhound_repository import BloodHoundRepository

from services.printing import *
from services.reporting import *
from services.scoring import path_cost

from references.privilege_levels import classify, PrivilegeLevel

from exceptions.no_path_error import NoPathError
from exceptions.api_error import ApiError
from exceptions.config_error import ConfigError

load_dotenv()

# ─── 1. Load credentials & connectivity check ────────────────────────────────
try:
    repo = BloodHoundRepository()
    print_check("Credentials loaded — connecting to BloodHound...")

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

# ─── 2. Fetch high-value targets ─────────────────────────────────────────────
print_title("Step 2 — Fetching high-value targets")

enum = EnumerationRepository()
tz_nodes = {}

try:
    tz_nodes = enum.get_high_value_nodes()
    print_check(f"Found {len(tz_nodes)} high-value node(s):")
    print_dict_node(tz_nodes)
except ApiError as e:
    print_error(str(e))
    sys.exit(1)
except RuntimeError as e:
    print_error(str(e))
    sys.exit(1)

if not tz_nodes:
    print_warning("No high-value targets found. Exiting.")
    sys.exit(0)

# ─── 3. Define owned nodes ────────────────────────────────────────────────────
print_title("Step 3 — Owned nodes")

owned_nodes: list[Node] = [
    Node(
        objectid="S-1-5-21-4100227132-2050190331-2295276406-1000",
        kind=NodeKind.USER,
        label="VAGRANT@SEVENKINGDOMS.LOCAL",
        properties={"owned": True}
    )
]

for node in owned_nodes:
    print_node(node, "Owned")

# ─── 4. Classify targets by privilege level ───────────────────────────────────
print_title("Step 4 — Classifying targets by privilege level")

classified: dict[PrivilegeLevel, list[Node]] = {}
for node in tz_nodes.values():
    level = classify(node)
    classified.setdefault(level, []).append(node)

for level, nodes in sorted(classified.items(), key=lambda x: x[0]):
    print_level(level)
    for node in nodes:
        print_node(node)

# ─── 5. Search for paths — stop at first successful tier ─────────────────────
print_title("Step 5 — Searching attack paths (best tier first)")

pthfinding = PathfindingRepository()

# Sort tiers: most critical first (lowest enum value = highest privilege)
sorted_tiers = sorted(classified.items(), key=lambda x: x[0])

for level, targets in sorted_tiers:
    print_title(f"Trying tier: {level.name}")

    tier_results = []

    for source in owned_nodes:
        for target in targets:
            if source.objectid == target.objectid:
                continue

            print_check(f"Trying: {source.label} → {target.label}")
            try:
                path = pthfinding.get_path(source, target)
                cost = path_cost(path.edges)
                tier_results.append({
                    "source": source,
                    "target": target,
                    "privilege_level": level,
                    "path": path,
                    "cost": cost,
                })
                print_check(
                    f"Path found! {source.label} → {target.label} "
                    f"[{level.name}] cost={cost} hops={len(path.edges)}"
                )
            except NoPathError:
                print_warning(f"No path: {source.label} → {target.label}")
            except Exception as e:
                print_warning(f"Error: {source.label} → {target.label}: {e}")

    if tier_results:
        # ── Found paths at this tier — rank and display, then stop ────────
        print_title(f"Step 6 — Best paths at tier {level.name}")

        tier_results.sort(key=lambda r: r["cost"])

        for i, r in enumerate(tier_results, 1):
            panel = format_path(
                path=r["path"],
                index=i,
                privilege_level=r["privilege_level"],
            )
            console.print(panel)

        # ── Summary ───────────────────────────────────────────────────────
        print_title("Summary")
        print_check(f"Tier reached:  {level.name}")
        print_done(  f"Paths found:   {len(tier_results)}")
        best = tier_results[0]
        print_check(
            f"Best path:     {best['source'].label} → {best['target'].label} "
            f"(cost={best['cost']}, hops={len(best['path'].edges)})"
        )

        break  # Don't move to lower-priority tiers

    else:
        print_warning(f"No paths at tier {level.name} — moving to next tier...")

else:
    # Loop completed without break = no paths found at any tier
    print_warning("No attack paths found from owned nodes to any high-value target.")
