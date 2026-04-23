# strategies/__init__.py

# from .exploit_strategy import ExploitStrategy

# from strategies.generic_all import GenericAllStrategy
# from strategies.generic_write import GenericWriteStrategy
# # from strategies.write_dacl import WriteDaclStrategy
# #from strategies.add_member import AddMemberStrategy
# from strategies.dc_sync import DCSyncStrategy
# #from strategies.kerberoast import KerberoastStrategy

# ABUSE_MAP: dict[str, "ExploitStrategy"] = {
#     "GenericAll":          GenericAllStrategy(),
#     "GenericWrite":        GenericWriteStrategy(),
#     # "WriteDacl":           WriteDaclStrategy(),
#     # "AddMember":           AddMemberStrategy(),
#     "GetChanges":          DCSyncStrategy(),
#     "GetChangesAll":       DCSyncStrategy(),
#     # "Kerberoastable":      KerberoastStrategy(),
# }