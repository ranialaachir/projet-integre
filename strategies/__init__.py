from .add_member import AddMemberStrategy
from .force_change_password import ForceChangePasswordStrategy
from .generic_all import GenericAllStrategy
from .generic_write import GenericWriteStrategy
from .write_dacl import WriteDaclStrategy
from .write_owner import WriteOwnerStrategy
from .owns import OwnsStrategy
from .read_laps import ReadLAPSStrategy

# (strategy_class, cypher_relationship, source_label, target_label)
STRATEGY_REGISTRY = [
    (AddMemberStrategy,             "AddMember",            "Base",  "Group"),
    (ForceChangePasswordStrategy,   "ForceChangePassword",  "Base",  "User"),
    (GenericAllStrategy,            "GenericAll",           "Base",  "Base"),
    (GenericWriteStrategy,          "GenericWrite",         "Base",  "Base"),
    (WriteDaclStrategy,             "WriteDACL",            "Base",  "Base"),
    (WriteOwnerStrategy,            "WriteOwner",           "Base",  "Base"),
    (OwnsStrategy,                  "Owns",                 "Base",  "Base"),
    (ReadLAPSStrategy,              "ReadLAPSPassword",     "Base",  "Computer"),
]