# strategies/__init__.py
from .add_member import AddMemberStrategy
from .force_change_password import ForceChangePasswordStrategy
from .generic_all import GenericAllStrategy
from .generic_write import GenericWriteStrategy

# (strategy_class, cypher_relationship, source_label, target_label)
STRATEGY_REGISTRY = [
    (AddMemberStrategy,             "AddMember",            "Base",  "Group"),
    (ForceChangePasswordStrategy,   "ForceChangePassword",  "Base",  "User"),
    (GenericAllStrategy,            "GenericAll",           "Base",  "Base"),
    (GenericWriteStrategy,          "GenericWrite",         "Base",  "Base"),
]