"""
strategies/
├── techniques/
│   ├── ldap_techniques.py
│   │   ├── _do_force_change_password
│   │   ├── _do_add_member
│   │   ├── _do_rbcd
│   │   ├── _do_grant_generic_all
│   │   ├── _do_take_ownership
│   │   └── _do_grant_dcsync        ← LDAP write (adds ACEs)
│   │
│   ├── kerberos_techniques.py
│   │   ├── _do_shadow_credentials  ← PKINIT auth using fake cert
│   │   ├── _do_kerberoast
│   │   ├── _do_asreproast
│   │   └── _do_s4u
│   │
│   ├── credential_techniques.py
│   │   ├── _do_dcsync              ← secretsdump (extracts hashes)
│   │   └── _do_read_laps
│   │
│   └── exec_techniques.py
│       ├── _do_rdp
│       ├── _do_psremote
│       └── _do_psexec
"""