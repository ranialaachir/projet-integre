# entities/credentials.py

from dataclasses import dataclass

@dataclass
class Credential:
    username: str
    password: str = ""
    hash:     str = ""
    ticket:   str = ""          # ccache path for Linux/WSL
    source:   str = ""          # which exploit produced this
