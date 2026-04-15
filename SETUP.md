## Setup

### Windows (3 personnes)
1. Install WSL2 : `wsl --install`
2. Install pipx : `sudo apt install pipx`
3. In WSL : `ppipx install bloodyAD && pipx ensurepath`
3. Verify after a new Session : `wsl bloodyAD --help`
4. Check in the powershell : `wsl bash -lc "which bloodyAD"`
5. `wsl sudo apt install -y samba-common-bin`
6. `route add <GOAD_MACHINE_NETIP> mask 255.255.255.0 <SERVER_IP> -p`

### Linux (1 personne)
1. `pip install bloodyAD`
2. `ip route add <GOAD_MACHINE_NETIP>/24 via <SERVER_IP>`

### Everyone
`pip install -r requirements.txt`


pipx install bloodyAD
pipx ensurepath
# Redémarre ton terminal, puis :
bloodyAD --help