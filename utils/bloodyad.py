# utils/bloodyad.py

def bloodyad_cmd(creds: dict, subcommand: list[str]) -> list[str]: #creds maybe class?
    cmd = [
        "-H", creds["dc_ip"],
        "-d", creds["domain"],
        "-u", creds["username"],
    ]
    cmd += ["-p", creds.get("secret","")]
    print(f"DEBUG : {cmd + subcommand}")
    return cmd + subcommand