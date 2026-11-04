"""For scripts/rehearse_demo.sh: what a person would do in the console."""

from __future__ import annotations

import sys

from aquasec import runtime_policies as rp

from aquasec_casc.client import connect, resolve_settings

action, name, *rest = sys.argv[1:]
client = connect(resolve_settings())
args = (client.server, client.token)

if action == "create":
    rp.create_runtime_policy(*args, {
        "name": name, "runtime_type": "container", "enabled": False, "enforce": False,
        "application_scopes": ["Global"], "block_disallowed_images": True,
        "description": "aquasec-casc demo rehearsal, safe to delete"})
elif action == "tick":
    rp.update_runtime_policy(*args, name, {**rp.get_runtime_policy(*args, name), rest[0]: True})
elif action == "show":
    value = rp.get_runtime_policy(*args, name)[rest[0]]
    print(f"in Aqua: {rest[0]} = {value}")
    sys.exit(0 if str(value).lower() == rest[1] else 1)
elif action == "delete":
    rp.delete_runtime_policy(*args, name, missing_ok=True)
