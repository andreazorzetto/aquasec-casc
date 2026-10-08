"""aquasec-casc: config-as-code for Aqua Security."""

#: The tool's name. Also part of the ownership marker written into every object
#: it manages ("managed-by: <TOOL_NAME>/<instance>"), so changing it after a
#: rollout makes every marked object look unmanaged.
TOOL_NAME = "aquasec-casc"
