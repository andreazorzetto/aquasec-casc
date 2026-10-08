"""aqua-casc: config-as-code for Aqua Security."""

#: The tool's name. Also part of the ownership marker written into every object
#: it manages ("managed-by: <TOOL_NAME>/<instance>"), so settle it before any
#: real rollout: objects marked under an old name look unmanaged under a new one.
TOOL_NAME = "aqua-casc"
