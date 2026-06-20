"""Optional integrations. Importing this package must not require the MCP SDK.

The submodules here (:mod:`mcp_doorman.integrations.fastmcp`) lazy-import ``mcp``/FastAPI
inside their functions so the core stays dependency-light and offline-testable.
"""
