# 1. Clean old packages
rm -rf __pypackages__

# 2. Reinstall all needed packages (including fastmcp for the MCP module)
mkdir -p __pypackages__/3.13/lib
/opt/homebrew/bin/python3.13 -m pip install --target=__pypackages__/3.13/lib --no-deps \
  platformdirs requests pycardano mnemonic fastmcp

# 3. Patch mcp's version check to prevent importlib.metadata crash
sed -i '' 's/__version__ = version("mcp")/__version__ = "0.1"/' \
  __pypackages__/3.13/lib/mcp/server/fastmcp/__init__.py

# 4. Optional: Delete some heavy unused deps fastmcp drags in (keep it small)
rm -rf __pypackages__/3.13/lib/openai* \
       __pypackages__/3.13/lib/uvicorn* \
       __pypackages__/3.13/lib/aiohttp* \
       __pypackages__/3.13/lib/pydantic* \
       __pypackages__/3.13/lib/numpy* \
       __pypackages__/3.13/lib/jinja2* \
       __pypackages__/3.13/lib/h11*

# 5. Repack
dxt pack