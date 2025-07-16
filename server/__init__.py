import os
import sys
import site

# Add local __pypackages__ to sys.path
pypackages = os.path.join(os.path.dirname(__file__), "..", "__pypackages__", f"{sys.version_info.major}.{sys.version_info.minor}", "lib")
site.addsitedir(pypackages)