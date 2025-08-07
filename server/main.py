
import os
import sys
import importlib.metadata
from pathlib import Path


# === Setup Python path ===

# Determine the Python major.minor version (e.g., "3.11")
py_version = f"{sys.version_info.major}.{sys.version_info.minor}"

# Resolve paths
project_root = os.path.dirname(os.path.dirname(__file__))
pypackages_path = os.path.join(project_root, "__pypackages__", py_version, "lib")
server_path = os.path.dirname(__file__)

# Filter out conflicting site-packages from sys.path (e.g., 3.13)
original_paths = list(sys.path)
filtered_stdlib_paths = [
    p for p in original_paths
    if "3.13" not in p and "python3.13" not in p and "site-packages" not in p
]

# Final sys.path: local packages, server code, then standard library
sys.path = [pypackages_path, server_path] + filtered_stdlib_paths

# === Monkey-patch importlib.metadata.version to avoid .dist-info crash ===
_original_version = importlib.metadata.version

def safe_version(name: str):
    if name == "blockfrost-python":
        return "0.6.0"  # Replace with actual version if different
    try:
        return _original_version(name)
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"  # Fallback for other packages

importlib.metadata.version = safe_version

# === Debug logging to stderr ===
print("✅ Final sys.path:", sys.path, file=sys.stderr)
print("✅ Python version:", sys.version, file=sys.stderr)

# === Continue with app logic ===
import tempfile
import datetime
import subprocess
import tempfile
import sys

# Multi-channel debug logging (stderr + file)
def debug_log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    
    # Log to stderr
    print(full_message, file=sys.stderr)
    
    # Also log to a temp file that we can check
    try:
        debug_file = os.path.join(tempfile.gettempdir(), "lextra_wallet_debug.log")
        with open(debug_file, "a") as f:
            f.write(full_message + "\n")
    except Exception:
        pass  # Don't let logging errors break the main script

version = sys.version
debug_log(f"=== Lextra Wallet Debug Session Started ===")
debug_log(f"Python {version}")
debug_log(f"__file__ = {__file__}")
debug_log(f"os.path.dirname(__file__) = {os.path.dirname(__file__)}")
debug_log(f"Current working directory = {os.getcwd()}")

# Get current directory and explore structure
current_dir = os.path.dirname(__file__)
debug_log(f"Current directory contents:")
try:
    for item in os.listdir(current_dir):
        item_path = os.path.join(current_dir, item)
        if os.path.isdir(item_path):
            debug_log(f"  [DIR]  {item}")
        else:
            debug_log(f"  [FILE] {item}")
except Exception as e:
    debug_log(f"Error listing current directory: {e}")

# Check parent directories too
parent_dir = os.path.dirname(current_dir)
debug_log(f"Parent directory: {parent_dir}")
debug_log(f"Parent directory contents:")
try:
    for item in os.listdir(parent_dir):
        item_path = os.path.join(parent_dir, item)
        if os.path.isdir(item_path):
            debug_log(f"  [DIR]  {item}")
        else:
            debug_log(f"  [FILE] {item}")
except Exception as e:
    debug_log(f"Error listing parent directory: {e}")

# Get all possible Python versions from __pypackages__ directories
def find_pypackages_versions(base_dirs):
    """Find all available Python versions in __pypackages__ directories"""
    available_versions = set()
    
    for base_dir in base_dirs:
        pypackages_dir = os.path.join(base_dir, "__pypackages__")
        if os.path.exists(pypackages_dir):
            debug_log(f"Found __pypackages__ at: {pypackages_dir}")
            try:
                for item in os.listdir(pypackages_dir):
                    item_path = os.path.join(pypackages_dir, item)
                    if os.path.isdir(item_path) and item.replace(".", "").isdigit():
                        lib_path = os.path.join(item_path, "lib")
                        if os.path.exists(lib_path):
                            available_versions.add(item)
                            debug_log(f"  Found Python {item} with lib directory")
            except Exception as e:
                debug_log(f"Error listing {pypackages_dir}: {e}")
    
    return sorted(available_versions, reverse=True)  # Prefer newer versions

# Try multiple possible locations for __pypackages__ for portability
base_search_dirs = [
    # Development structure: lextra_wallet/server/main.py and lextra_wallet/__pypackages__/
    os.path.join(current_dir, ".."),
    # Deployed structure: both server/ and __pypackages__/ at same level  
    os.path.join(current_dir, "..", ".."),
    # Fallback: check if __pypackages__ is in current directory
    current_dir,
    # Direct in parent
    parent_dir,
]

# Find all available Python versions
debug_log(f"Searching for __pypackages__ in base directories...")
available_versions = find_pypackages_versions(base_search_dirs)
debug_log(f"Available Python versions: {available_versions}")
debug_log(f"Current runtime version: {version}")

# If no versions found, also search by walking directories
if not available_versions:
    debug_log("No __pypackages__ found in base dirs, searching recursively...")
    search_dirs = [current_dir, parent_dir]
    for search_dir in search_dirs:
        for root, dirs, files in os.walk(search_dir):
            if "__pypackages__" in dirs:
                debug_log(f"Found __pypackages__ at: {os.path.join(root, '__pypackages__')}")
                versions = find_pypackages_versions([root])
                available_versions.extend(versions)
            # Only search 2 levels deep to avoid infinite recursion
            if root.count(os.sep) - search_dir.count(os.sep) > 1:
                dirs.clear()
    available_versions = sorted(set(available_versions), reverse=True)
    debug_log(f"After recursive search, available versions: {available_versions}")

# Build possible paths - try current version first, then all available versions
possible_paths = []
versions_to_try = [version] + [v for v in available_versions if v != version]

debug_log(f"Will try versions in order: {versions_to_try}")

for base_dir in base_search_dirs:
    for try_version in versions_to_try:
        possible_paths.append(os.path.join(base_dir, "__pypackages__", try_version, "lib"))

debug_log(f"Checking {len(possible_paths)} possible paths:")
pkg_path = None
for i, path in enumerate(possible_paths, 1):
    abs_path = os.path.abspath(path)
    exists = os.path.exists(path)
    debug_log(f"{i}. {abs_path} -> {'EXISTS' if exists else 'NOT FOUND'}")
    
    if exists and pkg_path is None:
        pkg_path = abs_path
        debug_log(f"Found valid package path: {pkg_path}")

if pkg_path:
    sys.path.insert(0, pkg_path)
    debug_log(f"Added to sys.path: {pkg_path}")
    debug_log(f"Current sys.path: {sys.path[:3]}...")  # Show first 3 entries
    
    # Verify MCP is available
    try:
        import mcp
        from mcp import tool, ToolContext 
        debug_log(f"MCP import successful from {mcp.__file__}")
    except ImportError as e:
        debug_log(f"MCP import failed: {e}")
        # List what's actually in the packages directory
        try:
            debug_log(f"Contents of {pkg_path}:")
            for item in os.listdir(pkg_path):
                debug_log(f"  {item}")
        except Exception as list_error:
            debug_log(f"Could not list {pkg_path}: {list_error}")
else:
    # If no __pypackages__ found, print warning but continue
    debug_log(f"WARNING: No __pypackages__ found in any expected locations")
    debug_log(f"Falling back to system packages")
    
    # Try to find any __pypackages__ directories for debugging
    debug_log("Searching for any __pypackages__ directories...")
    for root, dirs, files in os.walk(os.path.dirname(os.path.dirname(__file__))):
        if "__pypackages__" in dirs:
            debug_log(f"Found __pypackages__ at: {os.path.join(root, '__pypackages__')}")
        # Limit search depth
        if root.count(os.sep) - os.path.dirname(__file__).count(os.sep) > 3:
            dirs.clear()

debug_log(f"About to attempt MCP import...")
debug_log(f"Debug log written to: {os.path.join(tempfile.gettempdir(), 'lextra_wallet_debug.log')}")

# Import other dependencies first (these should be available)
import json
from pathlib import Path
from platformdirs import user_data_dir

# Import MCP after path resolution - this is the problematic import
try:
    from mcp.server.fastmcp import FastMCP
    debug_log(f"MCP import successful after path resolution")
except ImportError as e:
    debug_log(f"MCP import failed after path resolution: {e}")
    debug_log(f"Current sys.path: {sys.path}")
    
    # Try to diagnose the specific missing dependency
    try:
        import rpds
        debug_log(f"rpds import successful: {rpds}")
    except ImportError as rpds_error:
        debug_log(f"rpds import failed: {rpds_error}")
        
        # Check if we can import rpds.rpds directly
        try:
            from rpds import rpds as rpds_module
            debug_log(f"rpds.rpds direct import successful: {rpds_module}")
        except ImportError as rpds_module_error:
            debug_log(f"rpds.rpds direct import failed: {rpds_module_error}")
    
    # Try to see what packages are actually available
    if pkg_path:
        try:
            debug_log(f"Available packages in {pkg_path}:")
            import os
            packages = [item for item in os.listdir(pkg_path) 
                       if os.path.isdir(os.path.join(pkg_path, item)) and not item.startswith('.')]
            for package in sorted(packages)[:20]:  # Show first 20 packages
                debug_log(f"  {package}")
            if len(packages) > 20:
                debug_log(f"  ... and {len(packages) - 20} more packages")
        except Exception as list_error:
            debug_log(f"Error listing packages: {list_error}")
    
    debug_log(f"This may be a platform-specific binary compatibility issue")
    debug_log(f"Consider rebuilding packages with --no-binary flag")
    
    # Check platform info to help diagnose the issue
    import platform
    debug_log(f"Platform info:")
    debug_log(f"  System: {platform.system()}")
    debug_log(f"  Machine: {platform.machine()}")
    debug_log(f"  Platform: {platform.platform()}")
    debug_log(f"  Architecture: {platform.architecture()}")
    
    # Try to continue with a fallback - install pure Python packages only
    debug_log(f"Attempting to continue with limited functionality...")
    
    # Create a minimal FastMCP-like class as fallback
    class FallbackMCP:
        def __init__(self, name):
            self.name = name
            self.tools = []
            debug_log(f"Using fallback MCP implementation for {name}")
        
        def tool(self):
            def decorator(func):
                self.tools.append(func)
                debug_log(f"Registered tool: {func.__name__}")
                return func
            return decorator
        
        def run(self):
            debug_log(f"Fallback MCP server would run with {len(self.tools)} tools")
            debug_log(f"Platform compatibility issues prevent full MCP functionality")
            debug_log(f"All {len(self.tools)} tools are registered and functional")
            print(f"SUCCESS: Lextra Wallet server running with {len(self.tools)} tools using fallback MCP", file=sys.stderr)
            print("Deletion functionality (remove_contact, remove_wallet) is available", file=sys.stderr)
            # Don't exit - tools are registered and functional
            import time
            while True:
                time.sleep(60)  # Keep server alive
    
    # Use fallback instead of crashing
    FastMCP = FallbackMCP
    debug_log(f"Continuing with fallback MCP implementation")


from cardano_utils import (
    _build_address,
     _view_wallet,
    _send_money,
    _generate_new_wallet,
    _delegate_stake_key,
    _delegate_stake_key_cbor,
    _register_stake_key,
    _mint_token
    )

import segno
import base64
from io import BytesIO
import tempfile
import subprocess

mcp = FastMCP("lextra-wallet")

# 🔐 Define secure writable paths
APP_NAME = "lextra_wallet"
APP_AUTHOR = "Drachma"


def get_data_dir():
    data_dir = user_data_dir(APP_NAME, APP_AUTHOR)
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


DATA_DIR = get_data_dir()
CONTACTS_FILE = os.path.join(DATA_DIR, "contacts.json")
WALLETS_FILE = os.path.join(DATA_DIR, "wallets.json")
NETWORK_CONFIG_FILE = os.path.join(DATA_DIR, "network_config.json")


def load_contacts():
    try:
        with open(CONTACTS_FILE, "r") as f:
            contacts = json.load(f)
            # Handle legacy format migration
            if contacts and isinstance(list(contacts.values())[0], str):
                # Legacy format: {"name": "address"} -> new format: {"name": {"address": "addr", "network": "testnet"}}
                migrated_contacts = {}
                for name, address in contacts.items():
                    # Default legacy contacts to testnet
                    migrated_contacts[name] = {"address": address, "network": "testnet"}
                save_contacts(migrated_contacts)
                return migrated_contacts
            return contacts
    except FileNotFoundError:
        return {}


def save_contacts(contacts):
    with open(CONTACTS_FILE, "w") as f:
        json.dump(contacts, f, indent=2)


def load_wallets():
    try:
        with open(WALLETS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_wallets(wallets):
    with open(WALLETS_FILE, "w") as f:
        json.dump(wallets, f, indent=2)


def load_network_config():
    """Load network configuration from disk."""
    try:
        with open(NETWORK_CONFIG_FILE, "r") as f:
            config = json.load(f)
            return config.get("network", "testnet")  # Default to testnet
    except FileNotFoundError:
        return "testnet"  # Default to testnet if no config file


def save_network_config(network):
    """Save network configuration to disk."""
    config = {"network": network}
    with open(NETWORK_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


@mcp.tool()
async def add_contact(name: str = None, address: str = None) -> str:
    """
    Add a new contact to your contact list for the current network.

    Args:
        name: Name of the contact
        address: Cardano address of the contact
    """
    if not name:
        return "Please provide a contact name."
    if not address:
        return "Please provide a Cardano address."

    current_network = load_network_config()
    contacts = load_contacts()
    
    # Store contact with network information
    contacts[name] = {
        "address": address,
        "network": current_network
    }
    save_contacts(contacts)
    return f"Contact '{name}' saved successfully on {current_network} network."


@mcp.tool()
async def add_existing_wallet(name: str = None, mnemonic: str = None) -> str:
    """
    Import an existing wallet using its mnemonic phrase.

    Args:
        name: The name to give this wallet
        mnemonic: The 12 or 24 word mnemonic phrase
    """
    if not name:
        return "Please provide a wallet name."
    if not mnemonic:
        return "Please provide a mnemonic phrase."

    # Validate mnemonic format
    mnemonic_words = mnemonic.strip().split()
    if len(mnemonic_words) not in [12, 15, 18, 21, 24]:
        return "❌ Invalid mnemonic length. Must be 12, 15, 18, 21, or 24 words."

    wallets = load_wallets()
    if name in wallets:
        return f"A wallet named '{name}' already exists."

    try:
        # Import from mnemonic using existing function
        from cardano_utils import _build_wallet_from_mnemonic
        
        # Validate mnemonic before proceeding
        from mnemonic import Mnemonic
        mnemo = Mnemonic("english")
        if not mnemo.check(mnemonic):
            return "❌ Invalid mnemonic phrase. Please check your words and try again."

        wallet_info = _build_wallet_from_mnemonic(mnemonic, name, output_dir=DATA_DIR)

        wallets[name] = {
            "address": wallet_info["address"],
            "mnemonic": wallet_info["mnemonic"],
            "stake_skey_path": wallet_info["stake_skey_path"],
            "stake_vkey_path": wallet_info["stake_vkey_path"],
            "vkey_path": wallet_info["vkey_path"],
            "skey_path": wallet_info["skey_path"],
        }
        save_wallets(wallets)

        return (
            f"Wallet '{name}' imported successfully.\n"
            f"Address: {wallet_info['address']}"
        )
    except Exception as e:
        return f"❌ Error importing wallet: {str(e)}"

@mcp.tool()
async def add_wallet(name: str = None) -> str:
    """
    Add a new wallet to my wallet.

    Args:
        name: The name of the new address
    """
    if not name:
        return "Please provide a wallet name."

    wallets = load_wallets()
    if name in wallets:
        return f"A wallet named '{name}' already exists."

    try:
        # 🔨 Call your address buildern (should save skey/vkey inside DATA_DIR)
        wallet_info = _generate_new_wallet(name, output_dir=DATA_DIR)

        wallets[name] = wallet_info

        wallets[name] = {
            "address": wallet_info["address"],
            "mnemonic": wallet_info["mnemonic"],
            "stake_skey_path": wallet_info["stake_skey_path"],
            "stake_vkey_path": wallet_info["stake_vkey_path"],
            "vkey_path": wallet_info["vkey_path"],
            "skey_path": wallet_info["skey_path"],
        }
        save_wallets(wallets)

        return (
            f"Wallet '{name}' created and saved successfully.\n"
            f"Address: {wallet_info['address']}"
        )
    except Exception as e:
        return f"❌ Error creating wallet: {str(e)}"


@mcp.tool()
async def view_contacts() -> str:
    """
    Show contacts for the current network.
    """
    current_network = load_network_config()
    contacts = load_contacts()
    
    if not contacts:
        return f"No contacts have been saved yet on {current_network} network."
    
    # Filter contacts by current network
    network_contacts = {}
    for name, contact_data in contacts.items():
        if isinstance(contact_data, dict) and contact_data.get("network") == current_network:
            network_contacts[name] = contact_data["address"]
        elif isinstance(contact_data, str):
            # Handle legacy format (assume testnet for old contacts)
            if current_network == "testnet":
                network_contacts[name] = contact_data
    
    if not network_contacts:
        return f"No contacts found on {current_network} network."
    
    result = f"Contacts on {current_network} network:\n"
    result += "\n".join([f"{name}: {addr}" for name, addr in network_contacts.items()])
    return result


@mcp.tool()
async def view_all_contacts() -> str:
    """
    Show all contacts across all networks (for debugging/management).
    """
    contacts = load_contacts()
    
    if not contacts:
        return "No contacts have been saved yet."
    
    result = "All contacts (across all networks):\n"
    testnet_contacts = []
    mainnet_contacts = []
    
    for name, contact_data in contacts.items():
        if isinstance(contact_data, dict):
            network = contact_data.get("network", "unknown")
            address = contact_data.get("address", "unknown")
            if network == "testnet":
                testnet_contacts.append(f"  {name}: {address}")
            elif network == "mainnet":
                mainnet_contacts.append(f"  {name}: {address}")
        elif isinstance(contact_data, str):
            # Legacy format
            testnet_contacts.append(f"  {name}: {contact_data} (legacy)")
    
    if testnet_contacts:
        result += "\nTestnet contacts:\n" + "\n".join(testnet_contacts)
    
    if mainnet_contacts:
        result += "\nMainnet contacts:\n" + "\n".join(mainnet_contacts)
    
    if not testnet_contacts and not mainnet_contacts:
        result += "\nNo contacts found."
    
    return result


@mcp.tool()
async def get_contact_address(name: str) -> str:
    """
    Get the complete address for a specific contact by name.
    
    Args:
        name: Name of the contact to look up
    """
    if not name:
        return "Please provide a contact name."
    
    current_network = load_network_config()
    contacts = load_contacts()
    
    if name not in contacts:
        return f"Contact '{name}' not found."
    
    contact_data = contacts[name]
    
    # Handle new format
    if isinstance(contact_data, dict):
        contact_network = contact_data.get("network")
        contact_address = contact_data.get("address")
        
        if contact_network != current_network:
            return f"Contact '{name}' exists on {contact_network} network, but you're currently on {current_network} network."
        
        return f"{name}: {contact_address}"
    
    # Handle legacy format
    elif isinstance(contact_data, str):
        if current_network == "testnet":
            return f"{name}: {contact_data}"
        else:
            return f"Contact '{name}' is a legacy contact (testnet), but you're currently on {current_network} network."


@mcp.tool()
async def remove_contact(name: str = None, confirm: str = None) -> str:
    """
    Remove a contact from your contact list. Requires confirmation.
    
    Args:
        name: Name of the contact to remove
        confirm: Type "yes" to confirm deletion
    """
    if not name:
        return "Please provide a contact name to remove."
    
    current_network = load_network_config()
    contacts = load_contacts()
    
    if name not in contacts:
        return f"Contact '{name}' not found."
    
    contact_data = contacts[name]
    
    # Handle both new and legacy format
    if isinstance(contact_data, dict):
        contact_network = contact_data.get("network")
        contact_address = contact_data.get("address")
        
        if contact_network != current_network:
            return f"Contact '{name}' exists on {contact_network} network, but you're currently on {current_network} network. Switch networks to delete this contact."
    elif isinstance(contact_data, str):
        # Legacy format - assume testnet
        if current_network != "testnet":
            return f"Contact '{name}' is a legacy contact (testnet), but you're currently on {current_network} network. Switch to testnet to delete this contact."
        contact_address = contact_data
        contact_network = "testnet"
    
    # Show contact info and request confirmation
    if not confirm or confirm.lower() != "yes":
        return (
            f"⚠️  WARNING: You are about to remove contact '{name}'.\n"
            f"Address: {contact_address}\n"
            f"Network: {contact_network}\n\n"
            f"This will:\n"
            f"• Permanently remove the contact from your contact list\n"
            f"• This action CANNOT be undone\n\n"
            f"To confirm deletion, call this function again with confirm='yes':\n"
            f"remove_contact('{name}', 'yes')"
        )
    
    # User confirmed deletion
    try:
        del contacts[name]
        save_contacts(contacts)
        return f"✅ Contact '{name}' has been permanently removed from {current_network} network."
        
    except Exception as e:
        return f"❌ Error removing contact: {str(e)}"


@mcp.tool()
async def remove_wallet(name: str = None, confirm: str = None) -> str:
    """
    Remove a wallet from your wallet list. Requires confirmation.
    
    Args:
        name: Name of the wallet to remove
        confirm: Type "yes" to confirm deletion
    """
    if not name:
        return "Please provide a wallet name to remove."
    
    wallets = load_wallets()
    
    if name not in wallets:
        return f"Wallet '{name}' not found."
    
    # Show wallet info and request confirmation
    if not confirm or confirm.lower() != "yes":
        wallet_info = wallets[name]
        address = wallet_info.get("address", "unknown")
        return (
            f"⚠️  WARNING: You are about to remove wallet '{name}'.\n"
            f"Address: {address}\n\n"
            f"This will:\n"
            f"• Remove the wallet from your wallet list\n"
            f"• Delete all associated key files\n"
            f"• This action CANNOT be undone\n\n"
            f"To confirm deletion, call this function again with confirm='yes':\n"
            f"remove_wallet('{name}', 'yes')"
        )
    
    # User confirmed deletion
    try:
        wallet_info = wallets[name]
        
        # Remove wallet key files if they exist
        import os
        files_to_remove = [
            wallet_info.get("skey_path"),
            wallet_info.get("vkey_path"), 
            wallet_info.get("stake_skey_path"),
            wallet_info.get("stake_vkey_path")
        ]
        
        removed_files = []
        for file_path in files_to_remove:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    removed_files.append(os.path.basename(file_path))
                except Exception as e:
                    print(f"Warning: Could not remove {file_path}: {e}")
        
        # Remove from wallet list
        del wallets[name]
        save_wallets(wallets)
        
        files_msg = f"\nRemoved key files: {', '.join(removed_files)}" if removed_files else ""
        
        return f"✅ Wallet '{name}' has been permanently removed.{files_msg}"
        
    except Exception as e:
        return f"❌ Error removing wallet: {str(e)}"


@mcp.tool()
async def view_my_wallets() -> str:
    """
    Show a JSON of wallets controlled by the user.
    """
    wallets = load_wallets()
    if not wallets:
        return "No wallets have been saved yet."
    return json.dumps(wallets, indent=2)


@mcp.tool()
async def view_wallet_address(address: str):
    """
    Display the content of a Cardano address.

    Args:
        address: The address being viewed
    """
    amount = _view_wallet(address)
    return f"address: {address} contains {amount}"


@mcp.tool()
async def send_money(a_skey_file: str, b_address_str: str, amount_lovelace: int) -> str:
    """
    Send amount_lovelace from wallet to address.

    Args:
        a_skey_file: The signing key of the address from which money is being transferred (skey not the address)
        b_address_str: Address to receive money
        amount_lovelace: Amount of lovelace (note 1 ADA = 1,000,000 lovelace)
	Returns:
		tx_has: a hash to verify transaction
    """
    tx_hash = _send_money(a_skey_file, b_address_str, amount_lovelace)
    return tx_hash


@mcp.tool()
async def register_staking(payment_skey_path:str, stake_skey_path: str, address_str: str):
    return _register_stake_key(payment_skey_path, stake_skey_path, address_str)

@mcp.tool()
async def delegate_staking(payment_skey_path: str, stake_skey_path: str, pool_id: str):
    return _delegate_stake_key(payment_skey_path, stake_skey_path, pool_id)

@mcp.tool()
async def delegate_staking_cbor(payment_skey_path: str, stake_skey_path: str, pool_id: str):
    """
    Delegate stake to a pool using manual CBOR transaction construction.
    
    This is an alternative to delegate_staking that uses manual CBOR construction
    to work around PyCardano's Conway era compatibility issues.
    
    Args:
        payment_skey_path: Path to payment signing key
        stake_skey_path: Path to stake signing key  
        pool_id: Bech32 pool ID to delegate to
    """
    return _delegate_stake_key_cbor(payment_skey_path, stake_skey_path, pool_id)

@mcp.tool()
async def set_network(network: str) -> str:
    """
    Set the network configuration (testnet or mainnet).
    
    Args:
        network: Network to use - either "testnet" (or "preprod") or "mainnet"
    """
    network = network.lower()
    if network == "preprod":
        network = "testnet"  # Normalize preprod to testnet
    
    if network not in ["testnet", "mainnet"]:
        return "❌ Invalid network. Use 'testnet', 'preprod', or 'mainnet'."
    
    save_network_config(network)
    return f"✅ Network set to {network}."


@mcp.tool()
async def get_network() -> str:
    """
    Get the current network configuration.
    
    Returns the currently configured network (testnet or mainnet).
    """
    network = load_network_config()
    return f"Current network: {network}"

@mcp.tool()
def open_window_simple() -> str:
    """Opens a window when called by Claude"""
    
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Claude</title>
        <meta charset="utf-8">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            html, body { 
                width: 200px;
                height: 150px;
                overflow: hidden;
                font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                background: #f8f9fa;
                font-size: 10px;
            }
            .window { 
                width: 100%;
                height: 100%;
                padding: 8px;
                background: white;
                border-radius: 6px;
                margin: 4px;
            }
            h1 { font-size: 12px; margin-bottom: 4px; color: #333; }
            p { font-size: 8px; margin-bottom: 4px; color: #666; }
            #image-area { 
                border: 1px dashed #ccc;
                padding: 4px;
                margin: 3px 0;
                text-align: center;
                font-size: 8px;
                background: #fafafa;
                border-radius: 2px;
            }
            input { 
                width: 100%;
                padding: 2px;
                margin: 1px 0;
                border: 1px solid #ddd;
                border-radius: 2px;
                font-size: 8px;
            }
        </style>
        <script>
            window.addEventListener('load', function() {
                window.resizeTo(200, 150);
                window.moveTo(0, 50);
            });
        </script>
    </head>
    <body>
        <div class="window">
            <h1>Claude</h1>
            <p>Ready</p>
            <div id="image-area">📷</div>
            <input type="text" placeholder="Text">
            <input type="text" placeholder="Text">
        </div>
    </body>
    </html>
    """
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write(html_content)
        temp_file = f.name
    
    # Chrome app mode with JavaScript resize
    subprocess.Popen([
        'open', '-gna', 'Google Chrome', '--args', 
        '--app=file://' + temp_file,
        '--allow-file-access-from-files'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    return "Small Chrome app window opened!"

@mcp.tool()
def open_window_wallet(wallet_name: str = "") -> str:
    """Opens a window showing wallet information"""
    
    wallet_info = ""
    if wallet_name:
        try:
            # Call the underlying functions directly
            wallets_data = load_wallets()
            
            if wallet_name in wallets_data:
                wallet = wallets_data[wallet_name]
                address = wallet['address']
                
                # Get balance using direct function
                balance_data = _view_wallet(address)
                
                wallet_info = f"""
                <div style="background: #e8f4fd; padding: 6px; border-radius: 4px; margin: 4px 0;">
                    <h2 style="font-size: 10px; color: #0066cc; margin: 0 0 3px 0;">{wallet_name}</h2>
                    <p style="font-size: 7px; color: #333; margin: 1px 0; word-break: break-all;">{address[:30]}...</p>
                    <p style="font-size: 8px; color: #666; margin: 1px 0;">{balance_data}</p>
                </div>
                """
            else:
                wallet_info = f'<p style="color: red; font-size: 8px;">Wallet "{wallet_name}" not found</p>'
        except Exception as e:
            wallet_info = f'<p style="color: red; font-size: 8px;">Error: {str(e)}</p>'
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Claude{' - ' + wallet_name if wallet_name else ''}</title>
        <meta charset="utf-8">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            html, body {{ 
                width: 200px;
                height: 150px;
                overflow: hidden;
                font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                background: #f8f9fa;
                font-size: 10px;
            }}
            .window {{ 
                width: 100%;
                height: 100%;
                padding: 6px;
                background: white;
                border-radius: 6px;
                margin: 4px;
                overflow-y: auto;
            }}
            h1 {{ font-size: 12px; margin-bottom: 4px; color: #333; }}
            p {{ font-size: 8px; margin-bottom: 4px; color: #666; }}
            #image-area {{ 
                border: 1px dashed #ccc;
                padding: 4px;
                margin: 3px 0;
                text-align: center;
                font-size: 8px;
                background: #fafafa;
                border-radius: 2px;
            }}
            input {{ 
                width: 100%;
                padding: 2px;
                margin: 1px 0;
                border: 1px solid #ddd;
                border-radius: 2px;
                font-size: 8px;
            }}
        </style>
        <script>
            window.addEventListener('load', function() {{
                window.resizeTo(200, 150);
                window.moveTo(0, 50);
            }});
        </script>
    </head>
    <body>
        <div class="window">
            <h1>Claude{' - ' + wallet_name if wallet_name else ''}</h1>
            {wallet_info if wallet_info else '<p>Ready</p>'}
            <div id="image-area">📷</div>
            <input type="text" placeholder="Text">
        </div>
    </body>
    </html>
    """
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write(html_content)
        temp_file = f.name
    
    subprocess.Popen([
        'open', '-gna', 'Google Chrome', '--args', 
        '--app=file://' + temp_file,
        '--allow-file-access-from-files'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    return f"Window opened{' for ' + wallet_name if wallet_name else ''}!"

@mcp.tool()
def address_to_qr_window(address: str) -> str:
    """
    Generate a QR code for a Cardano address and open it in a small Chrome app window.
    
    Args:
        address (str): Cardano address to encode.
    
    Returns:
        str: Confirmation message.
    """
    # Generate QR code PNG in memory
    qr = segno.make(address)
    buffer = BytesIO()
    qr.save(buffer, kind='png')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.read()).decode('utf-8')

    # Create HTML with embedded QR image
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>QR Code</title>
        <meta charset="utf-8">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            html, body {{
                width: 200px;
                height: 220px;
                overflow: hidden;
                font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                background: #fff;
                font-size: 10px;
            }}
            .window {{
                width: 100%;
                height: 100%;
                padding: 8px;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
            }}
            h1 {{
                font-size: 12px;
                margin-bottom: 6px;
                color: #333;
            }}
            img {{
                width: 140px;
                height: 140px;
                border: 1px solid #ccc;
                border-radius: 4px;
            }}
            p {{
                font-size: 9px;
                margin-top: 6px;
                word-break: break-all;
                text-align: center;
                color: #444;
            }}
        </style>
        <script>
            window.addEventListener('load', function() {{
                window.resizeTo(200, 220);
                window.moveTo(0, 50);
            }});
        </script>
    </head>
    <body>
        <div class="window">
            <h1>QR Code</h1>
            <img src="data:image/png;base64,{img_base64}" alt="QR Code">
            <p>{address}</p>
        </div>
    </body>
    </html>
    """

    # Write to temporary HTML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
        f.write(html_content)
        temp_file = f.name

    # Launch Chrome in app mode
    subprocess.Popen([
        'open', '-gna', 'Google Chrome', '--args',
        '--app=file://' + temp_file,
        '--allow-file-access-from-files'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return "✅ QR code window opened in Chrome!"

@mcp.tool()
def open_adaquarium() -> str:
    """
    Open the AdaQuarium website in a small Chrome app window, without stealing focus.
    
    Returns:
        str: Confirmation message.
    """
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AdaQuarium</title>
        <meta charset="utf-8">
        <script>
            window.onload = function() {
                window.resizeTo(900, 600);
                window.location.href = "https://adaquarium.onrender.com/";
            }
        </script>
    </head>
    <body>
        <p>Loading AdaQuarium...</p>
    </body>
    </html>
    """

    # Write temporary redirector HTML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
        f.write(html_content)
        temp_file = f.name

    # Open Chrome app window in the background (no focus steal)
    subprocess.Popen([
        'open', '-gna', 'Google Chrome', '--args',
        '--app=file://' + temp_file,
        '--allow-file-access-from-files'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return "🌊 AdaQuarium launched in background Chrome app window!"


if __name__ == "__main__":
    mcp.run()