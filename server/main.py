import os
import sys

version = f"{sys.version_info.major}.{sys.version_info.minor}"

# Try multiple possible locations for __pypackages__ for portability
current_dir = os.path.dirname(__file__)
possible_paths = [
    # Development structure: nova_wallet/server/main.py and nova_wallet/__pypackages__/
    os.path.join(current_dir, "..", "__pypackages__", version, "lib"),
    # Deployed structure: both server/ and __pypackages__/ at same level
    os.path.join(current_dir, "..", "..", "__pypackages__", version, "lib"),
    # Fallback: check if __pypackages__ is in current directory
    os.path.join(current_dir, "__pypackages__", version, "lib"),
]

pkg_path = None
for path in possible_paths:
    if os.path.exists(path):
        pkg_path = os.path.abspath(path)
        break

if pkg_path:
    sys.path.insert(0, pkg_path)
else:
    # If no __pypackages__ found, print warning but continue
    print(f"Warning: __pypackages__ not found in expected locations. Falling back to system packages.")


import json
from pathlib import Path
from platformdirs import user_data_dir
from mcp.server.fastmcp import FastMCP

from cardano_utils import (
    _build_address,
     _view_wallet,
    _send_money,
    _generate_new_wallet,
    _delegate_stake_key,
    _delegate_stake_key_cbor,
    _register_stake_key
    )


mcp = FastMCP("nova-wallet")

# 🔐 Define secure writable paths
APP_NAME = "nova_wallet"
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



if __name__ == "__main__":
    mcp.run()