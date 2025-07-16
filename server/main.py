import os
import os
import sys

version = f"{sys.version_info.major}.{sys.version_info.minor}"
pkg_path = os.path.join(os.path.dirname(__file__), "..", "__pypackages__", version, "lib")
sys.path.insert(0, os.path.abspath(pkg_path))
import json
from platformdirs import user_data_dir
from mcp.server.fastmcp import FastMCP

from cardano_utils import _build_address, _view_wallet
import os
import json
from pathlib import Path
from platformdirs import user_data_dir
from mcp.server.fastmcp import FastMCP

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

def load_contacts():
    try:
        with open(CONTACTS_FILE, "r") as f:
            return json.load(f)
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

@mcp.tool()
async def add_contact(name: str = None, address: str = None) -> str:
    if not name:
        return "Please provide a contact name."
    if not address:
        return "Please provide a Cardano address."

    contacts = load_contacts()
    contacts[name] = address
    save_contacts(contacts)
    return f"Contact '{name}' saved successfully."

@mcp.tool()
async def add_wallet(name: str = None) -> str:
    if not name:
        return "Please provide a wallet name."

    wallets = load_wallets()
    if name in wallets:
        return f"A wallet named '{name}' already exists."

    try:
        # 🔨 Call your address builder (should save skey/vkey inside DATA_DIR)
        wallet_info = _build_address(name, output_dir=DATA_DIR)

        wallets[name] = {
            "address": wallet_info["address"],
            "skey_path": wallet_info["skey_path"],
            "vkey_path": wallet_info["vkey_path"]
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
    contacts = load_contacts()
    if not contacts:
        return "No contacts have been saved yet."
    return "\n".join([f"{name}: {addr}" for name, addr in contacts.items()])

@mcp.tool()
async def view_my_wallets() -> str:
    wallets = load_wallets()
    if not wallets:
        return "No wallets have been saved yet."
    return json.dumps(wallets, indent=2)

@mcp.tool()
async def view_wallet_address(address: str):
     amount = _view_wallet(address)
     return f"address: {address} contains {amount}"

if __name__ == "__main__":
	mcp.run()
