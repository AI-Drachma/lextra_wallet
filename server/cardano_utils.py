import os
import requests
from pathlib import Path
from pycardano import *

# === CONFIG ===
PROXY_URL = "https://nova-wallet-proxy.onrender.com/blockfrost"
PROXY_TOKEN = None  # Set if your proxy requires x-api-token

HEADERS = {"x-api-token": PROXY_TOKEN} if PROXY_TOKEN else {}

class ProxiedBlockfrostContext(BlockFrostChainContext):
    def __init__(self):
        super().__init__(
            project_id="not_used",  # Required by pycardano
            base_url=PROXY_URL
        )
        self._session.headers.update(HEADERS)

# === VIEW WALLET ===
def _view_wallet(address):
    address = "addr_test1vqnv2652dhpa0des2qku68psmg79xlxtvmrnr3gj657a9eck8t39z"
    print(f"\nBalance for {address}:")
    try:
        url = f"{PROXY_URL}/addresses/{address}"
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        info = response.json()

        lines = [
            f"- {amt['quantity']} {amt['unit']}"
            for amt in info.get("amount", [])
        ]
        return "\n".join(lines) if lines else "No funds found."

    except requests.exceptions.HTTPError as e:
        return f"HTTP error: {e.response.status_code} {e.response.text}"
    except Exception as e:
        return f"Error: {e}"

# === SEND MONEY ===
def _send_money(a_skey_file, b_address_str, amount_lovelace):
    sk = PaymentSigningKey.load(Path(a_skey_file))
    to_address = Address.from_primitive(b_address_str)
    ctx = ProxiedBlockfrostContext()
    builder = TransactionBuilder(ctx)

    from_address = Address(
        payment_part=sk.to_verification_key().hash(),
        network=Network.TESTNET
    )

    builder.add_input_address(from_address)
    builder.add_output(TransactionOutput(to_address, amount_lovelace))
    signed_tx = builder.build_and_sign([sk], change_address=from_address)

    tx_hash = ctx.submit_tx(signed_tx)
    print(f"✅ Transaction submitted: {tx_hash}")
    return tx_hash

def _build_address(name, output_dir):
    skey_path = os.path.join(output_dir, f"{name}.skey")
    vkey_path = os.path.join(output_dir, f"{name}.vkey")

    sk = PaymentSigningKey.generate()
    vk = sk.to_verification_key()

    sk.save(skey_path)
    vk.save(vkey_path)

    addr = Address(payment_part=vk.hash(), network=Network.TESTNET)

    return {
        "address": str(addr),
        "skey_path": skey_path,
        "vkey_path": vkey_path
    }


# === MAIN ===
if __name__ == '__main__':
    print(_view_wallet())

    # Example usage:
    # _send_money("alice.skey", "addr_test1q...", 1_000_000)