import os
import requests
from pathlib import Path
from pycardano import (
    Address,
    Network,
    PaymentSigningKey,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
    ProtocolParameters,
    ChainContext
)

# === CONFIG ===
PROXY_URL = "https://nova-wallet-proxy.onrender.com/blockfrost"
PROXY_TOKEN = None  # Your proxy applies the Blockfrost key

HEADERS = {"x-api-token": PROXY_TOKEN} if PROXY_TOKEN else {}


from pycardano import UTxO, TransactionInput, TransactionOutput, Value

from pycardano import TransactionId

def blockfrost_utxo_to_pycardano(utxo_json):
    input = TransactionInput(
        TransactionId.from_primitive(utxo_json["tx_hash"]),  # ✅ wrap here
        utxo_json["output_index"]
    )
    amount = sum(
        int(a["quantity"]) for a in utxo_json["amount"] if a["unit"] == "lovelace"
    )
    output = TransactionOutput(
        utxo_json["address"],
        Value(amount)
    )
    return UTxO(input, output)

# === CHAIN CONTEXT ===
class ProxiedBlockfrostContext(ChainContext):
    def __init__(self):
        self.base_url = PROXY_URL.rstrip("/")
        self.session = requests.Session()
        if HEADERS:
            self.session.headers.update(HEADERS)

    def utxos(self, address):
        res = self.session.get(f"{self.base_url}/addresses/{address}/utxos")
        res.raise_for_status()
        return [blockfrost_utxo_to_pycardano(utxo) for utxo in res.json()]

    @property
    def protocol_param(self):
        res = self.session.get(f"{self.base_url}/epochs/latest/parameters")
        res.raise_for_status()
        raw = res.json()

        return ProtocolParameters(
            min_fee_constant=int(raw["min_fee_b"]),
            min_fee_coefficient=int(raw["min_fee_a"]),
            max_block_header_size=int(raw["max_block_header_size"]),
            max_block_size=int(raw["max_block_size"]),
            max_tx_size=int(raw["max_tx_size"]),
            key_deposit=int(raw["key_deposit"]),
            pool_deposit=int(raw["pool_deposit"]),
            pool_influence=float(raw["a0"]),
            monetary_expansion=float(raw["rho"]),
            treasury_expansion=float(raw["tau"]),
            decentralization_param=float(raw["decentralisation_param"]),
            extra_entropy=None,
            protocol_major_version=int(raw["protocol_major_ver"]),
            protocol_minor_version=int(raw["protocol_minor_ver"]),
            min_utxo=int(raw["min_utxo"]),
            min_pool_cost=int(raw["min_pool_cost"]),
            price_mem=float(raw["price_mem"]),
            price_step=float(raw["price_step"]),
            max_tx_ex_mem=int(raw["max_tx_ex_mem"]),
            max_tx_ex_steps=int(raw["max_tx_ex_steps"]),
            max_block_ex_mem=int(raw["max_block_ex_mem"]),
            max_block_ex_steps=int(raw["max_block_ex_steps"]),
            max_val_size=int(raw["max_val_size"]),
            collateral_percent=int(raw["collateral_percent"]),
            max_collateral_inputs=int(raw["max_collateral_inputs"]),
            coins_per_utxo_word=int(raw["coins_per_utxo_size"]),  # 🔁 matches your version
            coins_per_utxo_byte=int(raw["coins_per_utxo_size"]),
            cost_models=raw["cost_models"]
        )

    def submit_tx(self, cbor_bytes: bytes) -> str:
        res = self.session.post(
            f"{self.base_url}/tx/submit",
            headers={"Content-Type": "application/cbor"},
            data=cbor_bytes
        )
        res.raise_for_status()
        return res.text.strip()


# === VIEW WALLET ===
def _view_wallet(address: str) -> str:
    try:
        url = f"{PROXY_URL}/addresses/{address}"
        res = requests.get(url, headers=HEADERS)
        res.raise_for_status()
        data = res.json()

        lines = [f"- {amt['quantity']} {amt['unit']}" for amt in data.get("amount", [])]
        return "\n".join(lines) if lines else "No funds found."
    except Exception as e:
        return f"❌ Error viewing wallet: {e}"


# === SEND MONEY ===
def _send_money(a_skey_file: str, b_address_str: str, amount_lovelace: int) -> str:
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

    tx_hash = ctx.submit_tx(signed_tx.to_cbor())  # 👈 this is the fix
    print(f"✅ Transaction submitted: {tx_hash}")
    return tx_hash


# === ADDRESS GENERATION ===
def _build_address(name: str, output_dir: str) -> dict:
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


# === MAIN TEST ENTRYPOINT ===
if __name__ == '__main__':
    skey = "/Users/maxhighsmith/Library/Application Support/nova_wallet/max.skey"
    b_addr = "addr_test1vqnv2652dhpa0des2qku68psmg79xlxtvmrnr3gj657a9eck8t39z"
    ada = 5_000_000
    print(_view_wallet(b_addr))
    print(_send_money(skey, b_addr, ada))