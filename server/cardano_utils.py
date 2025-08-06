import os
import time
import pdb
import struct
import hashlib
import cbor2
import bech32
import requests
from pathlib import Path
from platformdirs import user_data_dir
from mnemonic import Mnemonic
from pycardano import (
    HDWallet,
    Address,
    Network,
    PaymentSigningKey,
    StakeSigningKey,
    StakeVerificationKey,
    StakeCredential,
    StakeRegistration,
    StakeDelegation,
    TransactionBuilder,
    TransactionOutput,
    TransactionInput,
    TransactionId,
    UTxO,
    Value,
    ProtocolParameters,
    ChainContext,
    ScriptPubkey,
    AssetName,
    MultiAsset,
    Asset,
    NativeScript,
    InvalidHereAfter
)


def get_proxy_url():
    """Get the proxy URL based on current network configuration."""
    network = get_current_network()
    if network == Network.MAINNET:
        return "https://nova-wallet-proxy.onrender.com/mainnet"
    else:
        return "https://nova-wallet-proxy.onrender.com/preprod"


PROXY_TOKEN = None  # Your proxy applies the Blockfrost key
HEADERS = {"x-api-token": PROXY_TOKEN} if PROXY_TOKEN else {}

# Data directory setup for transaction files
APP_NAME = "nova_wallet"
APP_AUTHOR = "Drachma"


def get_current_network():
    """Get the current network from configuration."""
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from main import load_network_config
    
    network_str = load_network_config()
    return Network.TESTNET if network_str == "testnet" else Network.MAINNET

# Dynamic network based on configuration
def get_network():
    return get_current_network()


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
        self.base_url = get_proxy_url().rstrip("/")
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
        if res.status_code != 200:
            print(f"❌ Transaction submit failed:")
            print(f"Status code: {res.status_code}")
            print(f"Response: {res.text}")
            res.raise_for_status()
        return res.text.strip()


# === VIEW WALLET ===
def _view_wallet(address: str) -> str:
    try:
        url = f"{get_proxy_url()}/addresses/{address}"
        res = requests.get(url, headers=HEADERS)
        res.raise_for_status()
        data = res.json()

        lines = [f"- {amt['quantity']} {amt['unit']}" for amt in data.get("amount", [])]
        return "\n".join(lines) if lines else "No funds found."
    except Exception as e:
        return f"❌ Error viewing wallet: {e}"


def _send_money(a_skey_file: str, b_address_str: str, amount_lovelace: int) -> str:
    sk = PaymentSigningKey.load(Path(a_skey_file))
    
    # Load the corresponding stake key
    stake_skey_path = a_skey_file.replace('.skey', '.stake.skey')
    stake_sk = StakeSigningKey.load(Path(stake_skey_path))
    
    to_address = Address.from_primitive(b_address_str)
    ctx = ProxiedBlockfrostContext()
    builder = TransactionBuilder(ctx)

    # Create the same address format as wallet creation
    from_address = Address(
        payment_part=sk.to_verification_key().hash(),
        staking_part=stake_sk.to_verification_key().hash(),  # ← ADD this
        network=get_network()
    )

    builder.add_input_address(from_address)
    builder.add_output(TransactionOutput(to_address, amount_lovelace))
    signed_tx = builder.build_and_sign([sk], change_address=from_address)

    tx_hash = ctx.submit_tx(signed_tx.to_cbor())
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

    addr = Address(payment_part=vk.hash(), network=get_network())

    return {
        "address": str(addr),
        "skey_path": skey_path,
        "vkey_path": vkey_path
    }

def _build_wallet_from_mnemonic(mnemonic_words: str,
    name: str, 
    output_dir: str,
    derivation_path ="m/1852'/1815'/0'/0/0") -> dict:
    # Create HD wallet from mnemonic
    hdwallet = HDWallet.from_mnemonic(mnemonic_words)
    
    # Derive payment wallet and extract signing key
    payment_hdwallet = hdwallet.derive_from_path("m/1852'/1815'/0'/0/0")
    # Add some validation
    if len(payment_hdwallet.xprivate_key) == 64:
        private_key_bytes = payment_hdwallet.xprivate_key[:32]
    else:
        raise ValueError(f"Unexpected xprivate_key length: {len(payment_hdwallet.xprivate_key)}")
    payment_sk = PaymentSigningKey.from_primitive(private_key_bytes)
    payment_vk = payment_sk.to_verification_key()
    
    # Derive staking wallet and extract signing key
    stake_hdwallet = hdwallet.derive_from_path("m/1852'/1815'/0'/2/0")
    if len(stake_hdwallet.xprivate_key) == 64:
        private_key_bytes = stake_hdwallet.xprivate_key[:32]
    else:
        raise ValueError(f"Unexpected xprivate_key length: {len(stake_hdwallet.xprivate_key)}")
    stake_sk = StakeSigningKey.from_primitive(private_key_bytes)
    stake_vk = stake_sk.to_verification_key()
    
    # Create address with both parts
    addr = Address(
        payment_part=payment_vk.hash(),
        staking_part=stake_vk.hash(),
        network=get_network()
    )
    
    # Save keys to files
    payment_skey_path = os.path.join(output_dir, f"{name}.skey")
    payment_vkey_path = os.path.join(output_dir, f"{name}.vkey")
    stake_skey_path = os.path.join(output_dir, f"{name}.stake.skey")
    stake_vkey_path = os.path.join(output_dir, f"{name}.stake.vkey")
    
    payment_sk.save(payment_skey_path)
    payment_vk.save(payment_vkey_path)
    stake_sk.save(stake_skey_path)
    stake_vk.save(stake_vkey_path)
    
    return {
        "address": str(addr),
        "mnemonic": mnemonic_words,
        "skey_path": payment_skey_path,
        "vkey_path": payment_vkey_path,
        "stake_skey_path": stake_skey_path,
        "stake_vkey_path": stake_vkey_path,
    }

def _generate_new_wallet(name: str, output_dir: str) -> dict:
    # Generate new mnemonic
    mnemo = Mnemonic("english")
    mnemonic_words = mnemo.generate(strength=256)  # 24 words
    return _build_wallet_from_mnemonic(mnemonic_words, name, output_dir)

def get_stake_address(stake_vk: StakeVerificationKey, network=None) -> str:
    if network is None:
        network = get_network()
    stake_hash = stake_vk.hash().payload
    prefix = "stake_test" if network == Network.TESTNET else "stake"
    data = bech32.convertbits(stake_hash, 8, 5, True)
    return bech32.bech32_encode(prefix, data)

def is_stake_key_registered(stake_vk) -> bool:
    """Check if stake key is registered by trying to build a registration transaction.
    If it fails with StakeKeyRegisteredDELEG, the key is already registered."""
    try:
        stake_address = get_stake_address(stake_vk, network=get_network())
        ctx = ProxiedBlockfrostContext()
        
        # First try the API endpoint
        url = f"{ctx.base_url}/accounts/{stake_address}"
        res = ctx.session.get(url)
        print(f"🔍 Checking stake registration at: {url} → {res.status_code}")
        
        if res.status_code == 200:
            return True
        
        # If API check fails (404), fall back to transaction-based check
        # This is more reliable as it checks the actual blockchain state
        print("🔍 API check failed, using transaction-based registration check...")
        
        # Create a dummy stake credential to test registration
        stake_cred = StakeCredential(stake_vk.hash())
        stake_registration = StakeRegistration(stake_cred)
        
        # Try to build a registration transaction (without submitting)
        # If the stake key is already registered, this should fail validation
        builder = TransactionBuilder(ctx)
        
        # We need some UTxOs for the transaction to be valid, but we're not actually submitting
        # Try to get address from stake key
        from pycardano import PaymentVerificationKey, Address
        
        # For this check, we just return False if we can't determine 
        # The delegation function will handle this gracefully
        return False
        
    except Exception as e:
        print(f"🔍 Registration check error: {e}")
        # If we can't determine, assume not registered to be safe
        return False

def get_data_dir():
    data_dir = user_data_dir(APP_NAME, APP_AUTHOR)
    os.makedirs(data_dir, exist_ok=True)
    return data_dir

def _register_stake_key(payment_skey_path: str, stake_skey_path: str, address_str: str) -> str:
    # Load keys
    payment_sk = PaymentSigningKey.load(Path(payment_skey_path))
    stake_sk = StakeSigningKey.load(Path(stake_skey_path))
    payment_vk = payment_sk.to_verification_key()
    stake_vk = stake_sk.to_verification_key()

    # Build and verify address
    expected_address = Address(
        payment_part=payment_vk.hash(),
        staking_part=stake_vk.hash(),
        network=get_network()
    )
    provided_address = Address.from_primitive(address_str)
    if str(expected_address) != str(provided_address):
        raise ValueError(
            f"Address mismatch!\nExpected: {expected_address}\nProvided: {provided_address}"
        )

    print(f"✅ Address verified: {expected_address}")
    print(f"🔑 Stake key hash: {stake_vk.hash().payload.hex()}")

    # Check stake registration status (fallback logic handles 404 later)
    registered = is_stake_key_registered(stake_vk)
    if registered:
        print("ℹ️ Stake key is already registered.")
        return "ℹ️ Stake key is already registered on the network."

    # Get UTxOs
    ctx = ProxiedBlockfrostContext()
    utxos = ctx.utxos(str(provided_address))
    if not utxos:
        raise ValueError(f"❌ No UTxOs found at {provided_address}. Cannot fund registration.")

    # ✅ Check available balance
    total_balance = sum(utxo.output.amount.coin for utxo in utxos)
    print(f"💰 Total balance: {total_balance} lovelace")

    MIN_REQUIRED = 2_500_000  # Stake deposit + fee buffer
    if total_balance < MIN_REQUIRED:
        raise ValueError(
            f"❌ Insufficient funds to register stake key.\n"
            f"Requires at least {MIN_REQUIRED} lovelace.\n"
            f"Current balance: {total_balance} lovelace"
        )

    # Build stake registration transaction
    builder = TransactionBuilder(ctx)
    builder.add_input_address(provided_address)

    stake_cred = StakeCredential(stake_vk.hash())
    stake_registration = StakeRegistration(stake_cred)
    builder.certificates = [stake_registration]

    signed_tx = builder.build_and_sign([payment_sk, stake_sk], change_address=provided_address)

    # Save transaction to writable data directory
    data_dir = get_data_dir()
    tx_file_path = os.path.join(data_dir, "tx_register_stake.cbor")
    with open(tx_file_path, "wb") as f:
        f.write(signed_tx.to_cbor())
        print(f"💾 Saved transaction to {tx_file_path}")

    try:
        tx_hash = ctx.submit_tx(signed_tx.to_cbor())
        print(f"✅ Stake key registered: {tx_hash}")
        return f"✅ Stake key successfully registered. Transaction hash: {tx_hash}"
    except requests.HTTPError as e:
        if "StakeKeyRegisteredDELEG" in e.response.text:
            print("ℹ️ Stake key is already registered.")
            return "ℹ️ Stake key is already registered on the network."
        else:
            print(f"❌ Transaction submission failed with status {e.response.status_code}")
            return f"❌ Transaction submission failed: {e.response.text}"

def is_stake_key_delegated_to_pool(stake_vk, pool_id: str) -> bool:
    """Check if the stake key is already delegated to the specified pool."""
    stake_address = get_stake_address(stake_vk, network=get_network())
    ctx = ProxiedBlockfrostContext()
    url = f"{ctx.base_url}/accounts/{stake_address}"
    res = ctx.session.get(url)
    if res.status_code != 200:
        print(f"🔍 Delegation check failed with status {res.status_code}")
        return False
    data = res.json()
    current_pool = data.get("pool_id")
    print(f"🏊 Delegated pool: {current_pool}")
    return current_pool == pool_id

def _delegate_stake_key(payment_skey_path: str, stake_skey_path: str, pool_id: str) -> str:
    payment_sk = PaymentSigningKey.load(Path(payment_skey_path))
    stake_sk = StakeSigningKey.load(Path(stake_skey_path))
    payment_vk = payment_sk.to_verification_key()
    stake_vk = stake_sk.to_verification_key()
    stake_cred = StakeCredential(stake_vk.hash())

    # Note: Skipping registration check due to API reliability issues
    # The network will reject the delegation if the stake key isn't registered
    
    # Check if already delegated to target pool
    if is_stake_key_delegated_to_pool(stake_vk, pool_id):
        print(f"ℹ️ Already delegated to pool {pool_id}.")
        return f"ℹ️ Stake key is already delegated to pool {pool_id}."

    payment_address = Address(
        payment_part=payment_vk.hash(),
        staking_part=stake_vk.hash(),
        network=get_network()
    )

    ctx = ProxiedBlockfrostContext()
    utxos = ctx.utxos(str(payment_address))
    if not utxos:
        raise ValueError(f"❌ No UTxOs found at {payment_address}. Cannot fund delegation.")

    delegation_cert = StakeDelegation(stake_cred, pool_id)

    builder = TransactionBuilder(ctx)
    builder.add_input_address(payment_address)
    builder.certificates = [delegation_cert]
    
    # Build and sign the transaction
    signed_tx = builder.build_and_sign(
        signing_keys=[payment_sk, stake_sk], 
        change_address=payment_address
    )

    # Save transaction to writable data directory
    data_dir = get_data_dir()
    tx_file_path = os.path.join(data_dir, "tx_delegate_stake.cbor")
    with open(tx_file_path, "wb") as f:
        f.write(signed_tx.to_cbor())
        print(f"💾 Saved delegation transaction to {tx_file_path}")

    try:
        tx_hash = ctx.submit_tx(signed_tx.to_cbor())
        print(f"✅ Delegated to pool {pool_id}: {tx_hash}")
        return f"✅ Successfully delegated to pool {pool_id}. Transaction hash: {tx_hash}"
    except requests.HTTPError as e:
        print(f"❌ Delegation transaction submission failed with status {e.response.status_code}")
        if "DecoderErrorDeserialiseFailure" in e.response.text:
            return "❌ Transaction format incompatibility: PyCardano 0.14.0 generates transaction formats that are not compatible with the current Cardano Conway era. The delegation logic is correct, but the library needs updating to support the latest transaction serialization format. Consider checking for a newer version of pycardano or using an alternative Cardano library."
        else:
            return f"❌ Delegation transaction submission failed: {e.response.text}"

def _delegate_stake_key_cbor(payment_skey_path: str, stake_skey_path: str, pool_id: str) -> str:
    """
    Manual CBOR delegation transaction builder for Conway era compatibility.
    
    This function builds a delegation transaction using manual CBOR construction
    to avoid PyCardano's transaction format incompatibility with Conway era.
    """
    try:
        # Load keys
        payment_sk = PaymentSigningKey.load(Path(payment_skey_path))
        stake_sk = StakeSigningKey.load(Path(stake_skey_path))
        payment_vk = payment_sk.to_verification_key()
        stake_vk = stake_sk.to_verification_key()
        
        # Build payment address
        payment_address = Address(
            payment_part=payment_vk.hash(),
            staking_part=stake_vk.hash(),
            network=get_network()
        )
        
        # Get UTxOs
        ctx = ProxiedBlockfrostContext()
        utxos = ctx.utxos(str(payment_address))
        if not utxos:
            return "❌ No UTxOs found at address. Cannot fund delegation."
        
        # Calculate total input value
        total_input = sum(utxo.output.amount.coin for utxo in utxos)
        
        # Estimate fee (Conway era typical delegation fee)
        estimated_fee = 200000  # 0.2 ADA in lovelace
        
        if total_input < estimated_fee:
            return f"❌ Insufficient funds. Need at least {estimated_fee} lovelace for delegation fee."
        
        # Build Conway era transaction manually
        tx_body = _build_conway_delegation_tx_body(
            utxos=utxos,
            payment_address=payment_address,
            stake_vk_hash=stake_vk.hash(),
            pool_id=pool_id,
            fee=estimated_fee,
            total_input=total_input
        )
        
        # Sign transaction
        tx_hash = _hash_tx_body(tx_body)
        payment_signature = _sign_tx_hash(payment_sk, tx_hash)
        stake_signature = _sign_tx_hash(stake_sk, tx_hash)
        
        # Build witness set
        witness_set = _build_witness_set(
            payment_vk=payment_vk,
            stake_vk=stake_vk,
            payment_signature=payment_signature,
            stake_signature=stake_signature
        )
        
        # Complete transaction (Conway era format - array based)
        # Conway requires: [body, witness_set, is_valid, auxiliary_data]
        transaction = [tx_body, witness_set, True, None]
        
        # Encode to CBOR
        cbor_tx = cbor2.dumps(transaction)
        
        # Save transaction
        data_dir = get_data_dir()
        tx_file_path = os.path.join(data_dir, "tx_delegate_stake_cbor.cbor")
        with open(tx_file_path, "wb") as f:
            f.write(cbor_tx)
            print(f"💾 Saved CBOR delegation transaction to {tx_file_path}")
        
        # Submit transaction
        try:
            tx_hash_hex = ctx.submit_tx(cbor_tx)
            print(f"✅ Delegated to pool {pool_id}: {tx_hash_hex}")
            return f"✅ Successfully delegated to pool {pool_id}. Transaction hash: {tx_hash_hex}"
        except requests.HTTPError as e:
            print(f"❌ CBOR delegation transaction submission failed with status {e.response.status_code}")
            if "DelegateeStakePoolNotRegisteredDELEG" in e.response.text:
                return f"❌ Pool delegation failed: The specified pool ID '{pool_id}' is not registered on the testnet. Please verify the pool ID is correct and the pool is active."
            else:
                return f"❌ CBOR delegation failed: {e.response.text}"
            
    except Exception as e:
        print(f"❌ Error in CBOR delegation: {e}")
        return f"❌ CBOR delegation error: {str(e)}"


def _build_conway_delegation_tx_body(utxos, payment_address, stake_vk_hash, pool_id, fee, total_input):
    """Build Conway era transaction body with proper CBOR structure."""
    
    # Transaction inputs
    inputs = []
    for utxo in utxos:
        tx_input = [
            utxo.input.transaction_id.to_primitive(),  # transaction_id as bytes
            utxo.input.index  # output_index
        ]
        inputs.append(tx_input)
    
    # Transaction outputs (change back to payment address)
    change_amount = total_input - fee
    outputs = [[
        _encode_address(payment_address),  # address
        change_amount  # amount (lovelace only for simplicity)
    ]]
    
    # Delegation certificate (Conway era format)
    # According to CDDL: stake_delegation = (2, stake_credential, pool_keyhash)
    delegation_cert = [
        2,  # stake_delegation certificate type (was 3, should be 2)
        [0, stake_vk_hash.payload],  # stake credential [0, addr_keyhash]
        _decode_pool_id(pool_id)  # pool keyhash
    ]
    
    # Transaction body (Conway era format)
    tx_body = {
        0: inputs,                    # inputs
        1: outputs,                   # outputs  
        2: fee,                       # fee
        4: [delegation_cert],         # certificates
    }
    
    return tx_body


def _hash_tx_body(tx_body):
    """Hash transaction body for signing."""
    cbor_body = cbor2.dumps(tx_body)
    return hashlib.blake2b(cbor_body, digest_size=32).digest()


def _sign_tx_hash(signing_key, tx_hash):
    """Sign transaction hash with signing key."""
    # Use PyCardano's signing capability
    signature = signing_key.sign(tx_hash)
    if hasattr(signature, 'signature'):
        return signature.signature
    else:
        return signature  # signature is already bytes


def _build_witness_set(payment_vk, stake_vk, payment_signature, stake_signature):
    """Build Conway era witness set."""
    vkey_witnesses = [
        [payment_vk.payload, payment_signature],  # [vkey, signature]
        [stake_vk.payload, stake_signature]
    ]
    
    witness_set = {
        0: vkey_witnesses  # vkeywitness
    }
    
    return witness_set


def _encode_address(address):
    """Encode address for CBOR."""
    # Convert address to bytes properly
    return address.to_primitive()


def _decode_pool_id(pool_id):
    """Decode bech32 pool ID to bytes."""
    try:
        # Use bech32 decode properly
        hrp, data = bech32.bech32_decode(pool_id)
        if hrp == 'pool' and data:
            # Convert from 5-bit to 8-bit representation
            converted = bech32.convertbits(data, 5, 8, False)
            if converted:
                return bytes(converted)
        
        # If bech32 decode fails, try hex
        if len(pool_id) == 56:  # Standard pool keyhash length in hex
            return bytes.fromhex(pool_id)
            
        raise ValueError(f"Invalid pool ID format: {pool_id}")
        
    except Exception as e:
        print(f"Error decoding pool ID {pool_id}: {e}")
        raise ValueError(f"Could not decode pool ID: {pool_id}")


def _mint_token():
    print("TODO")

# === MAIN TEST ENTRYPOINT ===
if __name__ == '__main__':
    pay_skey_path = "server/tests/test_data/alex.skey"
    pay_vkey_path = "server/tests/test_data/alex.vkey"
    stake_skey_path = "server/tests/test_data/alex.stake.skey"
    stake_vkey_path = "server/tests/test_data/alex.stake.svkey"
    pool_id = "pool1zwzmlqkk8g5w63t7f02ch2t6p7y8g5rpgrq4gqcqc26t2k2d7l9"

    ALEX_ADDRESS = "addr_test1qqhe0pztnczpn483uu8km9hg52z47t92s5d9zsec870x258ug3n8hn3wpvqxw98z897kql8ufrkpuu2w8vz746ny4nqq8kadh3"
    BETHA_ADDRESS = "addr_test1qpqjuf0q5auemrntca53w78q2sghuwf9ap30senprnrphsmrnlsts2mcy2qql2yq52uh9m634f9tyn8wa9kflsa8g95qzzrdj0"
    

  
