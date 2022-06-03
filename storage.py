import secrets
from sha3 import keccak_256
from coincurve import PublicKey
from mnemonic import Mnemonic

def get_pk():
    return PublicKey.from_valid_secret(keccak_256(secrets.token_bytes(32)).digest()).format(compressed=False)[1:]
address = list("0x" + keccak_256(get_pk()).digest()[-20:].hex() for x in range(0,8))
print("\n".join(address))

wl_address = list(
    '0x7f2e41d92f2b46bd419969f7b47893ff83494ce3',
    '0x5c8680d80d09a0ca3f73232fdb2f6a23f31c214c',
    '0x34fd4327af7d6b25a684e3958d5498ab0f4ff7c3',
    '0x1192a2d80286d746b202426004295b688aeb68e1',
    '0xc589c1ed97121ec726d616fa4e4bbf7275e4e00e',
    '0x790a8b45d644cb8865edf034e94b2300642772e0',
    '0x36c080e91d6067fd2dc67eeb4d13a4d943a7a5e4',
    '0xd3e7ada22daff683193a3a8a3a92aa2dc11dadf7',
)