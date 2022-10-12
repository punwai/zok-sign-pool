import hashlib

from zokrates_pycrypto.eddsa import PrivateKey, PublicKey, Point
from zokrates_pycrypto.field import FQ
from zokrates_pycrypto.utils import write_signature_for_zokrates_cli
from bitstring import BitArray

class MerkleTree:
    def __init__(self, leaves, height):
        # Create an empty merkle tree
        x = 0
        self.elements = [x.to_bytes(32, 'big')] * (2 ** height - 1)
        self.height = height
        self.num_leaves = len(leaves)

        # Assign leaves
        STARTING_INDEX = 2 ** (height - 1) - 1
        for i in range(len(leaves)):
            self.elements[STARTING_INDEX + i] = leaves[i]
        for i in range(2 ** (height - 1) - 2, -1, -1):
            self.elements[i] = hashlib.sha256(self.elements[i * 2 + 1] + self.elements[i * 2 + 2]).digest()

    def merkle_root(self):
        return self.elements[0]

    def merkle_path(self, index):
        print("PRINTING MERKLE PATH FOR INDEX {}".format(index))
        STARTING_INDEX = 2 ** (self.height - 1) - 1
        tree_index = STARTING_INDEX + index
        path = []
        while tree_index:
            if tree_index % 2 == 0:
                path.append(self.elements[tree_index - 1])
                print(self.elements[tree_index - 1].hex())
            else:
                path.append(self.elements[tree_index + 1])
                print(self.elements[tree_index + 1].hex())
            tree_index = int((tree_index + 1) / 2) - 1
        return path

    def element(self, index):
        print("Hello World")

def generate_pk_and_sigs(n, msg):
    pks_and_sigs = []
    for i in range(1, n + 1):
        key = FQ(i)
        sk = PrivateKey(key)
        pk = PublicKey.from_private(sk)
        sig = sk.sign(msg)
        pks_and_sigs.append((pk, sig))
    return pks_and_sigs

def hash_pk(pk):
    flattened_pk = pk[0][0].__int__().to_bytes(32, 'big') + pk[0][1].__int__().to_bytes(32, 'big')
    hash = hashlib.sha256(flattened_pk).digest()
    print(flattened_pk.hex())
    print(hash.hex())
    return hash

def bytes_to_32_num(bytes):
    idx = 0
    chunks = []
    while idx < len(bytes):
        chunk_bytes = bytes[idx: idx+4]
        chunk_val = int.from_bytes(chunk_bytes, "big")
        chunks.append(str(chunk_val))
        idx += 4 
    return " ".join(chunks)

if __name__ == "__main__":
    print("GENERATING TEST PUBLIC INPUTS ...")

    msg = hashlib.sha512().digest()

    pks_and_sigs = generate_pk_and_sigs(5, msg)
    leaves = list(map(lambda pair: hash_pk(pair[0]), pks_and_sigs))

    mt = MerkleTree(leaves, 4)

    # Pick 3 of the public keys/signature pairs

    selected_indexes = [0, 1, 2]
    selected = list(map(lambda ix: pks_and_sigs[ix], selected_indexes))
    selected_leaves = list(map(lambda ix: leaves[ix], selected_indexes))

    print(selected_leaves[0].hex())

    # 1. Merkle Path
    # private field[N][2] R, private field[N] S, private field[N][2] A, private u32[N][PathLength][8] merkle_paths, private u32[N] merkle_indices, u32[8] M0, u32[8] M1, u32[8] root
    args = ""

    # Print all the signatures as field
    # Print R
    args += " ".join(list(map(lambda s: str(s[1][0].x) + " " + str(s[1][0].y), selected)))
    # Print s
    args += " " + " ".join(list(map(lambda s: str(s[1][1]), selected)))
    # Print public keys as field
    args += " " + " ".join(list(map(lambda s: str(s[0].p.x) + " " + str(s[0].p.y), selected)))
    # Print merkle_paths. Group bytes by 4, and then print each of them in the merkle_path

    for idx in selected_indexes:
        args += " " + " ".join(list(map(bytes_to_32_num, mt.merkle_path(idx))))

    # Print indices
    args += " " + " ".join(list(map(str, selected_indexes)))

    # Print M0, M1, 
    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]

    args += " " + bytes_to_32_num(bytes.fromhex(M0))
    args += " " + bytes_to_32_num(bytes.fromhex(M1))

    # Print root
    print(mt.merkle_root().hex())
    args += " " + bytes_to_32_num(mt.merkle_root())

    path = "zokrates_inputs.txt"
    with open(path, "w+") as file:
        for l in args:
            file.write(l)
    print("#### SUCCESS ####")