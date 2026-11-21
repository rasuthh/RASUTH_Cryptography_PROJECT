
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PathORAM:
    """Small educational Path ORAM model with encrypted data blocks."""

    def __init__(self, blocks, bucket_size=4, tree_depth=3, key=None):
        if not blocks:
            raise ValueError("At least one data block is required.")
        if bucket_size < 1 or tree_depth < 1:
            raise ValueError("Bucket size and tree depth must be positive.")

        self.bucket_size = bucket_size
        self.depth = tree_depth
        self.leaf_count = 2 ** tree_depth
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.cipher = AESGCM(self.key)
        self.position_map = {}
        self.tree = {self._node(0, i): [] for i in range(2 ** (tree_depth + 1) - 1)}
        self.stash = []
        self.access_log = []

        for block_id, value in blocks.items():
            if not isinstance(value, bytes):
                raise ValueError("All block values must be bytes.")
            leaf = secrets.randbelow(self.leaf_count)
            self.position_map[block_id] = leaf
            self.stash.append(self._make_entry(block_id, leaf, value))

        self._evict_path(0)

    def _node(self, depth, index):
        return (2 ** depth) - 1 + index

    def _path_nodes(self, leaf):
        nodes = []
        index = 0
        nodes.append(self._node(0, index))
        for depth in range(1, self.depth + 1):
            bit = (leaf >> (self.depth - depth)) & 1
            index = index * 2 + bit
            nodes.append(self._node(depth, index))
        return nodes

    def _make_entry(self, block_id, leaf, value):
        nonce = secrets.token_bytes(12)
        encrypted = nonce + self.cipher.encrypt(nonce, value, str(block_id).encode())
        return {"block_id": block_id, "leaf": leaf, "encrypted": encrypted}

    def _read_entry(self, entry):
        nonce = entry["encrypted"][:12]
        ciphertext = entry["encrypted"][12:]
        return self.cipher.decrypt(
            nonce, ciphertext, str(entry["block_id"]).encode()
        )

    def _is_in_subtree(self, leaf, depth, index):
        if depth == 0:
            return True
        return (leaf >> (self.depth - depth)) == index

    def _evict_path(self, leaf):
        path = self._path_nodes(leaf)

        for node in path:
            self.stash.extend(self.tree[node])
            self.tree[node] = []

        for depth in range(self.depth, -1, -1):
            node = path[depth]
            index = node - (2 ** depth - 1)
            eligible = [
                entry for entry in self.stash
                if self._is_in_subtree(entry["leaf"], depth, index)
            ]
            while eligible and len(self.tree[node]) < self.bucket_size:
                chosen = eligible.pop(0)
                self.stash.remove(chosen)
                self.tree[node].append(chosen)

    def access(self, block_id, new_value=None):
        if block_id not in self.position_map:
            raise KeyError(f"Unknown block: {block_id}")

        old_leaf = self.position_map[block_id]
        new_leaf = secrets.randbelow(self.leaf_count)
        self.position_map[block_id] = new_leaf

        path = self._path_nodes(old_leaf)
        self.access_log.append(tuple(path))

        for node in path:
            self.stash.extend(self.tree[node])
            self.tree[node] = []

        target = next(
            (entry for entry in self.stash if entry["block_id"] == block_id),
            None,
        )
        if target is None:
            raise RuntimeError("Requested block was not found on its ORAM path.")

        current_value = self._read_entry(target)
        if new_value is not None:
            if not isinstance(new_value, bytes):
                raise ValueError("New block value must be bytes.")
            current_value = new_value

        self.stash.remove(target)
        self.stash.append(self._make_entry(block_id, new_leaf, current_value))
        self._evict_path(old_leaf)
        return current_value

    def get_access_trace(self):
        """Return only accessed tree nodes, not logical block identifiers."""
        return list(self.access_log)
