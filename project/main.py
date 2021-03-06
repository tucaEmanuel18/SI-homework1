import enum
from Crypto.Cipher import AES
import os


def to_bits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result


def from_bits(bits):
    chars = []
    for b in range(len(bits) // 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


def get_blocks(message, size):
    bits = to_bits(message)
    bit_blocks = []
    # fill with 0 if is necessary
    rest = len(bits) % size
    for i in range(rest):
        bits.append(0)

    for i in range(len(bits) // size):
        start_pos = i * size
        bit_blocks.append(bits[start_pos: start_pos + size])

    blocks = []
    for bit_block in bit_blocks:
        blocks.append(from_bits(bit_block))
    return blocks


def xor(str1, str2):
    return "".join([chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2)])


class Cipher:
    def __init__(self, key):
        self.key = key
        self.cipher = AES(key)


class EcbCipher(Cipher):
    def __init__(self, key):
        Cipher.__init__(key)

    def encrypt(self, message):
        blocks = get_blocks(message, 128)
        cipher_text = ""
        for block in blocks:
            cipher_text += self.cipher.encrypt(block)
        return cipher_text

    def decrypt(self, encrypted_message):
        blocks = get_blocks(encrypted_message, 128)
        plain_text = ""
        for block in blocks:
            plain_text += self.cipher.decrypt(block)
        return plain_text


class OfbCipher(Cipher):
    def __init__(self, key):
        Cipher.__init__(key)
        self.vector = None

    def vector_init(self):
        self.vector = init_vector

    def encrypt(self, message):
        self.vector_init()
        blocks = get_blocks(message, 128)
        cipher_text = ""
        for block in blocks:
            self.vector = self.cipher.encrypt(self.vector)
            cipher_text += xor(block, self.vector)
        return cipher_text

    def decrypt(self, encrypted_message):
        self.vector_init()
        blocks = get_blocks(encrypted_message, 128)
        plain_text = ""
        for block in blocks:
            self.vector = self.cipher.decrypt(self.vector)
            plain_text += xor(block, self.vector)
        return plain_text


class OperationalMode(enum.Enum):
    ECB = 1
    OFB = 2

class CommunicationNode:
    def __init__(self):
        self.private_key = None
        self.mode = None
        self.memory = []

    def start_communication(self, another_node: "CommunicationNode", mode: "OperationalMode"):
        self.send_operational_mode(another_node, mode)
        encrypted_key = self.ask_for_a_key()
        self.receive_encrypted_key(encrypted_key)
        self.send_encrypted_key(encrypted_key, another_node)

    def send_operational_mode(self, another_node: "CommunicationNode", mode: "OperationalMode"):
        self.mode = mode
        another_node.mode = mode

    def set_operational_mode(self, mode):
        self.mode = mode

    def send_encrypted_key(self, encrypted_key, another_node: "CommunicationNode"):
        another_node.receive_encrypted_key(encrypted_key)

    def receive_encrypted_key(self, encrypted_key):
        public_key = KeyManager.get_public_key()
        cipher = AES(public_key)
        self.private_key = cipher.decrypt(encrypted_key)

    def ask_for_a_key(self):
        return KeyManager.get_random_key(self.mode)

    def send_message(self, message, another_node: "CommunicationNode"):
        encrypted_message = self.encrypt_message(message)
        another_node.memory.append(encrypted_message)

    def encrypt_message(self, message):
        if self.mode == OperationalMode.ECB:
            cipher = EcbCipher(self.private_key)
        else:
            cipher = OfbCipher(self.private_key)

        return cipher.encrypt(message)

    def print_messages(self):
        for message in self.memory:
            print(message)

class KeyManager:
    def __init__(self):
        self.public_key = "testamcriptarea"

    def get_random_key(self, mode: "Operational_Mode"):
        new_key = os.urandom(16)
        cipher = AES.new(self.public_key)
        return cipher.encrypt(new_key)

    def get_public_key(self):
        return self.public_key


def read_from_file(file_name):
    file = open(file_name, "r")
    return file.read()


if __name__ == '__main__':
    file_name = "input.txt"
    operational_mode = OperationalMode.ECB
    init_vector = "initialized"
    key_manager = KeyManager()
    A = CommunicationNode()
    B = CommunicationNode()
    A.start_communication(B, operational_mode)
    B.send_message("ack", A)
    A.send_message(read_from_file(file_name), B)
    B.print_messages()

