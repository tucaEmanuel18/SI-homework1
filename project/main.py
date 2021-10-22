import enum
import binascii
from Crypto.Cipher import AES
import os
import codecs


def xor(str1, str2):
    return "".join([chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2)])


def xor_bytes(b1, b2):
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])


class Cipher:
    def __init__(self, key, mode):
        self.key = key
        self.cipher = AES.new(key, mode)


class EcbCipher(Cipher):
    def __init__(self, key, mode):
        super().__init__(key, mode)

    def encrypt(self, message):
        size = 16
        cipher_text = ""
        # fill with 0
        if len(message) % size != 0:
            message = message + (size - len(message) % size) * " "

        for i in range(len(message) // size):
            start_pos = i * size
            block = message[start_pos:start_pos + size]
            encrypted_block = self.cipher.encrypt(block.encode('utf-8'))
            cipher_text = cipher_text + binascii.hexlify(encrypted_block).decode('utf-8')
        return cipher_text

    def decrypt(self, encrypted_message):
        size = 32
        plain_text = ""
        for i in range(len(encrypted_message) // size):
            start_pos = i * size
            block = encrypted_message[start_pos:start_pos + size]
            plain_text = plain_text + self.cipher.decrypt(binascii.unhexlify(block.encode('utf-8'))).decode('utf-8')

        return plain_text


class OfbCipher(Cipher):
    def __init__(self, key, mode):
        super().__init__(key, mode)
        self.vector = None

    def vector_init(self):
        self.vector = init_vector

    def encrypt(self, message):
        self.vector_init()
        self.vector = self.vector.encode('utf-8')
        size = 16
        cipher_text = ""
        # fill with 0
        if len(message) % size != 0:
            message = message + (size - len(message) % size) * " "

        for i in range(len(message) // size):
            start_pos = i * size
            block = message[start_pos:start_pos + size]
            self.vector = self.cipher.encrypt(self.vector)
            encrypted_block = xor_bytes(block.encode('utf-8'), self.vector)

            cipher_text = cipher_text + binascii.hexlify(encrypted_block).decode('utf-8')
        return cipher_text

    def decrypt(self, encrypted_message):
        self.vector_init()
        self.vector = self.vector.encode('utf-8')
        size = 32
        plain_text = ""

        for i in range(len(encrypted_message) // size):
            start_pos = i * size
            block = encrypted_message[start_pos:start_pos + size]
            self.vector = self.cipher.encrypt(self.vector)
            unhex_block = binascii.unhexlify(block.encode('utf-8'))
            decrypted_block = xor_bytes(unhex_block, self.vector)
            plain_text = plain_text + decrypted_block.decode('utf-8')

        return plain_text


class OperationalMode(enum.Enum):
    ECB = 1
    OFB = 2


class CommunicationNode:
    def __init__(self):
        self.private_key = None
        self.mode = None
        self.memory = []

    def start_communication(self, another_node: "CommunicationNode", mode):
        self.send_operational_mode(another_node, mode)
        encrypted_key = key_manager.get_random_key(self.mode)
        self.receive_encrypted_key(encrypted_key)
        self.send_encrypted_key(encrypted_key, another_node)

    def send_operational_mode(self, another_node: "CommunicationNode", mode):
        self.mode = mode
        another_node.mode = mode

    def send_encrypted_key(self, encrypted_key, another_node: "CommunicationNode"):
        another_node.receive_encrypted_key(encrypted_key)

    def receive_encrypted_key(self, encrypted_key):
        public_key = key_manager.get_public_key()
        cipher = AES.new(public_key, AES.MODE_ECB)
        self.private_key = cipher.decrypt(encrypted_key)

    def send_message(self, message, another_node: "CommunicationNode"):
        encrypted_message = self.encrypt_message(message)
        another_node.memory.append(encrypted_message)

    def encrypt_message(self, message):
        if self.mode == AES.MODE_ECB:
            cipher = EcbCipher(self.private_key, self.mode)
        else:
            cipher = OfbCipher(self.private_key, self.mode)
        return cipher.encrypt(message)

    def decrypt_message(self, message):
        if self.mode == AES.MODE_ECB:
            cipher = EcbCipher(self.private_key, self.mode)
        else:
            cipher = OfbCipher(self.private_key, self.mode)
        return cipher.decrypt(message)

    def print_messages(self):
        for message in self.memory:
            print(self.decrypt_message(message))


class KeyManager:
    def __init__(self):
        self.public_key = "testamcriptareab"
        self.public_key_bytes = self.public_key.encode(encoding='UTF-8')

    def get_random_key(self, mode):
        new_key = os.urandom(16)
        cipher = AES.new(self.public_key_bytes, mode)
        return cipher.encrypt(new_key)

    def get_public_key(self):
        return self.public_key_bytes

def set_mode(mode:"OperationalMode"):
    if mode == OperationalMode.ECB:
        return AES.MODE_ECB
    else:
        return AES.MODE_OFB
    return mode

def read_from_file(file_name):
    file = open(file_name, "r")
    return file.read()

if __name__ == '__main__':
    file_name = "input.txt"
    operational_mode = set_mode(OperationalMode.ECB)
    init_vector = "initialized"
    key_manager = KeyManager()
    A = CommunicationNode()
    B = CommunicationNode()
    A.start_communication(B, operational_mode)
    B.send_message("ack", A)
    print("A:")
    A.print_messages()
    A.send_message(read_from_file(file_name), B)
    print("B:")
    B.print_messages()
