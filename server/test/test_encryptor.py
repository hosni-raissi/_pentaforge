import unittest
from server.layers.llm_proxy.proxy.encryptor import Encryptor
import re

class TestEncryptor(unittest.TestCase):
    def setUp(self):
        self.encryptor = Encryptor(key="testkey123")

    def test_encrypt_and_decrypt(self):
        text = "https://orange.com"
        encrypted = self.encryptor.encrypt(text)
        print(f"Encrypted: {encrypted}")
        self.assertNotEqual(encrypted, text)
        decrypted = self.encryptor.decrypt(encrypted)
        print(f"Decrypted: {decrypted}")
        self.assertEqual(decrypted, text)

    def test_generate_hash(self):
        text = "https://orange.com"
        hash1 = self.encryptor.generate_hash(text)
        hash2 = self.encryptor.generate_hash(text)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 16)

if __name__ == "__main__":
    unittest.main()
