import unittest
from server.layers.llm_proxy.main import proxy_prompt, restore_prompt
from server.layers.llm_proxy.proxy.encryptor import Encryptor

class TestLLMProxy(unittest.TestCase):
    def setUp(self):
        self.encryptor = Encryptor(key="testkey123")

    def test_proxy_and_restore(self):
        prompt = "Test pentest for https://orange.com and orange.com. Do not show client."
        proxied = proxy_prompt(prompt, self.encryptor)
        print(f"Proxied: {proxied}")
        self.assertNotIn("orange.com", proxied)
        self.assertIn("example.com", proxied)
        restored = restore_prompt(proxied)
        print(f"Restored: {restored}")
        self.assertEqual(restored, prompt)

if __name__ == "__main__":
    unittest.main()
