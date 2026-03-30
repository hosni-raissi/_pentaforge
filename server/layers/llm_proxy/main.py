# Proxy logic to hide client-identifying data (static mapping version)
import re
from server.layers.llm_proxy.proxy.encryptor import Encryptor
from server.layers.llm_proxy.proxy.patterns import PatternRegistry, SensitiveDataType

# In-memory mapping: placeholder -> original
_proxy_mapping = {}

PLACEHOLDER_URL = "https://example.com"
PLACEHOLDER_DOMAIN = "example.com"

def proxy_prompt(prompt: str, encryptor: Encryptor = None) -> str:
	"""
	Replace sensitive URLs and domains in the prompt with placeholders.
	Store mapping for later restoration.
	"""
	if encryptor is None:
		encryptor = Encryptor(key="testkey123")

	# Replace URLs
	def url_replacer(match):
		url = match.group(0)
		token = PLACEHOLDER_URL
		_proxy_mapping[token] = url
		return token

	prompt = PatternRegistry.PATTERNS[0][1].sub(url_replacer, prompt)

	# Replace domains (but not if part of a URL already replaced)
	def domain_replacer(match):
		domain = match.group(0)
		# Avoid replacing inside already replaced URLs
		if domain in prompt:
			token = PLACEHOLDER_DOMAIN
			_proxy_mapping[token] = domain
			return token
		return domain

	prompt = PatternRegistry.PATTERNS[1][1].sub(domain_replacer, prompt)

	return prompt

def restore_prompt(proxied: str) -> str:
	"""Restore original client data from mapping."""
	out = proxied
	for token, original in _proxy_mapping.items():
		out = out.replace(token, original)
	return out
