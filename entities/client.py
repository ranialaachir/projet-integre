# entities/client.py

import sys

class Client:
	def __init__(self, token_id:str, token_key:str, base_url:str):
		self._token_id = token_id
		self._token_key = token_key
		self.base_url = base_url

	def check_credentials(self):
		if not all([self._token_id, self._token_key, self.base_url]):
			print("[-] Missing Environment Variables!")
			sys.exit(1)
