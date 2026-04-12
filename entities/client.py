import sys

class Client:
	def __init__(self, token_id, token_key, base_url):
		self._token_id = token_id
		self._token_key = token_key
		self.base_url = base_url

	def if_authenticated(self):
		if not all([self._token_id, self._token_key, self.base_url]):
			print("Error! Missing Environment Variables!")
			sys.exit(1)
