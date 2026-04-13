# utils/request.py

import requests
from entities.client import Client
import auth
import json
import hashlib

class BHRequest:
	def __init__(self, client:Client):
		self.client = client

	def bh_get(self, path:str) -> dict:
		   headers = bh_auth.make_auth_header(self.client._token_id, self.client._token_key,
		                   		      "GET", path)
		print("Headers being sent :")
		for k, v in headers.items():
			print(f" {k}: {v}")
		try:
			response = requests.get(f"{client.base_url}{path}", headers=headers)
			response.raise_for_status()
			return response.json()
		except requests.exceptions.ConnectionError:
			print("Could not reach the Bloodhound server. Is Bloodhound running?")
			return None
		except requests.exceptions.HTTPError as e:
			print(f"HTTP Error : {e}")
			return None
		except Exception as e:
			print(f"Unexpected error: {e}")
			return None

	def bh_post(self, path:str, body:dict) -> dict:
		body_bytes = json.dumps(body).encode("utf-8")
		headers = bh_auth.make_auth_header(self.client._token_id, self.client._token_key,
						  "POST", path, body_bytes)
		print("Headers being sent :")
		for k, v in headers.items():
			print(f" {k}: {v}")
		try:
			response = requests.post(f"{client.base_url}{path}",
	 				           headers={**headers, "Content-Type": "application/json"},
						   data=body_bytes
						)
			response.raise_for_status()
			return response.json()
		except requests.exceptions.ConnectionError:
			print("Could not reach the Bloodhound server. Is Bloodhound running?")
			return None
		except requests.exceptions.HTTPError as e:
			print(f"HTTP Error : {e}")
			return None
		except Exception as e:
			print(f"Unexpected error: {e}")
			return None
