from datetime import datetime, timezone
import hmac
import hashlib
import base64

def make_auth_header(token_id:str, token_key:str,
			method:str, path:str, body:str = None) -> dict:
	timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
	digester = hmac.new(token_key.encode(), None, hashlib.sha256)
	digester.update(f"{method.upper()}{path}".encode("utf-8"))
	digester = hmac.new(digester.digest(), None, hashlib.sha256)
	digester.update(timestamp[:13].encode("utf-8"))
	digester = hmac.new(digester.digest(), None, hashlib.sha256)
	if body is not None:
		print(f"DEBUG body received: {body}")
		digester.update(body)
	signature = base64.b64encode(digester.digest()).decode("utf-8")
	return {
		"Authorization" : f"bhesignature {token_id}",
		"RequestDate" : timestamp,
		"Signature" : signature
	}
