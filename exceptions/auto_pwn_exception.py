# exceptions/auto_pwn_exception.py

class AutoPwnException(Exception):
	"""
	Base exception for all bloodhound-auto errors.
	Never raised directly.
	except AutoPwnException will catch any custom exception.
	message is set with super().__init__()
	"""
	pass
