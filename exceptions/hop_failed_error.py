# exceptions/hop_failed_error.py
from entities.edge import Edge
from .auto_pwn_exception import AutoPwnException

class HopFailedError(AutoPwnException):
	"""
	Raised when a specific edge cannot be exploited.
	Useful for trying alternative paths.
	"""
	def __init__(self, edge:Edge, reason: str):
		self.edge = edge                    # which hop failed
		self.reason = reason                # why it failed
		super().__init__(
			f"Hop failed on edge '{edge.type}' "
			f"({edge.node_source.name} --> {edge.node_end.name}): {reason}"
		)
