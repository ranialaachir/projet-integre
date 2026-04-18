import json


class Pagination:

	def __init__(self, data : str, limit : int = 100):
		self.data = json.loads(data)
		self.limit = limit

	def paginate(self):
		skip = 0
		while True :
			page = self.data[skip: skip + self.limit]
			
			if not page:
				break
			
			yield page 
			skip += self.limit 
