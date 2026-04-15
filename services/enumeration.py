import requests
from urllib.parse import urljoin
from typing import Optional
from entities.client import Client
# On importe votre entité Client
# from entites.client import Client 

class Enumerations:
    def __init__(self, client_entity):
        """
        On passe l'instance de Client au lieu de recréer la session.
        client_entity doit avoir : .session et .base_url
        """
        self.client = client_entity
        self.session = client_entity.session
        self.base_url = client_entity.base_url 

    """ Helpers """
    def _url(self, path: str) -> str:
        # Assurez-vous que base_url ne finit pas par /api/v2 si vous l'ajoutez ici
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def _get(self, path: str, params=None) -> dict:
        response = self.session.get(self._url(path), params=params)
        response.raise_for_status()
        return response.json()

    def get_domains(self):
        # Correction du nom de la méthode pour correspondre au main
        return self._get("/api/v2/domains")

    def resolve_domains(self, domain_name: str) -> Optional[dict]:
        data = self.get_domains()
        domains = data.get("data", [])

        for domain in domains:
            if domain.get("name") == domain_name:
                return domain 

        return None

    def _paginate(self, path: str, params: Optional[dict] = None) -> list:
        result = []
        skip = 0
        limit = 100

        while True:
            query = params.copy() if params else {}
            query.update({"limit": limit, "skip": skip})

            data = self._get(path, params=query)
            batch = data.get("data", [])

            if not batch:
                break

            result.extend(batch)
            skip += len(batch)
            
            # Sécurité BloodHound : si on reçoit moins que la limite, c'est fini
            if len(batch) < limit:
                break

        return result

    def get_users(self):
        return self._paginate("/api/v2/users")

    def get_gpos(self):
        return self._paginate("/api/v2/gpos")
 
    def get_computers(self):
        return self._paginate("/api/v2/computers")

    def get_sessions(self):
        return self._paginate("/api/v2/sessions")

    def get_ous(self):
        return self._paginate("/api/v2/ous")


""" Main Fonction : """

if __name__ == "__main__":
    # 1. Initialisation de votre entité Client existante
    # On suppose que Client gère l'auth HMAC avec ID et Key en interne
    from entites.client import Client
    
    BASE_URL = "http://10.116.200.110:8083" # Votre URL BloodHound
    API_ID = "2f144e6b-21df-4c73-92ce-3eb563d5dbd6"
    API_KEY = "ES7qSK2o7/8hMLBUxCZGWV85VC3NDyrsSYp0kkKWdL/AQyh4mHju0g=="
    
    # Création de l'entité qui possède la session authentifiée
    my_auth_client = Client(BASE_URL, API_ID, API_KEY)

    # 2. On passe l'entité directement à Enumerations
    client = Enumerations(my_auth_client)

    # 3. Appels des méthodes
    users = client.get_users()
    gpos = client.get_gpos()
    computers = client.get_computers()
    sessions = client.get_sessions()
    domains = client.get_domains() # Appel corrigé
    ous = client.get_ous()

    print(f"Récupérés : {len(users)} users, {len(computers)} computers.")
