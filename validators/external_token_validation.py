from user import User
from settings import Config


class ExternalTokenValidator:
    def __init__(self):
        self.EXTERNAL_AUTHENTICATOR_URL = 'http://' + Config.EXTERNAL_AUTHENTICATOR_IP        
        
    def validate_token(self, token):
        return User(is_authenticated=True)
