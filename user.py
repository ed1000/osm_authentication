class User:
    def __init__(self, username=None, projects=None, token=None, is_authenticated=False, 
        is_enabled=False, is_admin=False, is_service=False, issued_at=None, expires_at=None):
        self.username = username
        self.projects = projects
        self.token = token
        self.is_authenticated = is_authenticated
        self.is_enabled = is_enabled
        self.is_admin = is_admin
        self.is_service = is_service
        self.issued_at = issued_at
        self.expires_at = expires_at

    def to_public_dict(self):
        data = dict()

        data['username'] = self.username
        data['projects'] = self.projects
        data['is_authenticated'] = self.is_authenticated
        data['is_enabled'] = self.is_enabled
        data['issued_at'] = self.issued_at
        data['expires_at'] = self.expires_at

        return data
