from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneclient.v3 import client

from user import User
from settings import Config


class TokenRevocator:
    def __init__(self):
        self.auth_url = Config.KEYSTONE_URL
        self.username = Config.KEYSTONE_USERNAME
        self.password = Config.KEYSTONE_PASSWORD
        self.project = Config.KEYSTONE_PROJECT
        self.admin_project = Config.KEYSTONE_ADMIN_PROJECT
        self.service_project = Config.KEYSTONE_SERVICE_PROJECT
        self.user_domain_name = Config.KEYSTONE_USER_DOMAIN_NAME
        self.project_domain_name = Config.KEYSTONE_PROJECT_DOMAIN_NAME

    def revoke_token(self, token):
        try:
            auth = v3.Password(user_domain_name=self.user_domain_name,
                               username=self.username,
                               password=self.password,
                               project_domain_name=self.project_domain_name,
                               project_name=self.project,
                               auth_url=self.auth_url)
            sess = session.Session(auth=auth)
            keystone = client.Client(session=sess)

            keystone.tokens.revoke_token(token=token)

            return True
        except ClientException as ex:
            print(ex)

            return False
