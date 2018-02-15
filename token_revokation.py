from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneclient.v3 import client

from user import User


class TokenRevokator:
    def __init__(self):
        self.auth_url = settings.KEYSTONE_URL
        self.username = settings.KEYSTONE_USERNAME
        self.password = settings.KEYSTONE_PASSWORD
        self.project = settings.KEYSTONE_PROJECT
        self.admin_project = settings.KEYSTONE_ADMIN_PROJECT
        self.service_project = settings.KEYSTONE_SERVICE_PROJECT
        self.user_domain_name = settings.KEYSTONE_USER_DOMAIN_NAME
        self.project_domain_name = settings.KEYSTONE_PROJECT_DOMAIN_NAME

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

            keystone.tokens.revoke(token=token)

            return True
        except ClientException as ex:
            print(ex)

            return False
