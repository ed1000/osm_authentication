import pprint

from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneclient.v3 import client

from user import User
from settings import Config


class BasicAuthentication:
    """
    Basic Authentication Class
    
    Responsible by authenticating users with basic credentials.
    """
    def __init__(self):
        self.auth_url = Config.KEYSTONE_URL
        self.username = Config.KEYSTONE_USERNAME
        self.password = Config.KEYSTONE_PASSWORD
        self.project = Config.KEYSTONE_PROJECT
        self.admin_project = Config.KEYSTONE_ADMIN_PROJECT
        self.service_project = Config.KEYSTONE_SERVICE_PROJECT
        self.user_domain_name = Config.KEYSTONE_USER_DOMAIN_NAME
        self.project_domain_name = Config.KEYSTONE_PROJECT_DOMAIN_NAME

    def authenticate(self, username=None, password=None):
        """
        Authenticating users using basic credentials.
        """
        def is_enabled(project):
            return project.enabled

        def is_service(project):
            return project.enabled and project.name == self.service_project

        def is_admin(project):
            return project.enabled and project.name == self.admin_project

        def filter_enabled_projects(project):
            return project.enabled

        def map_to_string(project):
            return project.name

        if username is None:
            return None

        if password is None :
            return None
        
        try:
            auth = v3.Password(user_domain_name=self.user_domain_name,
                               username=self.username,
                               password=self.password,
                               project_domain_name=self.project_domain_name,
                               project_name=self.project,
                               auth_url=self.auth_url)
            sess = session.Session(auth=auth)
            keystone = client.Client(session=sess)

            token = keystone.get_raw_token_from_identity_service(
                auth_url=self.auth_url,
                username=username,
                password=password,
                user_domain_name=self.user_domain_name)

            pprint.pprint(token)

            projects = keystone.projects.list(user=token.get('user').get('id'))

            enabled_projects = map(map_to_string,list(filter(filter_enabled_projects, projects)))
            enabled_token = len(list(filter(is_enabled, projects))) != 0
            admin_token = len(list(filter(is_admin, projects))) != 0
            service_token = len(list(filter(is_service, projects))) != 0

            issued_at = token.get('issued')
            expires_at = token.get('expires')

            return User(username=username,
                        projects=enabled_projects,
                        token=token.get('auth_token'),
                        is_authenticated=True,
                        is_enabled=enabled_token,
                        is_admin=admin_token,
                        is_service=service_token,
                        issued_at=issued_at,
                        expires_at=expires_at)
        except ClientException as ex:
            print(ex.message)

            return None
