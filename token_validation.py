from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneclient.v3 import client

from user import User


class TokenValidator:
    def __init__(self):
        self.auth_url = settings.KEYSTONE_URL
        self.username = settings.KEYSTONE_USERNAME
        self.password = settings.KEYSTONE_PASSWORD
        self.project = settings.KEYSTONE_PROJECT
        self.admin_project = settings.KEYSTONE_ADMIN_PROJECT
        self.service_project = settings.KEYSTONE_SERVICE_PROJECT
        self.user_domain_name = settings.KEYSTONE_USER_DOMAIN_NAME
        self.project_domain_name = settings.KEYSTONE_PROJECT_DOMAIN_NAME

    def validate_token(self, token):
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

        try:
            auth = v3.Password(user_domain_name=self.user_domain_name,
                               username=self.username,
                               password=self.password,
                               project_domain_name=self.project_domain_name,
                               project_name=self.project,
                               auth_url=self.auth_url)
            sess = session.Session(auth=auth)
            keystone = client.Client(session=sess)

            token_access_info = keystone.tokens.validate(token=token)

            username = token.get('username')

            projects = keystone.projects.list(user=token.get('user').get('id'))

            enabled_projects = map(map_to_string, list(filter(filter_enabled_projects, projects)))
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
            print(ex)

            return None