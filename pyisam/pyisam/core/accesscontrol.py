"""
Find more at: https://github.com/l-farrell/isam-ob/settings
"""

from .access.accesscontrol import AccessControl
from .access.accesscontrol import AccessControl9030 as AC9030
from .access.advancedconfig import AdvancedConfig
from .access.apiprotection import APIProtection, APIProtection9040, APIProtection9050
from .access.attributes import Attributes
from .access.authentication import Authentication, Authentication9021
from .access.filedownloads import FileDownloads
from .access.mmfaconfig import MMFAConfig, MMFAConfig9021
from .access.pushnotification import PushNotification, PushNotification9021
from .access.riskprofiles import RiskProfiles  
from .access.runtimeparameters import RuntimeParameters
from .access.scimconfig import SCIMConfig
from .access.serverconnections import ServerConnections
from .access.templatefiles import TemplateFiles
from .access.userregistry import UserRegistry
from .access.mappingrules import MappingRules


class AccessControl9020(object):

    def __init__(self, base_url, username, password):
        super(AccessControl9020, self).__init__()
        self.access_control = AccessControl(base_url, username, password)
        self.advanced_config = AdvancedConfig(base_url, username, password)
        self.api_protection = APIProtection(base_url, username, password)
        self.attributes = Attributes(base_url, username, password)
        self.authentication = Authentication(base_url, username, password)
        self.file_downloads = FileDownloads(base_url, username, password)
        self.mmfa_config = MMFAConfig(base_url, username, password)
        self.push_notification = PushNotification(base_url, username, password)
        self.risk_profiles = RiskProfiles(base_url, username, password)
        self.runtime_parameters = RuntimeParameters(
            base_url, username, password)
        self.scim_config = SCIMConfig(base_url, username, password)
        self.server_connections = ServerConnections(
            base_url, username, password)
        self.template_files = TemplateFiles(base_url, username, password)
        self.user_registry = UserRegistry(base_url, username, password)
        self.mapping_rules = MappingRules(base_url, username, password)


class AccessControl9021(AccessControl9020):

    def __init__(self, base_url, username, password):
        super(AccessControl9021, self).__init__(base_url, username, password)
        self.mmfa_config = MMFAConfig9021(base_url, username, password)
        self.push_notification = PushNotification9021(base_url, username, password)
        self.authentication = Authentication9021(base_url, username, password)


class AccessControl9030(AccessControl9021):

    def __init__(self, base_url, username, password):
        super(AccessControl9030, self).__init__(base_url, username, password)
        self.access_control = AC9030(base_url, username, password)


class AccessControl9040(AccessControl9030):

    def __init__(self, base_url, username, password):
        super(AccessControl9040, self).__init__(base_url, username, password)
        self.api_protection = APIProtection9040(base_url, username, password)


class AccessControl9050(AccessControl9040):

    def __init__(self, base_url, username, password):
              super(AccessControl9050, self).__init__(base_url, username, password)
              self.api_protection = APIProtection9050(base_url, username, password)

class AccessControl9060(AccessControl9050):

    def __init__(self, base_url, username, password):
              super(AccessControl9060, self).__init__(base_url, username, password)

class AccessControl9070(AccessControl9060):

    def __init__(self, base_url, username, password):
              super(AccessControl9070, self).__init__(base_url, username, password)
