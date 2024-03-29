""""
Find more at: https://github.com/l-farrell/isam-ob/settings
"""

import logging

from pyisam.util.model import DataObject
from pyisam.util.restclient import RESTClient

APPLICATION_LOGS = "/isam/application_logs"

logger = logging.getLogger(__name__)


class ApplicationLog(object):

    def __init__(self, base_url, username, password):
        super(ApplicationLog, self).__init__()
        self.client = RESTClient(base_url, username, password)

    def get_application_log(self, path):
        parameters = DataObject()
        parameters.add_value_string("type", "File")

        endpoint = "%s/%s" % (APPLICATION_LOGS, path)

        response = self.client.get_json(endpoint, parameters.data)
        response.success = response.status_code == 200

        return response