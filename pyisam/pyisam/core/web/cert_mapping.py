""""
Find more at: https://github.com/l-farrell/isam-ob/settings
"""

import logging
import urllib

from pyisam.util.model import DataObject
from pyisam.util.restclient import RESTClient


CLIENT_CERT = "/wga/user_map_cdas"

logger = logging.getLogger(__name__)


class CertMapping(object):

    def __init__(self, base_url, username, password):
        super(CertMapping, self).__init__()
        self.client = RESTClient(base_url, username, password)

    def list_cert_mappings(self):
    
        response = self.client.get_json(CLIENT_CERT)
        response.success = response.status_code == 200

        return response

    def create_cert_mapping(self, name, mapping):

        endpoint = CLIENT_CERT

        data = DataObject()
        data.add_value_string("name",name)
        data.add_value_string("content",mapping)

        response = self.client.post_json(endpoint, data.data)
        response.success = response.status_code == 200

        return response
