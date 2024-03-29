"""
Find more at: https://github.com/l-farrell/isam-ob/settings
"""

import logging

from pyisam.util.model import DataObject
from pyisam.util.restclient import RESTClient


SETUP_COMPLETE = "/setup_complete"
SERVICE_AGREEMENTS_ACCEPTED = "/setup_service_agreements/accepted"

logger = logging.getLogger(__name__)


class FirstSteps(object):

    def __init__(self, base_url, username, password):
        super(FirstSteps, self).__init__()
        self.client = RESTClient(base_url, username, password)

    def get_setup_status(self):
        response = self.client.get_json(SETUP_COMPLETE)
        response.success = response.status_code == 200

        return response

    def set_setup_complete(self):
        response = self.client.put_json(SETUP_COMPLETE)
        response.success = response.status_code == 200

        return response

    def get_sla_status(self):
        response = self.client.get_json(SERVICE_AGREEMENTS_ACCEPTED)
        response.success = response.status_code == 200

        return response

    def set_sla_status(self, accept=True):
        data = DataObject()
        data.add_value("accepted", accept)

        response = self.client.put_json(SERVICE_AGREEMENTS_ACCEPTED, data.data)
        response.success = response.status_code == 200

        return response
