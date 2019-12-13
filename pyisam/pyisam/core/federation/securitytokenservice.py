"""
Find more at: https://github.com/l-farrell/isam-ob/settings
"""

import logging
import uuid

from pyisam.util.model import DataObject
from pyisam.util.restclient import RESTClient

STS_TEMPLATES = "/iam/access/v8/sts/templates/"
STS_CHAINS = "/iam/access/v8/sts/chains/"

logger = logging.getLogger(__name__)

class SecurityTokenServiceChainTemplates(object):

    def __init__(self, base_url, username, password):
        super(SecurityTokenServiceChainTemplates, self).__init__()
        self.client = RESTClient(base_url, username, password)

    def get_templates(self):
        endpoint = STS_TEMPLATES
        response = self.client.get_json(endpoint)
        response.success = response.status_code == 200
        return response


    def get_template(self,id):


        endpoint = "{}/{}".format(STS_TEMPLATES,id)
        response = self.client.get_json(endpoint)
        response.success = response.status_code == 200
        return response


    def create_template(self,name, description="", chain_items=[]):
        data = DataObject()

        data.add_value('name',name)
        data.add_value('description',description)
        data.add_value('chainItems',chain_items)

        endpoint = STS_TEMPLATES
        response = self.client.post_json(endpoint, data.data)
        response.success = response.status_code == 201

        return response

    def update_template(self,name, description="", chain_items=[]):
        data = DataObject()

        data.add_value('name',name)
        data.add_value('description',description)
        data.add_value('chainItems',chain_items)

        endpoint = STS_TEMPLATES
        response = self.client.put_json(endpoint, data.data)
        response.success = response.status_code == 204

        return response

class SecurityTokenServiceChainInstances(object):

    def __init__(self, base_url, username, password):
        super(SecurityTokenServiceChainInstances, self).__init__()
        self.client = RESTClient(base_url, username, password)


    def get_chains(self):
        endpoint = STS_CHAINS
        response = self.client.get_json(endpoint)
        response.success = response.status_code == 200

        return response

    def get_chain(self, id):
        endpoint = "{}/{}".format(STS_CHAINS, id)
        response = self.client.get_json(endpoint)
        response.success = response.status_code == 200

        return response


    def create_chain(self, name, description, template_id, request_type, applies_to, issuer, chain_self_properties=[], validate_requests=False, sign_responses=False):
        data = DataObject()

        data.add_value('name',name)
        data.add_value('description',description)
        data.add_value('chainId',template_id)
        data.add_value('requestType',request_type)
        data.add_value('appliesTo',{"address":applies_to})
        data.add_value('issuer',{"address":issuer})
        data.add_value('validateRequests', validate_requests)
        data.add_value('signResponses',sign_responses)
        data.add_value('properties',{"self":chain_self_properties})

        endpoint = STS_CHAINS
        response = self.client.post_json(endpoint, data.data)
        response.success = response.status_code == 201

        return response

        