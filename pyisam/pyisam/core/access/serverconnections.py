"""
Find more at: https://github.com/l-farrell/isam-ob/settings
"""

import logging

from pyisam.util.model import DataObject
from pyisam.util.restclient import RESTClient


SERVER_CONNECTION_ROOT = "/mga/server_connections"
SERVER_CONNECTION_LDAP = "/mga/server_connections/ldap"
SERVER_CONNECTION_WEB_SERVICE = "/mga/server_connections/ws"
SERVER_CONNECTION_SMTP = "/mga/server_connections/smtp"

logger = logging.getLogger(__name__)


class ServerConnections(object):

    def __init__(self, base_url, username, password):
        super(ServerConnections, self).__init__()
        self.client = RESTClient(base_url, username, password)

    def create_ldap(
            self, name=None, description=None, locked=None,
            connection_host_name=None, connection_bind_dn=None,
            connection_bind_pwd=None, connection_ssl_truststore=None,
            connection_ssl_auth_key=None, connection_host_port=None,
            connection_ssl=None, connect_timeout=None, servers=None):
        connection_data = DataObject()
        connection_data.add_value_string("hostName", connection_host_name)
        connection_data.add_value_string("bindDN", connection_bind_dn)
        connection_data.add_value_string("bindPwd", connection_bind_pwd)
        connection_data.add_value_string(
            "sslTruststore", connection_ssl_truststore)
        connection_data.add_value_string("sslAuthKey", connection_ssl_auth_key)
        connection_data.add_value("hostPort", connection_host_port)
        connection_data.add_value("ssl", connection_ssl)

        manager_data = DataObject()
        manager_data.add_value("connectTimeout", connect_timeout)

        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("description", description)
        data.add_value_string("type", "ldap")
        data.add_value("locked", locked)
        data.add_value("servers", servers)
        data.add_value_not_empty("connection", connection_data.data)
        data.add_value_not_empty("connectionManager", manager_data.data)

        endpoint = SERVER_CONNECTION_LDAP + "/v1"

        response = self.client.post_json(endpoint, data.data)
        response.success = response.status_code == 201

        return response

    def delete_ldap(self, uuid):
        endpoint = "%s/%s/v1" % (SERVER_CONNECTION_LDAP, uuid)

        response = self.client.delete_json(endpoint)
        response.success = response.status_code == 204

        return response

    def list_ldap(self):
        endpoint = SERVER_CONNECTION_LDAP + "/v1"

        response = self.client.get_json(endpoint)
        response.success = response.status_code == 200

        return response

    def create_smtp(
            self, name=None, description=None,connect_timeout=None, 
            connection_host_name=None, connection_host_port=None,
            connection_ssl=None, connection_user=None, connection_password=None):
        connection_data = DataObject()
        connection_data.add_value_string("hostName", connection_host_name)
        connection_data.add_value("hostPort", connection_host_port)
        connection_data.add_value("ssl", connection_ssl)
        connection_data.add_value("user", connection_user)
        connection_data.add_value("password", connection_password)

        manager_data = DataObject()
        manager_data.add_value("connectTimeout", connect_timeout)

        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("description", description)
        data.add_value_string("type", "smtp")
        data.add_value_not_empty("connection", connection_data.data)
        data.add_value_not_empty("connectionManager", manager_data.data)

        endpoint = SERVER_CONNECTION_SMTP + "/v1"

        response = self.client.post_json(endpoint, data.data)
        response.success = response.status_code == 201

        return response

    def delete_smtp(self, uuid):
        endpoint = "%s/%s/v1" % (SERVER_CONNECTION_SMTP, uuid)

        response = self.client.delete_json(endpoint)
        response.success = response.status_code == 204

        return response

    def list_smtp(self):
        endpoint = SERVER_CONNECTION_SMTP + "/v1"

        response = self.client.get_json(endpoint)
        response.success = response.status_code == 200

        return response

    def create_web_service(
            self, name=None, description=None, locked=None, connection_url=None,
            connection_user=None, connection_password=None,
            connection_ssl_truststore=None, connection_ssl_auth_key=None,
            connection_ssl=None):
        connection_data = DataObject()
        connection_data.add_value_string("url", connection_url)
        connection_data.add_value_string("user", connection_user)
        connection_data.add_value_string("password", connection_password)
        connection_data.add_value_string(
            "sslTruststore", connection_ssl_truststore)
        connection_data.add_value_string("sslAuthKey", connection_ssl_auth_key)
        connection_data.add_value("ssl", connection_ssl)

        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("description", description)
        data.add_value_string("type", "ws")
        data.add_value("locked", locked)
        data.add_value_not_empty("connection", connection_data.data)

        endpoint = SERVER_CONNECTION_WEB_SERVICE + "/v1"

        response = self.client.post_json(endpoint, data.data)
        response.success = response.status_code == 201

        return response

    def delete_web_service(self, uuid):
        endpoint = "%s/%s/v1" % (SERVER_CONNECTION_WEB_SERVICE, uuid)

        response = self.client.delete_json(endpoint)
        response.success = response.status_code == 204

        return response

    def list_web_service(self):
        endpoint = SERVER_CONNECTION_WEB_SERVICE + "/v1"

        response = self.client.get_json(endpoint)
        response.success = response.status_code == 200

        return response

    def list_all(self):
        endpoint = SERVER_CONNECTION_ROOT + "/v1"

        response = self.client.get_json(endpoint)
        response.success = response.status_code == 200

        return response
