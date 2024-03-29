"""
Find more at: https://github.com/l-farrell/isam-ob/settings
"""

import logging

from pyisam.util.model import DataObject, Response
from pyisam.util.restclient import RESTClient


CLIENTS = "/iam/access/v8/clients"
DEFINITIONS = "/iam/access/v8/definitions"
MAPPING_RULES = "/iam/access/v8/mapping-rules"

logger = logging.getLogger(__name__)


class APIProtection(object):

    def __init__(self, base_url, username, password):
        super(APIProtection, self).__init__()
        self.client = RESTClient(base_url, username, password)

    

    def create_client(
            self, name=None, redirect_uri=None, company_name=None,
            company_url=None, contact_person=None, contact_type=None,
            email=None, phone=None, other_info=None, definition=None,
            client_id=None, client_secret=None):
        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("redirectUri", redirect_uri)
        data.add_value_string("companyName", company_name)
        data.add_value_string("companyUrl", company_url)
        data.add_value_string("contactPerson", contact_person)
        data.add_value_string("contactType", contact_type)
        data.add_value_string("email", email)
        data.add_value_string("phone", phone)
        data.add_value_string("otherInfo", other_info)
        data.add_value_string("definition", definition)
        data.add_value_string("clientId", client_id)
        data.add_value_string("clientSecret", client_secret)

        response = self.client.post_json(CLIENTS, data.data)
        response.success = response.status_code == 201

        return response

    def update_client(
            self, id=None, name=None, redirect_uri=None, company_name=None,
            company_url=None, contact_person=None, contact_type=None,
            email=None, phone=None, other_info=None, definition=None,
            client_id=None, client_secret=None):
        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("redirectUri", redirect_uri)
        data.add_value("companyName", company_name)
        data.add_value_string("companyUrl", company_url)
        data.add_value_string("contactPerson", contact_person)
        data.add_value_string("contactType", contact_type)
        data.add_value_string("email", email)
        data.add_value_string("phone", phone)
        data.add_value_string("otherInfo", other_info)
        data.add_value_string("definition", definition)
        data.add_value_string("clientId", client_id)
        data.add_value_string("clientSecret", client_secret)

        response = self.client.put_json(CLIENTS+"/"+str(id), data.data)
        response.success = response.status_code == 204

        return response

    def delete_client(self, id):
        endpoint = "%s/%s" % (CLIENTS, id)

        response = self.client.delete_json(endpoint)
        response.success = response.status_code == 204

        return response

    def list_clients(self, sort_by=None, count=None, start=None, filter=None):
        parameters = DataObject()
        parameters.add_value_string("sortBy", sort_by)
        parameters.add_value_string("count", count)
        parameters.add_value_string("start", start)
        parameters.add_value_string("filter", filter)

        response = self.client.get_json(CLIENTS, parameters.data)
        response.success = response.status_code == 200

        return response

    def create_definition(
            self, name=None, description=None, tcm_behavior=None,
            token_char_set=None, access_token_lifetime=None,
            access_token_length=None, authorization_code_lifetime=None,
            authorization_code_length=None, refresh_token_length=None,
            max_authorization_grant_lifetime=None, pin_length=None,
            enforce_single_use_authorization_grant=None,
            issue_refresh_token=None,
            enforce_single_access_token_per_grant=None,
            enable_multiple_refresh_tokens_for_fault_tolerance=None,
            pin_policy_enabled=None, grant_types=None):
        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("description", description)
        data.add_value_string("tcmBehavior", tcm_behavior)
        data.add_value_string("tokenCharSet", token_char_set)
        data.add_value("accessTokenLifetime", access_token_lifetime)
        data.add_value("accessTokenLength", access_token_length)
        data.add_value("authorizationCodeLifetime", authorization_code_lifetime)
        data.add_value("authorizationCodeLength", authorization_code_length)
        data.add_value("refreshTokenLength", refresh_token_length)
        data.add_value(
            "maxAuthorizationGrantLifetime", max_authorization_grant_lifetime)
        data.add_value("pinLength", pin_length)
        data.add_value(
            "enforceSingleUseAuthorizationGrant",
            enforce_single_use_authorization_grant)
        data.add_value("issueRefreshToken", issue_refresh_token)
        data.add_value(
            "enforceSingleAccessTokenPerGrant",
            enforce_single_access_token_per_grant)
        data.add_value(
            "enableMultipleRefreshTokensForFaultTolerance",
            enable_multiple_refresh_tokens_for_fault_tolerance)
        data.add_value("pinPolicyEnabled", pin_policy_enabled)
        data.add_value("grantTypes", grant_types)

        response = self.client.post_json(DEFINITIONS, data.data)
        response.success = response.status_code == 201

        return response

    def update_definition(
            self, definition_id=None, name=None, description=None, tcm_behavior=None,
            token_char_set=None, access_token_lifetime=None,
            access_token_length=None, authorization_code_lifetime=None,
            authorization_code_length=None, refresh_token_length=None,
            max_authorization_grant_lifetime=None, pin_length=None,
            enforce_single_use_authorization_grant=None,
            issue_refresh_token=None,
            enforce_single_access_token_per_grant=None,
            enable_multiple_refresh_tokens_for_fault_tolerance=None,
            pin_policy_enabled=None, grant_types=None, oidc_enabled=False,
            iss=None, poc=None, lifetime=None, alg=None, db=None, cert=None,
            enc_enabled=False, enc_alg=None, enc_enc=None, access_policy_id=None):
        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("description", description)
        data.add_value_string("tcmBehavior", tcm_behavior)
        data.add_value_string("tokenCharSet", token_char_set)
        data.add_value("accessTokenLifetime", access_token_lifetime)
        data.add_value("accessTokenLength", access_token_length)
        data.add_value("authorizationCodeLifetime", authorization_code_lifetime)
        data.add_value("authorizationCodeLength", authorization_code_length)
        data.add_value("refreshTokenLength", refresh_token_length)
        data.add_value(
            "maxAuthorizationGrantLifetime", max_authorization_grant_lifetime)
        data.add_value("pinLength", pin_length)
        data.add_value(
            "enforceSingleUseAuthorizationGrant",
            enforce_single_use_authorization_grant)
        data.add_value("issueRefreshToken", issue_refresh_token)
        data.add_value(
            "enforceSingleAccessTokenPerGrant",
            enforce_single_access_token_per_grant)
        data.add_value(
            "enableMultipleRefreshTokensForFaultTolerance",
            enable_multiple_refresh_tokens_for_fault_tolerance)
        data.add_value("pinPolicyEnabled", pin_policy_enabled)
        data.add_value("grantTypes", grant_types)
        data.add_value("accessPolicyId", access_policy_id)
        
        if oidc_enabled:
            oidc = DataObject()
            oidc.add_value("enabled",True)
            oidc.add_value("iss",iss)
            oidc.add_value("poc",poc)
            oidc.add_value("lifetime",lifetime)
            oidc.add_value("alg",alg)
            oidc.add_value("db",db)
            oidc.add_value("cert",cert)
            if enc_enabled:
                enc_data = DataObject()
                enc_data.add_value("db",enc_db)
                enc_data.add_value("cert",enc_cert)
                oidc.add_value("enc",enc_data.data)

            data.add_value("oidc",oidc.data)

        response = self.client.put_json(DEFINITIONS+"/"+str(definition_id), data.data)
        response.success = response.status_code == 204

        return response

    def delete_definition(self, id):
        endpoint = "%s/%s" % (DEFINITIONS, id)

        response = self.client.delete_json(endpoint)
        response.success = response.status_code == 204

        return response

    def list_definitions(
            self, sort_by=None, count=None, start=None, filter=None):
        parameters = DataObject()
        parameters.add_value_string("sortBy", sort_by)
        parameters.add_value_string("count", count)
        parameters.add_value_string("start", start)
        parameters.add_value_string("filter", filter)

        response = self.client.get_json(DEFINITIONS, parameters.data)
        response.success = response.status_code == 200

        return response

    def create_mapping_rule(
            self, name=None, category=None, file_name=None, content=None):
        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("category", category)
        data.add_value_string("fileName", file_name)
        data.add_value_string("content", content)

        response = self.client.post_json(MAPPING_RULES, data.data)
        response.success = response.status_code == 201

        return response

    def list_mapping_rules(
            self, sort_by=None, count=None, start=None, filter=None):
        parameters = DataObject()
        parameters.add_value_string("sortBy", sort_by)
        parameters.add_value_string("count", count)
        parameters.add_value_string("start", start)
        parameters.add_value_string("filter", filter)

        response = self.client.get_json(MAPPING_RULES, parameters.data)
        response.success = response.status_code == 200

        return response

    def import_mapping_rule(self, id, file_path):
        response = Response()

        try:
            with open(file_path, 'rb') as mapping_rule:
                files = {"file": mapping_rule}
                endpoint = "%s/%s/file" % (MAPPING_RULES, id)
                accept_type = "%s,%s" % ("application/json", "text/html")

                response = self.client.post_file(
                    endpoint, accept_type=accept_type, files=files)

                response.success = response.status_code == 200
        except IOError as e:
            logger.error(e)
            response.success = False

        return response

    def update_mapping_rule(self, id, content=None):
        data = DataObject()
        data.add_value_string("content", content)

        endpoint = "%s/%s" % (MAPPING_RULES, id)

        response = self.client.put_json(endpoint, data.data)
        response.success = response.status_code == 204

        return response

class APIProtection9040(APIProtection):

    def __init__(self, base_url, username, password):
        super(APIProtection, self).__init__()
        self.client = RESTClient(base_url, username, password)

    def get_valid_grant_types(self):
        return ["AUTHORIZATION_CODE","RESOURCE_OWNER_PASSWORD_CREDENTIALS","IMPLICIT_GRANT", "CLIENT_CREDENTIALS", "JWT_BEARER", "SAML_BEARER"]

    def create_definition(
            self, name=None, description=None, tcm_behavior=None,
            token_char_set=None, access_token_lifetime=None,
            access_token_length=None, authorization_code_lifetime=None,
            authorization_code_length=None, refresh_token_length=None,
            max_authorization_grant_lifetime=None, pin_length=None,
            enforce_single_use_authorization_grant=None,
            issue_refresh_token=None,
            enforce_single_access_token_per_grant=None,
            enable_multiple_refresh_tokens_for_fault_tolerance=None,
            pin_policy_enabled=None, grant_types=None, oidc_enabled=False,
            iss=None, poc=None, lifetime=None, alg=None, db=None, cert=None,
            enc_enabled=False, enc_alg=None, enc_enc=None, access_policy_id=None):
        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("description", description)
        data.add_value_string("tcmBehavior", tcm_behavior)
        data.add_value_string("tokenCharSet", token_char_set)
        data.add_value("accessTokenLifetime", access_token_lifetime)
        data.add_value("accessTokenLength", access_token_length)
        data.add_value("authorizationCodeLifetime", authorization_code_lifetime)
        data.add_value("authorizationCodeLength", authorization_code_length)
        data.add_value("refreshTokenLength", refresh_token_length)
        data.add_value(
            "maxAuthorizationGrantLifetime", max_authorization_grant_lifetime)
        data.add_value("pinLength", pin_length)
        data.add_value(
            "enforceSingleUseAuthorizationGrant",
            enforce_single_use_authorization_grant)
        data.add_value("issueRefreshToken", issue_refresh_token)
        data.add_value(
            "enforceSingleAccessTokenPerGrant",
            enforce_single_access_token_per_grant)
        data.add_value(
            "enableMultipleRefreshTokensForFaultTolerance",
            enable_multiple_refresh_tokens_for_fault_tolerance)
        data.add_value("pinPolicyEnabled", pin_policy_enabled)
        data.add_value("grantTypes", grant_types)
        data.add_value("accessPolicyId", access_policy_id)

        if oidc_enabled:
            oidc = DataObject()
            oidc.add_value("enabled",True)
            oidc.add_value("iss",iss)
            oidc.add_value("poc",poc)
            oidc.add_value("lifetime",lifetime)
            oidc.add_value("alg",alg)
            oidc.add_value("db",db)
            oidc.add_value("cert",cert)
            if enc_enabled:
                enc_data = DataObject()
                enc_data.add_value("db",enc_db)
                enc_data.add_value("cert",enc_cert)
                oidc.add_value("enc",enc_data.data)

            data.add_value("oidc",oidc.data)

        response = self.client.post_json(DEFINITIONS, data.data)
        response.success = response.status_code == 201

        return response

    def create_client(
            self, name=None, redirect_uri=None, company_name=None,
            company_url=None, contact_person=None, contact_type=None,
            email=None, phone=None, other_info=None, definition=None,
            client_id=None, client_secret=None, require_pkce_verification=None,
            jwks_uri=None, encryption_db=None, encryption_cert=None):
        data = DataObject()
        data.add_value_string("name", name)
        data.add_value("redirectUri", redirect_uri)
        data.add_value_string("companyName", company_name)
        data.add_value_string("companyUrl", company_url)
        data.add_value_string("contactPerson", contact_person)
        data.add_value_string("contactType", contact_type)
        data.add_value_string("email", email)
        data.add_value_string("phone", phone)
        data.add_value_string("otherInfo", other_info)
        data.add_value_string("definition", definition)
        data.add_value_string("clientId", client_id)
        data.add_value_string("clientSecret", client_secret)
        data.add_value_boolean("requirePkce", require_pkce_verification)
        data.add_value_string("jwksUri", jwks_uri)
        data.add_value_string("encryptionDb", encryption_db)
        data.add_value_string("encryptioncert", encryption_cert)

        print("derp")
        print(data.data)

        response = self.client.post_json(CLIENTS, data.data)
        response.success = response.status_code == 201

        return response


class APIProtection9050(APIProtection9040):

    def __init__(self, base_url, username, password):
        super(APIProtection, self).__init__()
        self.client = RESTClient(base_url, username, password)

    def get_valid_grant_types(self):
        return ["AUTHORIZATION_CODE","RESOURCE_OWNER_PASSWORD_CREDENTIALS","IMPLICIT_GRANT", "CLIENT_CREDENTIALS", "JWT_BEARER", "SAML_BEARER", "DEVICE"]

    def create_definition(
            self, name=None, description=None, tcm_behavior=None,
            token_char_set=None, access_token_lifetime=None,
            access_token_length=None, authorization_code_lifetime=None,
            authorization_code_length=None, refresh_token_length=None,
            max_authorization_grant_lifetime=None, pin_length=None,
            enforce_single_use_authorization_grant=None,
            issue_refresh_token=None,
            enforce_single_access_token_per_grant=None,
            enable_multiple_refresh_tokens_for_fault_tolerance=None,
            pin_policy_enabled=None, grant_types=None, oidc_enabled=False,
            iss=None, poc=None, lifetime=None, alg=None, db=None, cert=None,
            enc_enabled=False, enc_alg=None, enc_enc=None, access_policy_id=None,
            dynamic_register=False, dynamic_register_issue_secret=False):
        data = DataObject()
        data.add_value_string("name", name)
        data.add_value_string("description", description)
        data.add_value_string("tcmBehavior", tcm_behavior)
        data.add_value_string("tokenCharSet", token_char_set)
        data.add_value("accessTokenLifetime", access_token_lifetime)
        data.add_value("accessTokenLength", access_token_length)
        data.add_value("authorizationCodeLifetime", authorization_code_lifetime)
        data.add_value("authorizationCodeLength", authorization_code_length)
        data.add_value("refreshTokenLength", refresh_token_length)
        data.add_value(
            "maxAuthorizationGrantLifetime", max_authorization_grant_lifetime)
        data.add_value("pinLength", pin_length)
        data.add_value(
            "enforceSingleUseAuthorizationGrant",
            enforce_single_use_authorization_grant)
        data.add_value("issueRefreshToken", issue_refresh_token)
        data.add_value(
            "enforceSingleAccessTokenPerGrant",
            enforce_single_access_token_per_grant)
        data.add_value(
            "enableMultipleRefreshTokensForFaultTolerance",
            enable_multiple_refresh_tokens_for_fault_tolerance)
        data.add_value("pinPolicyEnabled", pin_policy_enabled)
        data.add_value("grantTypes", grant_types)
        data.add_value("accessPolicyId", access_policy_id)

        if oidc_enabled:
            oidc = DataObject()
            oidc.add_value("enabled",True)
            oidc.add_value("iss",iss)
            oidc.add_value("poc",poc)
            oidc.add_value("lifetime",lifetime)
            oidc.add_value("alg",alg)
            oidc.add_value("db",db)
            oidc.add_value("cert",cert)
            if enc_enabled:
                enc_data = DataObject()
                enc_data.add_value("db",enc_db)
                enc_data.add_value("cert",enc_cert)
                oidc.add_value("enc",enc_data.data)

            oidc.add_value("dynamicClients",dynamic_register)
            oidc.add_value("issueSecret",dynamic_register_issue_secret)

            data.add_value("oidc",oidc.data)

        response = self.client.post_json(DEFINITIONS, data.data)
        response.success = response.status_code == 201

        return response

