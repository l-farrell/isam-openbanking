"""
Find more at: https://github.com/l-farrell/isam-ob/settings
"""

import logging

from pyisam.util.model import DataObject, Response
from pyisam.util.restclient import RESTClient


FIDO2_RP = "/iam/access/v8/fido2/relying-parties"

logger = logging.getLogger(__name__)


class Fido2(object):

    def __init__(self, base_url, username, password):
        super(Fido2, self).__init__()
        self.client = RESTClient(base_url, username, password)

    

    def create_relying_party(self,
            name, 
            rp_id,
            origins,
            admin_group="adminGroup",
            metadata_set=[],
            metadata_soft_fail=True,
            statement_types=["basic", "self", "attCA", "none"],
            statement_formats=[ "fido-u2f", "packed", "tpm", "android-key", "android-safetynet", "none"],
            public_key_algorithms=["SHA256withECDSA","SHA256withRSA"],
            attestation_max_age=60000, clock_skew=30000):
        
        attestation = DataObject()
        attestation.add_value("statementTypes", statement_types)
        attestation.add_value("statementFormats", statement_formats)
        attestation.add_value('publicKeyAlgorithms', public_key_algorithms)

        android = DataObject()
        android.add_value('attestationMaxAge', attestation_max_age)
        android.add_value('clockSkew', clock_skew)

        fido_options = DataObject()
        fido_options.add_value("origins", origins )
        fido_options.add_value("attestation", attestation.data)
        fido_options.add_value("metadataSet",metadata_set )
        fido_options.add_value("metadataSoftFail", metadata_soft_fail)

        fido_options.add_value('android-safetynet', android.data)



        rp_options = DataObject()
        rp_options.add_value("impersonationGroup", admin_group)

        data = DataObject()
        data.add_value("fidoServerOptions", fido_options.data)
        data.add_value("name",name)
        data.add_value("rpId",rp_id)
        data.add_value("relyingPartyOptions",rp_options.data)

        response = self.client.post_json(FIDO2_RP, data.data)
        response.success = response.status_code == 201

        return response



    def list_relying_parties(self):

        response = self.client.get_json(FIDO2_RP)
        response.success = response.status_code == 200

        return response
