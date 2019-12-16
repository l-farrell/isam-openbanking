#!python3 

import requests
import urllib3
import yaml
import logging
import os
import sys
import json
import time


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)




BASE_URL = "management-url"
USER = "admin-username"
PASSWORD = "admin-password"
PASSWORD_OLD = "admin-password-old"

WEB_CODE="web-code"
AAC_CODE="aac-code"
FED_CODE="fed-code"

DB_CERT = "db-cert"
RT_CERT = "rt-cert"
RT_CERT_PASSWD = "rt-cert-passwd"
RT_CERT_LBL = "rt-cert-label"
OAUTH_DEFINITION = "definition"
SCIM_CONFIG = "scim-config"
JWT_VALIDATE_CHAIN_TEMPLATE = "jwt-validate-chain-template"
JWT_VALIDATE_CHAIN_PROPERTIES = "jwt-validate-properties"
JWT_SSA_PROPERTIES = "jwt-ssa-properties"

SSA_INFOMAP = "ssa-infomap"

OAUTH_CLIENT = "client"
RESOURCE_SERVER = "resource-server"
TRACE_SPEC= "trace-spec"
JUNCTION_ROOT_PAGE="junction-root-page"
LDAP_SERVER="ldap-server"
DB_SERVER="db-server"
RT_SERVER="rt-server"

def add_pyisam_to_path(logger=None):
    cwd = os.path.dirname(os.path.realpath(__file__))
    logger and logger.debug("cwd: %s", cwd)
    pyisam_root = os.path.join(cwd, "pyisam")
    if not os.path.isdir(pyisam_root):
        logger and logger.warn("pyisam directory doesn't exist: expected it at %s", pyisam_root)
    sys.path.append(pyisam_root)

def deflate_to_id(obj):
    result = []
    for i in obj:
        result.append(i['id'])
    return result
  
def ok(fp, *args, **kwargs):
    result = fp(*args, **kwargs)
    if result.success != True:
        print (result)
        print (result.json)
        print (result.data)
        raise Exception("failed calling {0} with {1}".format(fp, args))
    return result
if __name__ == '__main__':

    logging.getLogger().setLevel(logging.DEBUG)

    add_pyisam_to_path()

    #from pyisam.pyisam import Factory
    import pyisam

    #load config
    with open('settings.yml', 'r') as stream:

        properties = yaml.load(stream, Loader=yaml.FullLoader)


        url = properties.get(BASE_URL)
        user = properties.get(USER)
        passwd = properties.get(PASSWORD)
        passwd_old = properties.get(PASSWORD_OLD)
        web_code = properties.get(WEB_CODE)
        aac_code = properties.get(AAC_CODE)
        fed_code = properties.get(FED_CODE)
        db_cert = properties.get(DB_CERT)
        rt_cert = properties.get(RT_CERT)
        rt_cert_lbl = properties.get(RT_CERT_LBL)
        rt_cert_passwd = properties.get(RT_CERT_PASSWD)
        isam_ldap_server = properties.get(LDAP_SERVER)
        isam_db_server = properties.get(DB_SERVER)
        runtime_srv = properties.get(RT_SERVER)

        trace_spec = properties.get(TRACE_SPEC)

        junction_root_page = properties.get(JUNCTION_ROOT_PAGE)

        oauth_definition = json.loads(properties.get(OAUTH_DEFINITION))
        oauth_client = json.loads(properties.get(OAUTH_CLIENT))
        jwt_validate_chain_template = json.loads(properties.get(JWT_VALIDATE_CHAIN_TEMPLATE))
        jwt_validate_chain_properties = json.loads(properties.get(JWT_VALIDATE_CHAIN_PROPERTIES))
        jwt_ssa_properties = json.loads(properties.get(JWT_SSA_PROPERTIES))

        ssa_policy = properties.get(SSA_INFOMAP)

        scim_config = json.loads(properties.get(SCIM_CONFIG))
        factory = pyisam.Factory(url, user, passwd)    
        ss = factory.get_system_settings()
        web = factory.get_web_settings()
        fed = factory.get_federation()
        aac = factory.get_access_control()

 
        if ss.first_steps.get_sla_status().json['accepted'] == False:
            ss.first_steps.set_sla_status()
            print("Sla accepted.")
        else:
            print("Sla already accepted.")

        if ss.first_steps.get_setup_status().json['configured'] == False:
            #start by accepting the license agreement
            ss.first_steps.set_setup_complete()
            print("Setup completed.")
        else:
            print("First steps already complete.")



        response = ss.ssl_certificates.get_signer("rt_profile_keys", "isam-ldap")
        need_deploy = False

        if response.success != True:
            ok(ss.ssl_certificates.load_signer,"rt_profile_keys", server=isam_ldap_server, port=636,label="isam-ldap")
            need_deploy = True
        
            print("Loaded ldap certificate. (RT)")

        # load and trust the db and ldap
        # externalise the db
        if factory.is_docker():

            response = ss.ssl_certificates.get_signer("lmi_trust_store", "isam-db")
            if response.success != True:
                ok(ss.ssl_certificates.import_signer, "lmi_trust_store", db_cert, label="isam-db")
                need_deploy = True
                print("Loaded db certificate #1.")

            response = ss.ssl_certificates.get_signer("rt_profile_keys", "isam-db")
            if response.success != True:
                ok(ss.ssl_certificates.import_signer, "rt_profile_keys", db_cert, label="isam-db")
                need_deploy = True
                print("Loaded db certificate #2.")

            response = ss.ssl_certificates.get_personal("rt_profile_keys", label=rt_cert_lbl)
            if response.success != True:
                ok(ss.ssl_certificates.import_personal, "rt_profile_keys", "runtime.p12", "passw0rd")
                print("Added runtime.p12 to rt_profile_keys.")

        if need_deploy:
            ok(ss.configuration.deploy_pending_changes)
            need_deploy = False


        response = ok(ss.runtime_db.get_db)

        if 'hvdb_address' not in response.json or response.json['hvdb_address'] != isam_db_server:
            ok(ss.runtime_db.set_db, host=isam_db_server,port="5432",db_name="isam",secure=True,
                    user="postgres",passwd="Passw0rd",db_type="postgresql")
            print("Configured external HVDB.")
            ok(ss.configuration.deploy_pending_changes)

            #now activate

        response = ok(ss.licensing.get_activated_modules)
        ids = deflate_to_id(response.json)
        
        print("Checking activation...", end="")
        print("Existng activiations: {}...".format(ids), end="")
        if 'wga' not in ids:
            print("adding wga...", end = "")
            ok(ss.licensing.activate_module, web_code)
            need_deploy = True
        if 'mga' not in ids:
            print("adding aac...", end="")
            ok(ss.licensing.activate_module, aac_code)
            need_deploy = True
        if 'federation' not in ids:
            print("adding fed...", end="")
            ok(ss.licensing.activate_module, fed_code)
            need_deploy = True

        if need_deploy:
            print("activated")
            ok(ss.configuration.deploy_pending_changes)
            need_deploy = False
        else:
            print("Already activated.")


        #need to set the listening cert
        print("Setting AAC runtime listening cert to be the uploaded cert...", end="")

        ok(aac.runtime_parameters.update, "keystore_label", "runtime")
        ok(aac.runtime_parameters.update, "trace_specification", trace_spec)

        print ("Done")

        # Creating validate-jwt template
        response = fed.sts_templates.get_templates()
        templates = json.loads(response.data)
        template = None
        for possible_template in templates:
            if possible_template['name'] == 'validate-jwt':
                template = possible_template
                break   



        if template == None:
            print("creating validate-jwt template...", end="")

            response = ok(fed.sts_templates.create_template,"validate-jwt", "a simple jwt -> stsuu validate chain", jwt_validate_chain_template)
            template = response.id_from_location
            print("created!")
            need_deploy = True
        else:
            print("validate-jwt template already exists")
            template = template['id']

        # Creating validate-ssa chain
        response = fed.sts_chains.get_chains()
        chains = json.loads(response.data)
        chain = None
        for possible_chain in chains:
            if possible_chain['name'] == 'validate-req-jwt':
                chain = possible_chain
                break   

        if chain == None:
            print("creating validate-req-jwt chain...", end="")
            response = ok(fed.sts_chains.create_chain,"validate-req-jwt", "a simple jwt -> stsuu validate chain for validating request JWTs", template, 'http://schemas.xmlsoap.org/ws/2005/02/trust/Validate', 'urn:validate:ssa', 'urn:validate:ssa', jwt_ssa_properties)
            chain = response.data
            print("created!")
            need_deploy = True
        else:
            print("validate-req-jwt chain already exists")

        # Creating validate-jwt chain
        response = fed.sts_chains.get_chains()
        chains = json.loads(response.data)
        chain = None
        for possible_chain in chains:
            if possible_chain['name'] == 'validate-req-jwt':
                chain = possible_chain
                break   

        if chain == None:
            print("creating validate-req-jwt chain...", end="")
            response = ok(fed.sts_chains.create_chain,"validate-req-jwt", "a simple jwt -> stsuu validate chain for validating request JWTs", template, 'http://schemas.xmlsoap.org/ws/2005/02/trust/Validate', 'https://localhost/sps/oauth/oauth20', 'REGEXP:(urn:ibm:ITFIM:oauth20:client_request:.*)', jwt_validate_chain_properties)
            chain = response.data
            print("created!")
            need_deploy = True
        else:
            print("validate-req-jwt chain already exists")

        # Creating validate-jwt chain

        response = fed.sts_chains.get_chains()
        chains = json.loads(response.data)
        chain = None
        for possible_chain in chains:
            if possible_chain['name'] == 'validate-auth-jwt':
                chain = possible_chain
                break   

        if chain == None:
            print("creating validate-auth-jwt chain...", end="")

            response = ok(fed.sts_chains.create_chain,"validate-auth-jwt", "a simple jwt -> stsuu validate chain for validating request JWTs", template, 'http://schemas.xmlsoap.org/ws/2005/02/trust/Validate', 'https://localhost/sps/oauth/oauth20', 'REGEXP:(urn:ietf:params:oauth:client-assertion-type:jwt-bearer:.*)', jwt_validate_chain_properties)
            chain = response.data
            print("created!")
            need_deploy = True
        else:
            print("validate-auth-jwt chain already exists")

        #configure oauth initially
        response = ok(aac.api_protection.list_definitions, filter="name equals {}".format(oauth_definition['name']))

        if len(response.json) == 0 or 'name' not in response.json[0]:
            print ("Need to create definition...{0}".format(oauth_definition), end="")

            d = oauth_definition
            oidc = d['oidc']
            response = ok(aac.api_protection.create_definition,name=d['name'], description=d['description'],
                    tcm_behavior=d['tcmBehavior'],issue_refresh_token=d['issueRefreshToken'], 
                    enable_multiple_refresh_tokens_for_fault_tolerance=d['enableMultipleRefreshTokensForFaultTolerance'],
                    grant_types=d['grantTypes'], oidc_enabled=oidc['enabled'],
                    iss=oidc['iss'], poc=oidc['poc'], lifetime=oidc['lifetime'], alg=oidc['alg'],
                    db=oidc['db'], cert=oidc['cert'], enc_enabled=False, enc_alg=None, enc_enc=None, access_policy_id=None,
                    dynamic_register=True, dynamic_register_issue_secret=True)
            def_id = response.id_from_location
            print("...Created.")
        else:
            print ("Definition  already exists")
            def_id = response.json[0]['id']

        #configure our API client
        response = ok(aac.api_protection.list_clients, filter="clientId equals static_client")

        if len(response.json) == 0 or 'name' not in response.json[0]:
            print ("Need to create client...{0}".format(oauth_client), end="")
            c = oauth_client
            ok(aac.api_protection.create_client, name=c['name'], redirect_uri=c['redirectUri'], company_name=c['companyName'],
                    company_url=c['companyUrl'], contact_person=c['contactPerson'], contact_type=c['contactType'],
                    email=c['email'], phone=None, other_info=None, definition=def_id,
                    client_id=c['clientId'], client_secret=c['clientSecret'], require_pkce_verification=None,
                    jwks_uri=None, encryption_db=None, encryption_cert=None)
            print("...Created.")
        else:
            print ("Client already exists.")

        response = ok(aac.mapping_rules.get_rule, filter="name startswith {}".format(oauth_definition['name']))

        pre_token_id = list(filter(lambda x: "pre_token" in x['fileName'], response.json))[0]['id']
        post_token_id = list(filter(lambda x: "post_token" in x['fileName'], response.json))[0]['id']

        print ("Updating  pre rule....", end = "")
        ok(aac.mapping_rules.update_rule, pre_token_id, "./pre_token_generation.js")
        print("Done!");
        print ("Updating  post rule....", end = "")
        ok(aac.mapping_rules.update_rule, post_token_id, "./post_token_generation.js")
        print("Done!");

        #now configure the RTE
        response = ok(web.runtime_component.get_status)
        if 'status' not in response.json or response.json['status'] == "Unconfigured":
            print ("configring RTE...", end="")
            ok(web.runtime_component.configure, ps_mode='local', user_registry='ldap', admin_password='passw0rd',
                    ldap_password='Passw0rd', admin_cert_lifetime=1460, ssl_compliance=None,
                    ldap_host=isam_ldap_server, ldap_port=636, isam_domain='Default', ldap_dn='cn=root,secAuthority=Default',
                    ldap_suffix=None, ldap_ssl_db="rt_profile_keys", ldap_ssl_label="isam-ldap",
                    isam_host=None, isam_port=7315)
            print("Done.")
        else:
            print ("RTE already configured")

        #now configure webseal

        names = deflate_to_id(ok(web.reverse_proxy.list_instances).json)

        if 'default' not in names:
            ok(web.reverse_proxy.create_instance,inst_name='default', host="localhost", admin_id="sec_master", admin_pwd="passw0rd",
                    ssl_yn="yes", key_file="rt_profile_keys", cert_label="isam-ldap", ssl_port="636",
                    http_yn="no", http_port=None, https_yn="yes", https_port=None,
                    nw_interface_yn=None, ip_address=None, listening_port=None,domain="Default")

            response = ss.ssl_certificates.get_personal("pdsrv", label=rt_cert_lbl)
            if response.success is not True:
                ok(ss.ssl_certificates.import_personal, "pdsrv", rt_cert, rt_cert_passwd)
                print("Added runtime.p12 to pdsrv.")

            ok(web.reverse_proxy.update_configuration_stanza_entry, 'default', 'ssl', 'webseal-cert-keyfile-label', rt_cert_lbl)

            print("Created instance 'default.")

            print("Setting up external users for oauth-auth")
            ok(web.reverse_proxy.update_configuration_stanza_entry, 'default', 'oauth', 'external-user-identity-attribute','username')
            ok(web.reverse_proxy.update_configuration_stanza_entry, 'default', 'oauth', 'user-identity-attribute','not-username')

            #print("Setting URL filtering for SCIM")
            #ok(web.reverse_proxy.add_configuration_stanza_entry, 'default', 'filter-content-types', 'type','application/scim+json')
            #ok(web.reverse_proxy.add_configuration_stanza_entry, 'default', 'script-filtering', 'rewrite-absolute-with-absolute','yes')
            #ok(web.reverse_proxy.update_configuration_stanza_entry, 'default', 'script-filtering', 'script-filter','yes')


        else:
            print ("Instance 'default' already exists.") 

        ok(web.reverse_proxy.configure_api_protection, "default", hostname=runtime_srv, port=443,
                username="easuser", password="passw0rd", reuse_certs=True,reuse_acls=False, api=True,
                browser=True, junction="/isam", auth_register=False)

        print("Successfully invoked OAuth Config.")
        print("Checking POC Configuration...", end="")

        profile_name = 'pac with authn macros'
        response = ok(fed.poc.get_profiles)
        previous_profile = list(filter(lambda x: profile_name == x['name'], response.json))
        profile_id = None
        if len(previous_profile) < 1:
            profile = ok(fed.poc.create_like_credential, profile_name, "pac like poc config, but with the authentication macro 'SSOREQUEST'",
                    authenticate_callbacks={ "authentication.macros":"%SSOREQUEST%" }, local_id_callbacks=None,
                    sign_out_callbacks=None, sign_in_callbacks=None)
            profile_id = profile.id_from_location
            print('created profile {0}'.format(profile.id_from_location))
        else:
            profile_id = previous_profile[0]['id']
            print('profile {0} already existed'.format(profile_id))



        ok(fed.poc.set_current_profile, profile_id)
        print("Set active POC ProfileId to {0}".format(profile_id))


        print("Configuring ISAM Runtime server connection")


        response = ok(aac.server_connections.list_isam)
        connections = json.loads(response.data)
        connection = None
        for possible_connection in connections:
            if possible_connection['name'] == 'ISAM':
                connection = possible_connection
                break   

        if connection == None:
                print("Creating ISAM Runtime server connection...", end="")
                response = ok(aac.server_connections.create_isam,"ISAM","Connection to the ISAM runtime",
                        None, "cn=root,secAuthority=Default","passw0rd","rt_profile_keys","","false")

                need_deploy = True
        else:
                print("ISAM Runtime server connection exists! ", end="")

        if need_deploy:
            ok(ss.configuration.deploy_pending_changes)
            need_deploy = False

        # print("Setting scim config....", end="")
        # response = ok(aac.scim_config.update,scim_config)
        # need_deploy = True
        # print("Done")

        # print("Setting scim ISAM user config....", end="")
        # response = ok(aac.scim_config.update_isam_user, "ISAM", "Default","isamruntime", False)
        # need_deploy = True
        # print("Done")


        print("Requiring path based authentication to the authentication service")
        response = ok(aac.advanced_config.update,12503, "both")
        response = aac.template_files.get_directory("C/authsvc/authenticator/ssa")
        if not response.success:
            print("Creating infomap template dir ")
            response = ok(aac.template_files.create_directory,"C/authsvc/authenticator/", "ssa")

        response = aac.template_files.get_directory("C/authsvc/authenticator/ssa/template.json")
        if not response.success:
            print("Creating infomap template")
            response = ok(aac.template_files.create_file,"C/authsvc/authenticator/ssa","template.json", "@JSON@")

        print("Uploading SSA mapping rule...", end="")
        print("Does rule already exists? ", end="")

        response = ok(aac.mapping_rules.get_rule, filter="name startswith {}".format("SSA"))
        rules = json.loads(response.data)
        ssa_rule = None
        if 0 == len(rules):
            print("No...", end="")
            response = ok(aac.mapping_rules.create_rule, "./ssa.js", "SSA", "InfoMap")
            ssa_rule = response.id_from_location
            print("Created!")
            need_deploy = True
        else:
            print("Yes...", end="")
            ssa_rule=rules[0]['id']
            ok(aac.mapping_rules.update_rule, ssa_rule, "./ssa.js")
            print("Updated!")
            need_deploy = True


        print("Does mechanism exist...", end="")
        response = ok(aac.authentication.list_mechanisms,filter="name equals ssa")
        mechanisms = json.loads(response.data)
        mech_id = None
        if len(mechanisms) == 0:
            print("No, creating....", end = "")
            response = ok(aac.authentication.create_mechanism,"Used to parse SSAs",
                    "ssa", 'urn:ibm:security:authentication:asf:mechanism:ssa', 13, properties=[{"value":"C/authsvc/authenticator/ssa/template.json","key":"infoMap.HTMLPage"},{"value":"SSA","key":"infoMap.JSRule"}])
            mech_id = response.id_from_location
            print("Created {}".format(mech_id))
            need_deploy = True
        else:
            mech_id = mechanisms[0]['id']
            print("Exists {}".format(mech_id))

        response = ok(aac.authentication.list_policies,filter="name equals ssa")
        policies = json.loads(response.data)
        policy_id = None

        if len(policies) == 0:
            print("Policy doesn't exist, creating")
            response = ok(aac.authentication.create_policy, "ssa", ssa_policy, "urn:ibm:security:authentication:asf:ssa",
                    "Policy for consuming SSAs", None, None, None, None)
            policy_id = response.id_from_location
            print("{} created.".format(policy_id))
            need_deploy = True
        else:
            print("Policy already exists")


        #print("Configuring SSA infomap")


        # Do our generic pdadmin workload here:
        #
        print("Creating testuser, testadmin, adminGroup....")
        pdadmin = ok(web.policy_administration.execute, 'sec_master', 'passw0rd', 
                    [
                    #"server task default-webseald-localhost create -t ssl -p 443 -h isam-runtime -B -U easuser -W passw0rd -c iv_user,iv_groups,iv_creds -f -x /scim",
                    "server task default-webseald-localhost create -t tcp -p 8081 -h ssahopper -b ignore -f /ssa",
                    "acl attach isam_oauth_unauth /WebSEAL/localhost-default/ssa",
                    "acl attach isam_oauth_nobody /WebSEAL/localhost-default/isam/sps/authsvc",
                    "acl attach isam_oauth_unauth /WebSEAL/localhost-default/isam/sps/authsvc/policy/ssa",
                    "user create testuser cn=testuser,dc=iswga testuser testuser passw0rd",
                    "user modify testuser account-valid yes",
                    "user create testadmin cn=testadmin,dc=iswga testadmin testadmin passw0rd",
                    "user modify testadmin account-valid yes",
                    "group create adminGroup cn=adminGroup,dc=iswga adminGroup",
                    "group modify adminGroup add testadmin"
                    ])


        print (pdadmin.json['result'])

        ok(ss.configuration.deploy_pending_changes)
        #publish so that webseal restarts
        if factory.is_docker():
            ok(ss.docker.publish)
            print("Published docker image.")

        print("Done! Ready to run a smarter bank.")
