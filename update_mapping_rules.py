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



LOG_LEVEL = "logging-level"

BASE_URL = "management-url" #
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
OAUTH_CLIENT = "client"
TRACE_SPEC= "trace-spec"

def add_pyisam_to_path(logger=None):
    cwd = os.path.dirname(os.path.realpath(__file__))
    logger and logger.debug("cwd: %s", cwd)
    pyisam_root = os.path.join(cwd, "pyisam")
    if not os.path.isdir(pyisam_root):
        logger and logger.warn("pyisam directory doesn't exist: expected it at %s", pyisam_root)
    sys.path.append(pyisam_root)



def configure_loggers(level):
    if level < logging.INFO:
        logging.getLogger().setLevel(level)
    else:
        logging.getLogger("Common").setLevel(level)
        logging.getLogger("BaseConfig").setLevel(level)
        logging.getLogger("ExtendedConfig").setLevel(level)
        logging.getLogger("ExtraConfig").setLevel(level)

def deflate_to_id(obj):
    return map(lambda d : d['id'], obj)

def ok(fp, *args, **kwargs):
    result = fp(*args, **kwargs)
    if result.success != True:
        print (result)
        print (result.json)
        raise Exception("failed calling {0} with {1}".format(fp, args))
    return result

if __name__ == '__main__':

    add_pyisam_to_path()

    #from pyisam.pyisam import Factory
    import pyisam

    

    #init mpyisam, load config
    with open('settings.yml', 'r') as stream:

        properties = yaml.load(stream, Loader=yaml.FullLoader)
        configure_loggers(properties.get(LOG_LEVEL, logging.INFO))


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
        trace_spec = properties.get(TRACE_SPEC)

        oauth_definition = json.loads(properties.get(OAUTH_DEFINITION))
        oauth_client = json.loads(properties.get(OAUTH_CLIENT))


        factory = pyisam.Factory(url, user, passwd)    
        ss = factory.get_system_settings()
        web = factory.get_web_settings()
        aac = factory.get_access_control()
        fed = factory.get_federation()

        
        # at this point we'd want the OB mapping rules
        # Maybe a server connection for the user lookup helper?
        # Template files for access policy
        #
        #first, lets figure out the pre/post rules


        response = ok(aac.mapping_rules.get_rule, filter="name startswith OpenBanking")

        pre_token_id = list(filter(lambda x: "pre_token" in x['fileName'], response.json))[0]['id']
        post_token_id = list(filter(lambda x: "post_token" in x['fileName'], response.json))[0]['id']

        print ("Updating OB pre rule....", end = "")
        ok(aac.mapping_rules.update_rule, pre_token_id, "./pre_token_generation.js")
        print("Done!");
        print ("Updating OB post rule....", end = "")
        ok(aac.mapping_rules.update_rule, post_token_id, "./post_token_generation.js")
        print("Done!");

        print ("Updating ssa rule....", end = "")

        response = ok(aac.mapping_rules.get_rule, filter="name startswith {}".format("SSA"))
        rules = json.loads(response.data)
        ssa_rule = None
        if 0 == len(rules):
            print("No...", end="")
        else:
            print("Yes...", end="")
            ssa_rule=rules[0]['id']
            ok(aac.mapping_rules.update_rule, ssa_rule, "./ssa.js")
            print("Updated!")



        print("Done!");

        ok(ss.configuration.deploy_pending_changes)
        #publish so that webseal restarts
        if factory.is_docker():
            ok(ss.docker.publish)
            print("Published docker image.")

        print("Done! Ready to run a smarter bank.")

