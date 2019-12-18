importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.modules.http.stsclient.STSClientHelper);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.MMFAMappingExtUtils);
importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Headers);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
importClass(Packages.java.util.ArrayList);
importClass(Packages.java.util.HashMap);


/**
 * Discover the request_type and the grant type
 */
var request_type = null;
var grant_type = null;
var state_id = null;

// The request type - if none available assume 'resource'
var global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("request_type", "urn:ibm:names:ITFIM:oauth:request");
if (global_temp_attr != null && global_temp_attr.length > 0) {
	request_type = global_temp_attr[0];
} else {
	request_type = "resource";
}

// The grant type
global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("grant_type", "urn:ibm:names:ITFIM:oauth:body:param");
if (global_temp_attr != null && global_temp_attr.length > 0) {
	grant_type = global_temp_attr[0];
}

// The state id handle
global_temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("state_id", "urn:ibm:names:ITFIM:oauth:state");
if (global_temp_attr != null && global_temp_attr.length > 0) {
  state_id = global_temp_attr[0];
}

IDMappingExtUtils.traceString("request_type: " + request_type);
IDMappingExtUtils.traceString("state_id: " + state_id);

/** UserInfo Customization
 *
 * This block provides example how to customize UserInfo output based on
 * OIDC 'scope' and/or 'claims' request parameters
 * In the STSUU context, the claims are listed in terms of essential and voluntary claims.
 * Also, when AttributeSources are configured in the definition, they will be resolved as well,
 * and available in the STSUU. This is one way of doing customization. 
 */
function produceClaim(claimName, expectedValues, isEssential) {

	var value = null;

	// If expectedValues exist, use it
	if (expectedValues != null && expectedValues.length > 0) {
		value = expectedValues[0];
	}

	// Attempt to get the value of the claim from AttributeSource resolution.
	if (value == null) {
		value = stsuu.getAttributeContainer().getAttributeValueByNameAndType(claimName, "urn:ibm:names:ITFIM:5.1:accessmanager");
	}

	// Check the extra attrs now
	if(value == null && state_id != null) {
		value = OAuthMappingExtUtils.getAssociation(state_id, "urn:ibm:names:ITFIM::oauth:saved:claim:" + claimName);
  }

	// Essential claim - set the value to 'n/a' or boolean 'false' if not exist
	if (value == null && isEssential) {
		value = claimName.endsWith("_verified") ? "false" : "n/a";
	}

	// Output it for userinfo if exist
	if (value != null) {
		var attr = new Attribute(claimName, "urn:ibm:names:ITFIM:oauth:response:attribute", value);
		stsuu.addContextAttribute(attr);
	}

}
 
if (request_type == "userinfo") {

	/*
	 * Process essential claims and voluntary claims separately
	 * as we may treat them differently if it has no value.
	 * STSUU attribute's name is the claim name
	 * STSUU attribute's value(s) are the 'expected' value of the claim
	 */

	var attrs = null;

	// Retrieve list of all the 'essential' claims
	attrs = stsuu.getContextAttributes().getAttributesByType("urn:ibm:names:ITFIM:oidc:claim:essential");
	if (attrs != null && attrs.length > 0) {
		for (i = 0; i < attrs.length; i++) {
			produceClaim(attrs[i].getName(), attrs[i].getValues(), true);
		}
	}

	// Retrieve list of all the 'voluntary' claims
	attrs = stsuu.getContextAttributes().getAttributesByType("urn:ibm:names:ITFIM:oidc:claim:voluntary");
	if (attrs != null && attrs.length > 0) {
		for (i = 0; i < attrs.length; i++) {
			produceClaim(attrs[i].getName(), attrs[i].getValues(), false);
		}
	}
	
}

/** Producing JWT UserInfo
 *
 * This block provides example how to produce JWT UserInfo.
 * In the STSUU context, the signing/encryption data (based on OP Definition) are available.
 * To create JWT, we call an STS Chain which has 2 steps (not available out of the box):
 * - Default STSUU validation module
 * - Default JWT issuer module
 * Passing the signature/encryption data and all the JWT claims.
 * The JWT token result then need to be set back in STSUU under special name and type.
 */
var produce_jwt_userinfo = false;

if (request_type == "userinfo" && produce_jwt_userinfo) {

	var sts_client = new STSClientHelper("https://localhost/TrustServer/SecurityTokenService",
		"easuser", "passw0rd", "rt_profile_keys", null, null); // Change this to match your credential

	var req_stsuu = new STSUniversalUser();

	var attrs = null;

	// Retrieve context attributes of type 'urn:ibm:oidc10:jwt:create'
	attrs = stsuu.getContextAttributes().getAttributesByType("urn:ibm:oidc10:jwt:create");
	if (attrs != null && attrs.length > 0) {
		for (i = 0; i < attrs.length; i++) {
			var attr = new Attribute(attrs[i].getName(), null, attrs[i].getValues());
			req_stsuu.addContextAttribute(attr);
		}
	}

	// Retrieve context attributes of type 'urn:ibm:JWT:header:claim'
	attrs = stsuu.getContextAttributes().getAttributesByType("urn:ibm:JWT:header:claim");
	if (attrs != null && attrs.length > 0) {
		for (i = 0; i < attrs.length; i++) {
			req_stsuu.addContextAttribute(attr[i]);
		}
	}

	// Add 'iss' and 'aud' claim
	var iss = stsuu.getAttributeContainer().getAttributeValueByName("iss");
	req_stsuu.addAttribute(new Attribute("iss", "urn:ibm:jwt:claim", iss));
	var aud = stsuu.getContextAttributes().getAttributeValueByName("client_id");
	req_stsuu.addAttribute(new Attribute("aud", "urn:ibm:jwt:claim", aud));

	// Retrieve claims from context attributes of type 'urn:ibm:names:ITFIM:oauth:response:attribute'
	attrs = stsuu.getContextAttributes().getAttributesByType("urn:ibm:names:ITFIM:oauth:response:attribute");
	if (attrs != null && attrs.length > 0) {
		for (i = 0; i < attrs.length; i++) {
			var attr = new Attribute(attrs[i].getName(), "urn:ibm:jwt:claim", attrs[i].getValues());
			req_stsuu.addAttribute(attr);
		}
	}

	var base_element = req_stsuu.toXML().getDocumentElement();
	var rsp = sts_client.doSTSExchange("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue",
		null, // No token type
		"urn:issuer", // Change this to match STS Chain issuer
		"urn:appliesTo", // Change this to match STS Chain appliesTo
		null, // No claims
		base_element);
	var jwtToken = IDMappingExtUtils.extractBinarySecurityToken(rsp);
	if (jwtToken != null) {
		stsuu.addContextAttribute(new Attribute("userinfo", "urn:ibm:names:ITFIM:oauth:rule:userinfo", jwtToken));
		stsuu.addContextAttribute(new Attribute("is_userinfo_jwt", "urn:ibm:names:ITFIM:oauth:rule:userinfo", "true"));
	}
}



var save_cred_attrs = true;

if (save_cred_attrs) {
	if(state_id != null) {
		var to_save_string = stsuu.getContextAttributes().getAttributeValueByNameAndType("attributesToSave", "urn:ibm:names:ITFIM::oauth:save");
		if(to_save_string != null && "" != to_save_string) {
			to_save = JSON.parse(to_save_string);

			for (var i in to_save) {
				OAuthMappingExtUtils.associate(state_id,"urn:ibm:names:ITFIM::oauth:saved:claim:" + to_save[i].key, to_save[i].value); 
			}
		}
	}
}

if (request_type == "authorization"){
  var code = stsuu.getContextAttributes().getAttributeValueByNameAndType("code","urn:ibm:names:ITFIM:oauth:response:attribute");
  var nonce = stsuu.getContextAttributes().getAttributeValueByNameAndType("nonce","urn:ibm:names:ITFIM:oauth:query:param");
  if(nonce == null) {
    nonce = stsuu.getContextAttributes().getAttributeValueByNameAndType("nonce","urn:ibm:names:ITFIM:oauth:body:param");
  }
  if(code != null && nonce != null) {
    IDMappingExtUtils.getIDMappingExtCache().put(code, nonce, 3600);
  }
}

if(request_type == "access_token") {
  var fingerprint = stsuu.getAttributeContainer().getAttributeValueByNameAndType("fingerprint", "urn:ibm:names:ITFIM:5.1:accessmanager");
  if(fingerprint == null) {
    IDMappingExtUtils.traceString("No fingerprint presented");
  } else {
    IDMappingExtUtils.traceString("Saving MTLS fingerprint: " + fingerprint);
    OAuthMappingExtUtils.associate(state_id,"mtls_fingerprint", fingerprint)
  }

}

if(request_type == "introspect") {
  IDMappingExtUtils.traceString("fetching MTLS fingerprint");

  var fingerprint = OAuthMappingExtUtils.getAssociation(state_id,"mtls_fingerprint");

  if(fingerprint != null) {
    IDMappingExtUtils.traceString("MTLS fingerprint: [" + fingerprint + "].");
		stsuu.addContextAttribute(new Attribute("mtls_fingerprint", "urn:ibm:names:ITFIM:oauth:response:attribute", fingerprint));
  }

  var acr = OAuthMappingExtUtils.getAssociation(state_id,"acr");

  if(acr != null) {
    IDMappingExtUtils.traceString("acr: [" + acr + "].");
		stsuu.addContextAttribute(new Attribute("acr", "urn:ibm:names:ITFIM:oauth:response:attribute", acr));
  }

}
  

if(request_type == "authorization") {
  var acr = stsuu.getAttributeContainer().getAttributeValueByNameAndType("authenticationTypes", "urn:ibm:names:ITFIM:5.1:accessmanager");
  if(acr == null) {
    IDMappingExtUtils.traceString("No acr presented");
  } else {
    IDMappingExtUtils.traceString("Saving acr: " + acr);
    OAuthMappingExtUtils.associate(state_id,"acr", acr)
  }

}


//if(request_type == "userinfo") {
//  var sub = stsuu.getContextAttributes().getAttributeValueByName("sub");
//  stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("emailAddress" ,"urn:ibm:names:ITFIM:oauth:response:attribute", sub+"@myisam.ibm.com"));
//  stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("email" ,"urn:ibm:names:ITFIM:oauth:response:attribute", sub+"@myisam.ibm.com"));
//}
