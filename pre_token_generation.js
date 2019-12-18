importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.oauth20);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.ibm.security.access.user);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
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

/**
 * ROPC scenario using a user registry for verification of the username 
 * and password.
 *
 * TODO: Enable ROPC registry checking
 */
if ( false && request_type == "access_token" && grant_type == "password") {

  // The username
  temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("username", "urn:ibm:names:ITFIM:oauth:body:param");
  if (temp_attr != null && temp_attr.length > 0) {
    username = temp_attr[0];
  }

  // The password
  temp_attr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("password", "urn:ibm:names:ITFIM:oauth:body:param");
  if (temp_attr != null && temp_attr.length > 0) {
    password = temp_attr[0];
  }

  // Throw an exception if no username or password was defined
  if (username == null || password == null) {
      // use throwSTSUserMessageException to return the exception message in request's response
    OAuthMappingExtUtils.throwSTSUserMessageException("No username/password.");
  }

  var isAuthenticated = false;

  if(username == "testuser" && password == "Passw0rd") {
    isAuthenticated = true;
  }

  if (!isAuthenticated) {
    OAuthMappingExtUtils.throwSTSUserMessageException("Invalid username/password. Authentication failed.");
  }
}



if (request_type == "access_token" && grant_type == "authorization_code") {
  var code = stsuu.getContextAttributes().getAttributeValueByNameAndType("code","urn:ibm:names:ITFIM:oauth:body:param");
  if(code != null) {
    var nonce = IDMappingExtUtils.getIDMappingExtCache().getAndRemove(code);
    if(nonce != null) {
      var attr = new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("nonce", "urn:ibm:jwt:claim", nonce);
      stsuu.addAttribute(attr);
    }
  }
}

// Populate ACR
if (request_type == "access_token") {
 populate_id_token = true;
 var code = stsuu.getContextAttributes().getAttributeValueByNameAndType("code","urn:ibm:names:ITFIM:oauth:body:param");
 if (code != null) {
  var token = OAuthMappingExtUtils.getToken(code);
  if (token != null) {
   state_id = token.getStateId();
   var acr = OAuthMappingExtUtils.getAssociation(state_id,"acr");
   if(acr != null) {
    var attr = new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("acr", "urn:ibm:jwt:claim", acr);
    stsuu.addAttribute(attr);
   }
  }
 }
} else if (request_type == "authorization") {
  var vals = stsuu.getAttributeContainer().getAttributeValuesByNameAndType("authenticationTypes", "urn:ibm:names:ITFIM:5.1:accessmanager");
  var attr = new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("acr", "urn:ibm:jwt:claim", vals);
  stsuu.addAttribute(attr);
}

