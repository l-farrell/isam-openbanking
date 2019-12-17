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
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);
importClass(Packages.java.lang.System);
function javaToJson(java) {
  if (java.length == 1) {
    return ""+java[0];
  }

  var res = []
  for (var i = 0; i < java.length; i++) {
    res.push(""+java[i]);
  }
  return res
}


function post(json) {
	var hr = new HttpResponse();
	var headers = new Headers();
	var params= new Parameters();
	headers.addHeader("iv-user", "testAdmin");

	// httpPost(String url, Map parameters)
	hr = HttpClient.httpPost("https://localhost/sps/oauth/oauth20/register/OpenBanking", headers, JSON.stringify(json), null, null, null, null, 60);

  
	if (hr != null) {
    var body = hr.getBody();
    System.err.println("code: " + hr.getCode());
		System.err.println("body: " + body);
		macros.put("@JSON@", body);
  } else {
    System.err.println("Missing HR!");
    internalError()
  }
}

// Step 1, get the JWt from the request:


function internalError() {
  macros.put("@JSON@", JSON.stringify({ "error": "missing software statement" }))

}

function error(message) {
  macros.put("@JSON@", JSON.stringify({ "error": message }))
}

var jwt = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "jwt");

if (jwt == null) {
  internalError()
} else {

  // Step 2 validate the JWT. 

  // First we need to build a binary security token from the jwt:
  var bst = IDMappingExtUtils.stringToXMLElement('<wss:BinarySecurityToken xmlns:wss="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" wss:EncodingType="http://ibm.com/2004/01/itfim/base64encode"  wss:ValueType="urn:com:ibm:JWT" >' + jwt + '</wss:BinarySecurityToken>')
  // validate the token
  var requestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate";
  var identifier = "urn:validate:ssa";
  // We don't have any claims to pass. 
  var token = LocalSTSClient.doRequest(requestType, identifier, identifier, bst, null);


  // Token is valid. Parse it as an stsuu
  var tokenStsuu = new STSUniversalUser();

  if (token.errorMessage != null) {
    error(token.errorMessage);
  } else {
    tokenStsuu.fromXML(token.token);
    var attrs = tokenStsuu.getAttributeContainer().getAttributes()

    registerJson = {}

    for (var i = 0; i < attrs.length; i++) {
      registerJson[attrs[i].getName()] = javaToJson(attrs[i].getValues());
    }

    post(registerJson)
  }
}
