
// Step 1, get the JWt from the request:
function internalError() {
  macros.put("@JSON@", JSON.stringify({"error":"missing software statement"}))

}

function error(message) {
  macros.put("@JSON@", JSON.stringify({"error":message}))
}

var jwt = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "jwt");

if (jwt == null) {
  internalError()
} else {

  // Step 2 validate the JWT. 
  // First we need to build a binary security token from the jwt:
  var bst = IDMappingExtUtils.stringToXMLElement('<wss:BinarySecurityToken xmlns:wss="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" wss:EncodingType="http://ibm.com/2004/01/itfim/base64encode"  wss:ValueType="urn:com:ibm:JWT" >'+jwt+'</wss:BinarySecurityToken>')
  // validate the token
  var requestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate";
  var identifier = "urn:validate:ssa"

  // We don't have any claims to pass. 
  var tokenResult = LocalSTSClient.doRequest(requestType, identifier, identifier, baseToken, null);

  // Token is valid. Parse it as an stsuu
  var tokenStsuu = new STSUniversalUser();

  if(token.errorMessage != null) {
    trace(token.errorMessage);	
  } else {
    tokenStsuu.fromXML(token.token);	
    //tokenStsuu.
  }
}
