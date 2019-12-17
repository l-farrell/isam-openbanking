//Open banking access policy

importClass(Packages.com.ibm.security.access.policy.decision.Decision);
importClass(Packages.com.ibm.security.access.policy.decision.HtmlPageDenyDecisionHandler);
importClass(Packages.com.ibm.security.access.policy.decision.RedirectChallengeDecisionHandler);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);  
importClass(Packages.java.util.UUID);

trace('ENTRY-access policy');

// the authsvc policy we want to use
var policyId = "urn:ibm:security:authentication:asf:fido2"
var authenticationTypes = "authenticationTypes"

// To enable trace, set the trace string:
//     com.tivoli.am.fim.trustserver.sts.utilities.*=ALL
function trace(msg) {
  IDMappingExtUtils.traceString(msg);
}

// produces a redirect handler to the authsvc
function getRedirectToAuthSvc() {
  var handler = new RedirectChallengeDecisionHandler();
  handler.setRedirectUri("/sps/authsvc?Target=/sps/auth&PolicyId=" + policyId);
  trace("Redirecting to invoke policy ["+policyId+"].");
  return handler;
}

// Return a decision to pass into the context setDecision() call

function getDecision() {
  var request = context.getRequest();

  var user = context.getUser();

  // Successful authentication service calls populate this credential attribute
  var attribute = user.getAttribute(authenticationTypes);
  if(attribute != null) {
    var value = attribute.getValue();
    if(value != null) {
      // If theres a ',' we need to process further
      if(value.contains(",")) {
        var values = value.split(",");
        // This will occur when multiple authentication polices have been
        // performed
        for(var i = 0 ; i < values.length; i++) {
          // Check for our exact id
          if(values[i].trim().equals(policyId)) {
            // Match! Allow.
            trace(policyId + " found! Allowing");
            return Decision.allow();
          }
        }
      } else if(value.equals(policyId)) {
        // It contains the policy Id, permit!
        trace(policyId + " found! Allowing");
        return Decision.allow();
      } else {
        // Should not occur, redirect if it does.
        return Decision.challenge(getRedirectToAuthSvc());
      }
    } else {
      trace(authenticationTypes + " value not found.");
      return Decision.challenge(getRedirectToAuthSvc());
    }
  } else {
    trace(authenticationTypes + " not found.");
    return Decision.challenge(getRedirectToAuthSvc());
  }

}

// Set the decision
context.setDecision(getDecision());

