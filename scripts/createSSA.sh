REDIRECT_URI=$1
read -r -d '' XML_DOC <<'ENDOFDOC'
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:ns1="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"
  xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <SOAP-ENV:Body>
    <!--  <ns1:RequestSecurityTokenCollection>-->
      <ns1:RequestSecurityToken>
        <wsp:AppliesTo>
          <wsa:EndpointReference>
            <wsa:Address>urn:jwt:issue</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wst:Issuer>
          <wsa:Address>urn:jwt:issue</wsa:Address>
        </wst:Issuer>
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Validate</wst:RequestType>
        <wst:Base>
          <stsuuser:STSUniversalUser xmlns:stsuuser="urn:ibm:names:ITFIM:1.0:stsuuser">
            <stsuuser:Principal/>
            <stsuuser:AttributeList>
            </stsuuser:AttributeList>
            <stsuuser:ContextAttributes>
              <stsuuser:Attribute name="claim_json" type="">
                <stsuuser:Value>{"redirect_uris":["@URI@"]}</stsuuser:Value>
              </stsuuser:Attribute>
              <stsuuser:Attribute name="signing.db" type="">
                <stsuuser:Value>rt_profile_keys</stsuuser:Value>
              </stsuuser:Attribute>
              <stsuuser:Attribute name="signing.cert" type="">
                <stsuuser:Value>runtime</stsuuser:Value>
              </stsuuser:Attribute>
              <stsuuser:Attribute name="signing.alg" type="">
                <stsuuser:Value>RS256</stsuuser:Value>
              </stsuuser:Attribute>
            </stsuuser:ContextAttributes>
            <stsuuser:AdditionalAttributeStatement id=""/>
          </stsuuser:STSUniversalUser> 

        </wst:Base>
      </ns1:RequestSecurityToken>
      <!--</ns1:RequestSecurityTokenCollection>-->
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>

ENDOFDOC

URI_XML_DOC=$(echo $XML_DOC | sed  "s/@URI@/$REDIRECT_URI/g")

OUTPUT=$(curl -s -S -k --user easuser:passw0rd -H "x-forwarded-by" -H "Content-Type: text/xml" -d "$URI_XML_DOC"  https://isam.local:20443/TrustServerWS/SecurityTokenServiceWST13)

#echo $OUTPUT | xmllint --format -
JWT=$(echo $OUTPUT | xmllint --xpath "//*[local-name()='BinarySecurityToken']/text()" -)

echo Jwt: 
echo $JWT


