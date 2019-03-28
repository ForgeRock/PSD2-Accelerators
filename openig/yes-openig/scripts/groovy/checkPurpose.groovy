logger.debug("query= {}", request.uri.query)
def map = request.uri.query.split('&').inject([:]) {map, kv-> def (key, value) = kv.split('=').toList(); map[key] = value != null ? URLDecoder.decode(value) : null; map }

class amService {
	final String openamUrl
	final String user 
	final String password 
	static String ssoToken
	def http
	def logger
	amService(String openamUrl, String user, String password, def http, def logger){
		this.openamUrl = openamUrl
		this.http = http
		this.logger = logger
		this.user = user
		this.password = password
	}
	String createSSOToken() {
        /* Request to get an SSOToken*/
		logger.info("Create token")
		def req = new Request()
		req.setUri("${openamUrl}/json/authenticate")
		req.setMethod("POST")
		req.getHeaders().add('Content-Type','application/json')
		req.getHeaders().add('Accept-Api-Version','resource=2.1')
		req.getHeaders().add('X-OpenAM-Username',user)
		req.getHeaders().add('X-OpenAM-Password',password)
		req.setEntity( "{}" )
		logger.info("Sending http request...{}",req.uri)

		def resp = http.send(req).get()

		if (resp.getStatus().getCode()==200){
			ssoToken = resp.entity.getJson().tokenId
			logger.debug("ssotoken: {}",ssoToken)
		}
		else{
			logger.error("error response form create ssotoken: {}",resp.getStatus())
		}
		return ssoToken
    }
	
	private boolean isTokenValid(){
		boolean isValid=false
		if (ssoToken!=null){
			logger.info("Validate token {}",ssoToken)
			def req = new Request()
			req.setUri("${openamUrl}/json/sessions?tokenId="+ssoToken+"&_action=validate")
			req.setMethod("POST")
			req.getHeaders().add('Content-Type','application/json')
			req.getHeaders().add('Accept','application/json')
			req.getHeaders().add('Accept-Api-Version','resource=1.2')
			req.setEntity( "{}" )
			logger.debug("Sending http request...{}",req.uri)

			def resp = http.send(req).get()

			if (resp.getStatus().getCode()==200){
				isValid = resp.entity.getJson().valid
				logger.info("isValid={}",isValid)
			}else{
				logger.error("error response form validate ssotoken {}: {}",ssoToken,resp.getStatus())
			}
		}
		return isValid
	}
	
    String getSSOToken() {
		if (isTokenValid()){
			return ssoToken
		}
		else {
			createSSOToken()
		}
    }
}

def scope = map["scope"]
def purpose = map[param]
def redirect_uri = map["redirect_uri"]
def state = map["state"]
def nonce = map["nonce "]
			
if (!scope.contains(param)){
	if (purpose != null){
		def len = purpose.length()
		logger.debug("purpose value = {}", purpose)
		if (len<min || len>max ) {
			logger.error("invalid purpose length = {} response invalid_request", len)

			if (redirect_uri != null) {
				def err = redirect_uri + "?error=" + error + "&error_description=" + description			
				if (state!=null) { err += "&state=" + state }
				if (nonce!=null) { err += "&nonce=" + nonce }
				
				logger.debug("response to {}", err)
				
				Response response = new Response(Status.FOUND)
				response.headers.add("Location", err)
				return response
			}
		}
		// Move purpose into scope then pass on OpenAM

		map["scope"] += " " + param + "=" + URLEncoder.encode(purpose,"UTF-8").replaceAll("\\+", "%20")
		logger.info("query= {}", map.collect { k,v -> "$k=$v" }.join('&'))
		map.remove(param)

		logger.info("new query= {}", map.collect { k,v -> "$k=$v" }.join('&'))
		request.uri.setQuery(map.collect { k,v -> "$k=$v" }.join('&'))
	} else {
		def am = new amService(openamUrl, user, password, http, logger)

		def token = am.getSSOToken()
		logger.debug("token... {}",token)

		def clientId = map["client_id"]
		def originalUri = contexts.router.originalUri.host

		// Request to get a clientId
		def req = new Request()
		req.setUri("${openamUrl}/json/realm-config/agents/OAuth2Client/${clientId}")
		req.setMethod("GET")
		req.getHeaders().add('Cookie','iPlanetDirectoryPro='+token)
		req.getHeaders().add('Accept','application/json')
		req.getHeaders().add('Accept-Api-Version','protocol=1.0,resource=1.0')
		req.getHeaders().add('host',originalUri)
		req.setEntity( "{}" )

		logger.info("Query OAuth2Client={}",clientId)
		logger.info("Sending http request... {},header... {} {}",req.uri,req.headers.get("Cookie"),req.headers.get("host"))

		def resp = http.send(req).get()

		if (resp.getStatus().getCode()==200){
			def clientDescription = resp.entity.getJson().advancedOAuth2ClientConfig.descriptions.value[0]
			if (clientDescription != null) {
					def defaultConsentPurpose = clientDescription.split("defaultConsentPurpose\\|")[1]
					if (defaultConsentPurpose!=null){
					logger.info("defaultConsentPurpose: {} ",defaultConsentPurpose)	
					map["scope"] += " " + param + "=" + URLEncoder.encode(defaultConsentPurpose,"UTF-8").replaceAll("\\+", "%20")
				}
				
				//Encode cliams parameter 
				if (map["claims"] != null) { 
					def claims = URLEncoder.encode(map["claims"],"UTF-8").replaceAll("\\+", "%20") 
					map["claims"] = claims
					logger.debug("claims = {}",claims)
				} 
				map.remove(param)

				logger.info("query= {}", map.collect { k,v -> "$k=$v" }.join('&'))

				request.uri.setQuery(map.collect { k,v -> "$k=$v" }.join('&'))
			}
			else {
				logger.error("Can't found defaultConsentPurpose of {}",clientId)
				def err = redirect_uri + "?error=" + error + "&error_description=" + description			
				if (state!=null) { err += "&state=" + state }
				if (nonce!=null) { err += "&nonce=" + nonce }
				
				logger.debug("response to {}", err)
				
				Response response = new Response(Status.FOUND)
				response.headers.add("Location", err)
				return response
			}
		}
		else{
			logger.error("error response form get OAuth2Client: {}",resp.getStatus())
		}
	}
}

return next.handle(context, request)
