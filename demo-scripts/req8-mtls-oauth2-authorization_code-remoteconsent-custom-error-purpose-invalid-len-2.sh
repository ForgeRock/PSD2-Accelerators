#!/usr/bin/env bash
#

# local user credentials
user="testinguser"
pass="testing123"
# name of the session cookie as configured inside AM (default is iPlanetDirectoryPro)
cookie_name="iPlanetDirectoryPro"
# base uri of IG
openig_endpoint=http://login6.booleans.local:8080/xs
# client settings
client_id="booleans_client"
# a redirect URI
redirect_uri=http://someservice.booleans.local:8080/dummycallback
# which scopes to request
scope="uid%20openid%20profile"
# ssl location
ssl_dir="ssl/"
# curl settings
curl_opts="-k"
# purpose parameter
purpose="12"

# normal authentication
get_session_id() {
    session=$(curl \
        -s \
        -X POST ${curl_opts} \
        -H "X-OpenAM-Username: ${user}" \
        -H "X-OpenAM-Password: ${pass}" \
        -H "Accept-API-Version: protocol=1.0,resource=1.0" \
        ${openig_endpoint}/json/authenticate | awk -F '"' '{ print $4 }')
    echo "${session}"
}

# get the authorization code with prompt value
get_authorization_code_prompt_consent() {
    local sessionid="${1}";
    local prompt="consent";
    ac_response=$(curl\
        -s \
        -X GET ${curl_opts} \
        -H "Cookie: ${cookie_name}=${sessionid}" \
        -v \
        "${openig_endpoint}/oauth2/authorize?response_type=code&scope=${scope}&client_id=${client_id}&client_secret=${client_secret}&redirect_uri=${redirect_uri}&prompt=${prompt}&https://www.yes.com/parameters/purpose=${purpose}" 2>&1 | grep '< Location' | sed -e 's/< Location: //')
    echo "${ac_response}"
}

# Executing the complete OAuth2 flow using the Authorization code Grant type.
sessionid=$(get_session_id)
echo "Received session ID: ${sessionid}"
echo

_consent_redirect=$(get_authorization_code_prompt_consent "${sessionid}")
echo "Received consent redirect: ${_consent_redirect}"
echo
