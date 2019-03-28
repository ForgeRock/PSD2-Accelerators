#!/usr/bin/env bash
#

# local user credentials
user="testinguser"
pass="testing123"
# name of the session cookie as configured inside AM (default is iPlanetDirectoryPro)
cookie_name="iPlanetDirectoryPro"
# base uri of AM
openam_endpoint=https://login3.booleans.local:8443/xs
# client settings
client_id="booleans_client"
# a redirect URI
redirect_uri=http://someservice.booleans.local:8080/dummycallback
# which scopes to request
scope="uid%20openid"
# ssl location
ssl_dir="ssl/"
# curl settings
curl_opts="-k"

# normal authentication
get_session_id() {
    session=$(curl \
        -s \
        -X POST ${curl_opts} \
        -H "X-OpenAM-Username: ${user}" \
        -H "X-OpenAM-Password: ${pass}" \
        -H "Accept-API-Version: protocol=1.0,resource=1.0" \
        ${openam_endpoint}/json/authenticate | awk -F '"' '{ print $4 }')
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
        "${openam_endpoint}/oauth2/authorize?response_type=code&scope=${scope}&client_id=${client_id}&redirect_uri=${redirect_uri}&prompt=${prompt}" 2>&1 | grep '< Location' | sed -e 's/< Location: //')
    echo "${ac_response}"
}

# Executing the complete OAuth2 flow using the Authorization code Grant type.
sessionid=$(get_session_id)
echo "Received session ID: ${sessionid}"
echo

_code2=$(get_authorization_code_prompt_consent "${sessionid}")
echo "Received response redirect with prompt=consent: ${_code2}"
echo 
