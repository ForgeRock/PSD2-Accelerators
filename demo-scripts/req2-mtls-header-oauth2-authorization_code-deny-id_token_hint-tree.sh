#!/usr/bin/env bash
#

# local user credentials
user="testinguser"
pass="testing123"
# name of the session cookie as configured inside AM (default is iPlanetDirectoryPro)
cookie_name="iPlanetDirectoryPro"
# base uri of AM
openam_endpoint=http://login2.booleans.local:8080/xs
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
# mtls header name
mtls_header="X-Yes-mtlsCertAuth"
# client certificate
client_cert=${ssl_dir}oauth2_client.crt
# client certificate as one line
certificate_header=$(egrep -v ' CERTIFICATE-----' ${client_cert} | awk 'NF {sub(/\r/, ""); printf "%s",$0;}')

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

# get the authorization code from the redirect
get_authorization_code() {
    local sessionid="${1}";
    ac_response=$(curl\
        -s \
        -X POST ${curl_opts} \
        -H "Cookie: ${cookie_name}=${sessionid}" \
        -d "response_type=code&scope=${scope}&client_id=${client_id}&nonce=123&csrf=${sessionid}&redirect_uri=${redirect_uri}&decision=allow" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -v \
        ${openam_endpoint}/oauth2/authorize 2>&1 | grep '< Location' | sed -e 's/< Location: //')
    ac_code=$(echo ${ac_response} | awk -F'?' '{ print $2 }'| awk -F'&' '{ print $1 }' | awk -F'=' '{ print $2 }')
    echo "${ac_code}"
}

# exchange the access_code for a token
exchange_ac_for_token() {
    local _access_code="${1}";
    local _token_resp=$(curl \
        -s \
        -X POST ${curl_opts} \
        -H "${mtls_header}: ${certificate_header}" \
        -d "client_id=${client_id}&code=${_access_code}&redirect_uri=${redirect_uri}&grant_type=authorization_code" \
        ${openam_endpoint}/oauth2/access_token)
    echo "${_token_resp}"
}

# call the authnode service directly in AM
get_idtokennode_response_callback() {
    local idtoken="${1}";
    ac_response=$(curl\
        -s \
        -X POST ${curl_opts} \
        -H "Accept-API-Version: protocol=1.0,resource=1.0" \
        -H "Content-Type: application/json" \
        "${openam_endpoint}/json/authenticate?authIndexType=service&authIndexValue=IDTokenHint%20Tree" 2>&1)
    echo "${ac_response}"
}

# Executing the complete OAuth2 flow using the Authorization code Grant type.
sessionid=$(get_session_id)
echo "Received session ID: ${sessionid}"
echo

_code=$(get_authorization_code "${sessionid}")
echo "Received authorization code: ${_code}"
echo

_access_token_response=$(exchange_ac_for_token "${_code}")
echo "The access token reponse: "
jq . <<< ${_access_token_response}
at=$(jq -r '.access_token' <<< "${_access_token_response}")
rt=$(jq -r '.refresh_token' <<< "${_access_token_response}")
id=$(jq -r '.id_token' <<< "${_access_token_response}")
echo "Access token: ${at}"
echo "Refresh token: ${rt}"
echo "IdToken: ${id}"
echo

_idtokennode_response=$(get_idtokennode_response_callback "${id}")
echo "Direct call towards the authentication node: "
echo "${_idtokennode_response}"

