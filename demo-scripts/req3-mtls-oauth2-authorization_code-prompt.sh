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
get_authorization_code_prompt_none() {
    local sessionid="${1}";
    local prompt="none";
    ac_response=$(curl\
        -s \
        -X GET ${curl_opts} \
        -v \
        "${openam_endpoint}/oauth2/authorize?response_type=code&scope=${scope}&client_id=${client_id}&redirect_uri=${redirect_uri}&prompt=${prompt}" 2>&1 | grep '< Location' | sed -e 's/< Location: //')
    echo "${ac_response}"
}

# get the authorization code with prompt value
get_authorization_code_prompt_none_session() {
    local sessionid="${1}";
    local prompt="none";
    ac_response=$(curl\
        -s \
        -X GET ${curl_opts} \
        -H "Cookie: ${cookie_name}=${sessionid}" \
        -v \
        "${openam_endpoint}/oauth2/authorize?response_type=code&scope=${scope}&client_id=${client_id}&redirect_uri=${redirect_uri}&prompt=${prompt}" 2>&1 | grep '< Location' | sed -e 's/< Location: //')
    echo "${ac_response}"
}

# get the authorization code with prompt value
get_authorization_code_prompt_login() {
    local sessionid="${1}";
    local prompt="login";
    ac_response=$(curl\
        -s \
        -X GET ${curl_opts} \
        -H "Cookie: ${cookie_name}=${sessionid}" \
        -v \
        "${openam_endpoint}/oauth2/authorize?response_type=code&scope=${scope}&client_id=${client_id}&redirect_uri=${redirect_uri}&prompt=${prompt}" 2>&1 | grep '< Location' | sed -e 's/< Location: //')
    echo "${ac_response}"
}

# exchange the access_code for a token
exchange_ac_for_token() {
    local _access_code="${1}";
    local _token_resp=$(curl \
        -s \
        -X POST ${curl_opts} \
        --cert ${ssl_dir}oauth2_client.crt \
        --key ${ssl_dir}oauth2_client.key \
        --cacert ${ssl_dir}login.booleans.local.crt \
        -d "client_id=${client_id}&code=${_access_code}&redirect_uri=${redirect_uri}&grant_type=authorization_code" \
        ${openam_endpoint}/oauth2/access_token)
    echo "${_token_resp}"
}

# perform mtls request towards introspection endpoint
get_introspect() {
    local _access_token="${1}";
    local _token_resp=$(curl \
        -s \
        -X POST ${curl_opts} \
        --cert ${ssl_dir}oauth2_client.crt \
        --key ${ssl_dir}oauth2_client.key \
        --cacert ${ssl_dir}login.booleans.local.crt \
        -d "client_id=${client_id}&token_type_hint=access_token&token=${_access_token}" \
        ${openam_endpoint}/oauth2/introspect)
    echo "${_token_resp}";
}

# get token information from a central endpoint
get_tokeninfo() {
    local _access_token="${1}";
    tokeninfo_response=$(curl\
        -X GET ${curl_opts} \
        -s \
        -H "Authorization: Bearer ${_access_token}" \
        ${openam_endpoint}/oauth2/tokeninfo 2>&1)
    echo "${tokeninfo_response}"
}

# get user information from a central endpoint
get_userinfo() {
    local _access_token="${1}";
    userinfo_response=$(curl\
        -X GET ${curl_opts} \
        -s \
        -H "Authorization: Bearer ${_access_token}" \
        ${openam_endpoint}/oauth2/userinfo 2>&1)
    echo "${userinfo_response}"
}

# perform a refresh of the access_token using the refresh_token
refresh_access_token() {
    local _refresh_token="${1}";
    local _token_resp=$(curl \
        -s \
        -X POST ${curl_opts} \
        --cert ${ssl_dir}oauth2_client.crt \
        --key ${ssl_dir}oauth2_client.key \
        --cacert ${ssl_dir}login.booleans.local.crt \
        -d "refresh_token=${_refresh_token}&grant_type=refresh_token&client_id=${client_id}" \
        ${openam_endpoint}/oauth2/access_token)
    echo "${_token_resp}"
}

# Executing the complete OAuth2 flow using the Authorization code Grant type.
sessionid=$(get_session_id)
echo "Received session ID: ${sessionid}"
echo

_code=$(get_authorization_code_prompt_none "${sessionid}")
echo "Received response redirect with prompt=none: ${_code}"
echo

_code=$(get_authorization_code_prompt_none_session "${sessionid}")
echo "Received response with prompt=none and valid session: ${_code}"
echo

_code1=$(get_authorization_code_prompt_login "${sessionid}")
echo "Received response redirect with prompt=login: ${_code1}"
echo
