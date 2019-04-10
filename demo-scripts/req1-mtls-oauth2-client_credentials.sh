#!/usr/bin/env bash
#
#

# name of the session cookie as configured inside AM (default is iPlanetDirectoryPro)
cookie_name="iPlanetDirectoryPro"
# base uri of AM
openam_endpoint=https://login11.booleans.local:8443/xs
# client settings
client_id="booleans_client"
# a redirect URI
redirect_uri=http://someservice.booleans.local:8080/dummycallback
# which scopes to request
scope="uid%20openid"
# ssl location
ssl_dir="ssl/"

# curl settings
curl_opts="-k --tlsv1.2"

# perform the client_credentials grant
get_access_token_client_credentials() {
    local _token_resp=$(curl \
        -s \
        -X POST ${curl_opts} \
        --cert ${ssl_dir}oauth2_client.crt \
        --key ${ssl_dir}oauth2_client.key \
        --cacert ${ssl_dir}login.booleans.local.crt \
        -d "client_id=${client_id}&scope=${scope}&grant_type=client_credentials&response_type=token" \
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

# Executing the complete OAuth2 flow using the Client Credentials Grant type.
sessioninfo=$(get_access_token_client_credentials)
echo "Received info from client_credentials: "
jq . <<< "${sessioninfo}"
echo
at=$(jq -r '.access_token' <<< "${sessioninfo}")
introspectresp=$(get_introspect "${at}")
echo "Received introspection response: "
jq . <<< "${introspectresp}"

_tokeninfo_response=$(get_tokeninfo "${at}")
echo "Response from tokeninfo endpoint: "
jq . <<< ${_tokeninfo_response}
echo

_userinfo_response=$(get_userinfo "${at}")
echo "Response from userinfo endpoint: "
jq . <<< ${_userinfo_response}
echo
