#!/usr/bin/env bash
#

# local user credentials
user="testinguser"
pass="testing123"
# name of the session cookie as configured inside AM (default is iPlanetDirectoryPro)
cookie_name="iPlanetDirectoryPro"
# base uri of AM
openam_endpoint=http://login7.booleans.local:8080/xs
# client settings
client_id="booleans_client"
# a redirect URI
redirect_uri=http://someservice.booleans.local:8080/dummycallback
# which scopes to request
scope="uid%20openid%20https://www.yes.com/scopes/sign:123456"
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

# get the .well-known/oauth-authorization-server
get_oauth2_metadata_wellknown_disco() {
    resp=$(curl \
        -s \
        -X GET ${curl_opts} \
        ${openam_endpoint}/oauth2/.well-known/oauth-authorization-server)
    echo "${resp}"
}

# get jwks details
get_jwks_details() {
    local _uri="${1}";
    local _kid="${2}";
    resp=$(curl \
        -s \
        -X GET ${curl_opts} \
        ${_uri})
    echo "${resp}"
}

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

# perform mtls request towards introspection endpoint
get_introspect() {
    local _access_token="${1}";
    local _token_resp=$(curl \
        -s \
        -X POST ${curl_opts} \
        -H "${mtls_header}: ${certificate_header}" \
        -d "client_id=${client_id}&token_type_hint=access_token&token=${_access_token}" \
        ${openam_endpoint}/oauth2/introspect)
    echo "${_token_resp}";
}

# perform mtls request towards introspection endpoint to get a signed JWT
get_introspect_signed() {
    local _access_token="${1}";
    local _token_resp=$(curl \
        -s \
        -X POST ${curl_opts} \
        -H "Accept: application/jwt" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "${mtls_header}: ${certificate_header}" \
        -d "client_id=${client_id}&token=${_access_token}" \
        ${openam_endpoint}/oauth2/introspect)
    echo "${_token_resp}";
        # -d "client_id=${client_id}&token_type_hint=access_token&token=${_access_token}" \
}

# perform mtls request towards introspection endpoint to get a signed JWT based on the id_token


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

decode_token() {
    local _tkn="${1}"
    echo "Header information: "
    get_jwt_header "${_tkn}"
    echo "Body information: "
    get_jwt_body "${_tkn}"
}

get_jwt_header() {
    local _tkn="${1}";
    perl -MMIME::Base64 -e '@tkn = split(/\./,shift); print decode_base64($tkn[0])."\n"' "${_tkn}" | jq .
}

get_jwt_body() {
    local _tkn="${1}";
    perl -MMIME::Base64 -e '@tkn = split(/\./,shift); print decode_base64($tkn[1])."\n"' "${_tkn}" | jq .
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
echo "Access token: ${at}"
echo "Refresh token: ${rt}"
echo

_tokeninfo_response=$(get_tokeninfo "${at}")
echo "Response from tokeninfo endpoint: "
jq . <<< ${_tokeninfo_response}
echo

_userinfo_response=$(get_userinfo "${at}")
echo "Response from userinfo endpoint: "
jq . <<< ${_userinfo_response}
echo

_introspect_response=$(get_introspect "${at}")
echo "Response from introspect endpoint: "
jq . <<< ${_introspect_response}
echo

_signed_introspect_response=$(get_introspect_signed "${at}")
echo "Response from signed introspect endpoint: "
echo "SignedJWT: ${_signed_introspect_response}"
decode_token "${_signed_introspect_response}"
echo

_header=$(get_jwt_header "${_signed_introspect_response}")
_kid=$(jq -rc .kid <<< "${_header}");
_alg=$(jq -rc .alg <<< "${_header}");
echo "Found kid: ${_kid} for algorithm ${_alg}"

_metadata=$(get_oauth2_metadata_wellknown_disco)
_jwks_uri=$(jq -rc .jwks_uri <<< "${_metadata}")
_jwks_details=$(get_jwks_details "${_jwks_uri}" "${_kid}")

echo "Found JWKSet for kid: ${_kid} and algorithm ${_alg}: "
jq '.keys[]|(select(.kid=="'${_kid}'" and .alg=="'${_alg}'"))' <<< "${_jwks_details}"
echo
