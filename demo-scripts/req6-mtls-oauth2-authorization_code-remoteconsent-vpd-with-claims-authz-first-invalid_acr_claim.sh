#!/usr/bin/env bash
#

# local user credentials
user="testinguser"
pass="testing123"
# name of the session cookie as configured inside AM (default is iPlanetDirectoryPro)
cookie_name="iPlanetDirectoryPro"
# base uri of AM
openam_endpoint=https://login66.booleans.local:8443/xs
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
# claims
claims='{ "id_token": { "https://www.yes.com/claims/verified_person_data": null, "acr": { "essential": true, "values": [ "https://www.no.com/acrs/online_banking_sca" ] } }, "userinfo": { "https://www.yes.com/claims/verified_person_data": null } }'

# get a session ID with a goto param
get_session_id_with_goto() {
    local _goto="${1}";
    session=$(curl \
        -s \
        -X POST ${curl_opts} \
        -H "X-OpenAM-Username: ${user}" \
        -H "X-OpenAM-Password: ${pass}" \
        -H "Accept-API-Version: protocol=1.0,resource=1.0" \
        -G \
        --data-urlencode "goto=${_goto}" \
        ${openam_endpoint}/json/authenticate | awk -F '"' '{ print $4 }')
    echo "${session}"
}

# get the authorization code with prompt value
get_authorization_code_prompt_consent() {
    local sessionid="${1}";
    local prompt="consent";
    local _urlenc_claims=$(urlencode "${claims}")
    ac_response=$(curl\
        -s \
        -X GET ${curl_opts} \
        -H "Cookie: ${cookie_name}=${sessionid}" \
        -v \
        "${openam_endpoint}/oauth2/authorize?response_type=code&scope=${scope}&client_id=${client_id}&redirect_uri=${redirect_uri}&prompt=${prompt}&claims=${_urlenc_claims}" 2>&1 | grep '< Location' | sed -e 's/< Location: //')
    echo "${ac_response}"
}

urlencode() {
    local LANG=C
    for ((i=0;i<${#1};i++)); do
        if [[ ${1:$i:1} =~ ^[a-zA-Z0-9\.\~\_\-]$ ]]; then
            printf "${1:$i:1}"
        else
            printf '%%%02X' "'${1:$i:1}"
        fi
    done
}

# Executing the complete OAuth2 flow using the Authorization code Grant type.
_goto_url=$(get_authorization_code_prompt_consent_url)
echo "Received goto URL: ${_goto_url}"
echo
sessionid=$(get_session_id_with_goto "${_goto_url}")
echo "Received session ID: ${sessionid}"
echo

_consent_redirect=$(get_authorization_code_prompt_consent "${sessionid}")
echo "Received consent redirect: ${_consent_redirect}"
echo
