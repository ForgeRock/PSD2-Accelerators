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
scope="uid%20openid"
# ssl location
ssl_dir="ssl/"
# curl settings
curl_opts="-k"

# gets the oauth authorization metadata
get_oauth_metadata() {
    resp=$(curl \
        -s \
        -X GET ${curl_opts} \
        ${openam_endpoint}/oauth2/.well-known/oauth-authorization-server)
    echo "${resp}"
}

_response=$(get_oauth_metadata)
echo "Get OAuth 2.0 Authorization Server Metadata: "
jq . <<< ${_response}
echo
