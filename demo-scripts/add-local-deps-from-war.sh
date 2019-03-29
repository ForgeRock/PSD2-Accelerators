#!/bin/bash
#
# this adds all jars from a  war file into my local maven repo

warfile=${1}

if [[ -z "${warfile}" ]]; then
    echo "Usage: $0 <warfile>"
    exit 1;
fi;

tmp_dir=$(mktemp -d /tmp/XXXXXXXX)
unzip -d ${tmp_dir} ${warfile}

cd ${tmp_dir}/WEB-INF/lib/

for file in $(ls *.jar); do 
    echo "Attempting to add $file as a local mvn dep"; 
    _pomprops=$(unzip -l -c "${file}" | grep pom.properties | awk '{ print $2 }')
    if [[ ! -z "${_pomprops}" ]]; then
        echo "Found pom.properties here: ${_pomprops}"
        _pomcontents=$(unzip -q -c "${file}" ${_pomprops})
        _version=$(echo "${_pomcontents}" | grep ^version= | sed -e 's/^version=//')
        _artifact_id=$(echo "${_pomcontents}" | grep ^artifactId= | sed -e 's/^artifactId=//')
        _group_id=$(echo "${_pomcontents}" | grep ^groupId= | sed -e 's/^groupId=//')

        echo "Version: ${_version} artifactId: ${_artifact_id} groupId: ${_group_id}" 
        if [[ ! -z "${_version}" && ! -z "${_artifact_id}" && ! -z "${_group_id}" ]]; then
            mvn install:install-file \
                -Dfile=${file} \
                -DgroupId=${_group_id} \
                -DartifactId=${_artifact_id} \
                -Dversion=${_version} \
                -Dpackaging=jar \
                -DgeneratePom=true
        else
            echo "Not all info is available: Version: ${_version} artifactId: ${_artifact_id} groupId: ${_group_id}"
        fi;
    else
        echo "No pom.properties found in jar ${file}"
    fi
done;

rm -rf ${tmp_dir}
