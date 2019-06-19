# OpenAM - Amster AM OpenBanking Realm Configuration

OpenAM is an "all-in-one" access management solution that provides the following features in a single unified project:

+ Authentication
    - Adaptive 
    - Strong  
+ Single sign-on (SSO)
+ Authorization
+ Entitlements
+ Federation 
+ Web Services Security

This asset contains all the AM configuration (Amster export for the specific obenbanking realm) that need to be in place in order to have the initial ootb setup for the openbanking features. 

## Run the Amster import

Note: the AM version used for the configuration included in these assets is 6.5.1

In order to import the AM configuration using the Amster utilitar, follow the follosing steps (also described more in detail in the oficial Forgerock documentation: https://backstage.forgerock.com/docs/amster/6.5/user-guide/#sec-usage-import):

Caution: A successful import overwrites any configuration that already exists in the target AM instance. 

### Before importing configuration

- Start the Amster command-line interface
- Connect to the AM instance where you will import the configuration data after starting the Amster command-line interface
	``` 
	am> connect --interactive https://openam.example.com:8443/openam
	``` 
- Specify username and password to authenticate to AM:
	``` 
	Sign in to OpenAM
	User Name: amadmin
	Password: *********
	amster openam.example.com:8443>
	``` 
- You must ensure that the configuration data you are trying to import is compatible with the version of AM you have deployed.
	For example, do not try to import configuration data exported from an AM 6.5.1 instance into an AM 5 instance. 

### Import configuration

- Usage:
	```
	am> import-config --path Path [options]
	```
	--path Path
		The path containing configuration files to import.
		Specify a directory to import from all correctly-formatted JSON files within that directory and recurse through each sub-directory, or specify an individual JSON file.
	Options:
		--failOnError [true|false]
			If specified, the import process halts if an error occurs.
			Default: false
		--clean [true|false]
			If specified, all configuration data except the Amster Authentication Module is removed from the target AM instance before the import is performed.
			Specify this option when importing configuration into a new AM instance.
			Default: false

### Example
	```
	am> import-config --path /tmp/myExportedConfigFiles --clean true --failOnError true
	```

## License

>  Copyright 2019 ForgeRock AS
>
> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
>
>    http://www.apache.org/licenses/LICENSE-2.0
>
>  Unless required by applicable law or agreed to in writing, software
>  distributed under the License is distributed on an "AS IS" BASIS,
>  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
>  See the License for the specific language governing permissions and
>  limitations under the License.