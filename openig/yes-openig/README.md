# Overview

This project contains a number of routes and script for OpenIG configurations to deliver some functionality of YES integration as below.
* Proxies all the requests through OAuth2/OIDC flow where OpenAM is the provider. 
* Provide custom authorization response for purpose query parameter and verified_person_data cliams

# Installation

For more information on install OpenIG refer to the [documentation](http://openig.forgerock.org/doc/webhelp/gateway-guide/index.html) 

# Configuration 

The project use env.json in config folder to read environment parameter. Rename 
the file env.template to env.json and edit property to suit your environment.

For example as below: 
```
{
	"openamUrl" : "http://openam.example.com:8080",
	"openamPath" : "openam",
	"user" : "<admin user>",
	"password" : "<admin password>"
}
```

# Note about admin user 

The user requires admin privileges. For more information on how to create user with admin privileges refer to an article [here](https://backstage.forgerock.com/knowledge/kb/article/a69972604)

# Running the project

By default, the IG configuration files are in the directory $HOME/.openig (on Windows, %appdata%\OpenIG) Change the default location in the following ways:

Set the IG_INSTANCE_DIR environment variable to the full path to the base location for IG files:

```
# On Linux, macOS, and UNIX using Bash
$ export IG_INSTANCE_DIR=/path/to/openig

# On Windows
C:>set IG_INSTANCE_DIR=c:\path\to\openig
```

When you start the web application container where IG runs, set the ig.instance.dir Java system property to the full path to the base location for IG files.

The following example starts Jetty server in the foreground and sets the value of ig.instance.dir:
```
$ java -Dig.instance.dir=/path/to/openig -jar start.jar
```