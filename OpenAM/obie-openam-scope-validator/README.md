# OpenAM - Scope Validator

OpenAM is an "all-in-one" access management solution that provides the following features in a single unified project:

+ Authentication
    - Adaptive 
    - Strong  
+ Single sign-on (SSO)
+ Authorization
+ Entitlements
+ Federation 
+ Web Services Security

This project implements a new custom scope validator that has the purpose of adding the open\_banking\_intent_id in a token. The custom scope validator is added next to the OpenAM original features, without changing any of the out of the box source code.

## Build The Source Code

In order to build the project from the command line follow these steps:

### Prepare your Environment

You will need the following software to build the code.

```
Software               | Required Version
---------------------- | ----------------
Java Development Kit   | 1.8 and above
Maven                  | 3.1.0 and above
Git                    | 1.7.6 and above
```
The following environment variables should be set:

- `JAVA_HOME` - points to the location of the version of Java that Maven will use.
- `MAVEN_OPTS` - sets some options for the jvm when running Maven.

For example your environment variables might look something like this:

```
JAVA_HOME=/usr/jdk/jdk1.8.0_201
MAVEN_HOME=C:\Program Files\Apache_Maven_3.6.0
MAVEN_OPTS='-Xmx2g -Xms2g -XX:+CMSClassUnloadingEnabled -XX:MaxPermSize=512m'
```

### Getting the Code

If you want to run the code unmodified you can simply clone the ForgeRock PSD2-Accelerators repository:

```
git clone https://github.com/ForgeRock/PSD2-Accelerators.git
git checkout obie-prod
```


### Building the Code

The build process and dependencies are managed by Maven. The first time you build the project, Maven will pull 
down all the dependencies and Maven plugins required by the build, which can take a longer time. 
Subsequent builds will be much faster!

```
cd /OpenAM/obie-openam-scope-validator
mvn package
```

Maven builds the binary in `obie-openam-scope-validator/target/`. The file name format is `obie-openam-scope-validator-<nextversion>-SNAPSHOT.jar` , 
for example "obie-openam-scope-validator-2.0.0-SNAPSHOT.jar".


### Adding the library to OpenAM war

+ Download and unzip the OpenAM.war from ForgeRock backstage:

```
https://backstage.forgerock.com/downloads/browse/am/latest
$ mkdir ROOT && CD ROOT
$ jar -xf ~/Downloads/AM-6.5.1.war
```

+ Copy the newly generated jar file to /ROOT/WEB-INF/lib folder

```
$ cp ~/obie-openam-scope-validator-<nextversion>-SNAPSHOT.jar WEB-INF/lib
```

+ Rebuild the war file: 

```
$ jar -cf ../ROOT.war *
```

## License

This project is licensed under the Common Development and Distribution License (CDDL). The following text applies to 
both this file, and should also be included in all files in the project:

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