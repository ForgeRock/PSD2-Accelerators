##Local 
	mvn clean install -DskipTests -Pdev
	mvn spring-boot:run -Pdev

####Test Deploy
Run in terminal/ecliplse maven
	mvn clean install -DskipTests -Ptest

rename 
	psd-2-rsc-sevice-0.0.1-SNAPSHOT.war -> ASPSP_ASSET.war

kill  process 
	ps -ef | grep ASPSP_ASSET

use alias to run app
	startForgeRockUSAsset

access and copy all from this page {ENV}/api/rcs/consent/jwk_pub
	http://18.211.177.234:8083/api/rcs/consent/jwk_pub

access openAM {ENV}/XUI/#realms/%2Fopenbanking/applications-agents-remoteConsent/agents/edit/forgerock-rcs
	https://login.psd2accelerators.fridam.aeet-forgerock.com/XUI/#realms/%2Fopenbanking/applications-agents-remoteConsent/agents/edit/forgerock-rcs
or navigate to:
	OpenAm (login with admin) -> realms (openbanking) - > Applications -> Agents -> Remote Consent -> agents 
	In  Public key selector  : JWKs (should be value)
	In Json Web Key : {"keys":[{"kty".....
	Save.

Enjoy!
#### END Test Deploy

# psd2RSCSevice

This application was generated using JHipster 5.7.2, you can find documentation and help at [https://www.jhipster.tech/documentation-archive/v5.7.2](https://www.jhipster.tech/documentation-archive/v5.7.2).

This is a "microservice" application intended to be part of a microservice architecture, please refer to the [Doing microservices with JHipster][] page of the documentation for more information.

This application is configured for Service Discovery and Configuration with the JHipster-Registry. On launch, it will refuse to start if it is not able to connect to the JHipster-Registry at [http://localhost:8761](http://localhost:8761). For more information, read our documentation on [Service Discovery and Configuration with the JHipster-Registry][].

## Development

To start your application in the dev profile, simply run:

    ./mvnw

For further instructions on how to develop with JHipster, have a look at [Using JHipster in development][].

## Building for production

To optimize the psd2RSCSevice application for production, run:

    ./mvnw -Pprod clean package

To ensure everything worked, run:

    java -jar target/*.war

Refer to [Using JHipster in production][] for more details.

## Testing

To launch your application's tests, run:

    ./mvnw clean test

For more information, refer to the [Running tests page][].

### Code quality

Sonar is used to analyse code quality. You can start a local Sonar server (accessible on http://localhost:9001) with:

```
docker-compose -f src/main/docker/sonar.yml up -d
```

Then, run a Sonar analysis:

```
./mvnw -Pprod clean test sonar:sonar
```

For more information, refer to the [Code quality page][].

## Using Docker to simplify development (optional)

You can use Docker to improve your JHipster development experience. A number of docker-compose configuration are available in the [src/main/docker](src/main/docker) folder to launch required third party services.

You can also fully dockerize your application and all the services that it depends on.
To achieve this, first build a docker image of your app by running:

    ./mvnw package -Pprod verify jib:dockerBuild

Then run:

    docker-compose -f src/main/docker/app.yml up -d

For more information refer to [Using Docker and Docker-Compose][], this page also contains information on the docker-compose sub-generator (`jhipster docker-compose`), which is able to generate docker configurations for one or several JHipster applications.

## Continuous Integration (optional)

To configure CI for your project, run the ci-cd sub-generator (`jhipster ci-cd`), this will let you generate configuration files for a number of Continuous Integration systems. Consult the [Setting up Continuous Integration][] page for more information.

[jhipster homepage and latest documentation]: https://www.jhipster.tech
[jhipster 5.7.2 archive]: https://www.jhipster.tech/documentation-archive/v5.7.2
[doing microservices with jhipster]: https://www.jhipster.tech/documentation-archive/v5.7.2/microservices-architecture/
[using jhipster in development]: https://www.jhipster.tech/documentation-archive/v5.7.2/development/
[service discovery and configuration with the jhipster-registry]: https://www.jhipster.tech/documentation-archive/v5.7.2/microservices-architecture/#jhipster-registry
[using docker and docker-compose]: https://www.jhipster.tech/documentation-archive/v5.7.2/docker-compose
[using jhipster in production]: https://www.jhipster.tech/documentation-archive/v5.7.2/production/
[running tests page]: https://www.jhipster.tech/documentation-archive/v5.7.2/running-tests/
[code quality page]: https://www.jhipster.tech/documentation-archive/v5.7.2/code-quality/
[setting up continuous integration]: https://www.jhipster.tech/documentation-archive/v5.7.2/setting-up-ci/
