# Mediation Records Mock

This 'Mediation Records' mock service only logs POST data, to be used as a showcase only. It does not implement authN/authZ or any other checks.

Currently there is no standard for how a mediation record service should respond, so we're only displaying incoming request data. Additional features are left as an exercise to the integration party.

This service contains the following endpoint:

- ```POST /rest/mediation/record``` - endpoint for submitting JSON data

## Running Mediation Record Mock
For development purposes this includes an embedded Jetty setup which will spin up a new Jetty instance with this application deployed. To run the embedded Jetty use maven together with the maven-jetty plugin like this:

``` 
 $ mvn jetty:run
``` 
Although useful for development, this is not an option for a different deployment method. To create a WAR file, run: 
```
 $ mvn package
```