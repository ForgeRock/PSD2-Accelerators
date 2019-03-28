# Verified Person Data Mock

This 'Verified Person Data' mock service only returns one set of data, to be used as a showcase only. It does not implement authN/authZ or any other checks.

Currently there is no standard for how a Verified Person Data service should respond, so we're only responding with the same information every time. Additional features are left as an exercise to the integration party.

This service contains the following endpoint:

- ```POST /rest/vpd/get_verified_person_data``` - endpoint for returning a static JSON response

## Running Verified Person Data Mock
For development purposes this includes an embedded Jetty setup which will spin up a new Jetty instance with this application deployed. To run the embedded Jetty use maven together with the maven-jetty plugin like this:

``` 
 $ mvn jetty:run
``` 
Although useful for development, this is not an option for a different deployment method. To create a WAR file, run: 
```
 $ mvn package
```
