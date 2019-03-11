import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Base64;

/***************************************************************************
 * Copyright 2019 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 ***************************************************************************/

public class EidasTest {
	private static final Base64 base64 = new Base64(false);

	public static void main(String[] args) {
		String clientId = "IaIzRtIYNp";
		String clientSecret = "r78XvfBsvkTInnngOi3h72P1OF4Ro7qX";
		String client = clientId+":"+clientSecret;
		System.out.println("TEST:" + new String (base64.encode(client.getBytes())));
		String cert = "MIIEozCCA4ugAwIBAgIJAProlDhf79tIMA0GCSqGSIb3DQEBBQUAMEQxCzAJBgNVBAYTAkZSMQswCQYDVQQIEwJGUjETMBEGA1UEChMKQ2VydEV1cm9wZTETMBEGA1UEAxMKQ2VydEV1cm9wZTAeFw0xODEyMjAxNTI4MTlaFw0xOTEyMjAxNTI4MTlaMIGQMQswCQYDVQQGEwJHQjEyMDAGA1UECgwpQW1lcmljYW4gRXhwcmVzcyBQYXltZW50IFNlcnZpY2VzIExpbWl0ZWQxMjAwBgNVBAMMKUFtZXJpY2FuIEV4cHJlc3MgUGF5bWVudCBTZXJ2aWNlcyBMaW1pdGVkMRkwFwYDVQRhDBBQU0RHQi1OQ0EtNDg0MzQ3MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsucVIG3OuIyaY6n/R0zAdlXrG25tSqB/ME6+MBuV5w2mPiAThatbS9hLdfBw6KEAwF1nlv14zo6dX/D9FtIYcvtKJlC3QMD03UkeWezJww8hapiD6JN9uvWcZ5dZ1c5Kzn6HRFf3kEDDZmlXpJsBALS5eqWv1i0thFtunohUaTkYPIMTmus4lPmQgn9Ivxtb/DJ5u24RY2rAKfoYRhmOD+yAA2oZf1sSUp1u8OAaR1iOO9rtgcyxDaNwK0DNGFC4jx5D4T0964WkmwzJuKjTQqruoTmfvyNM0ZTu/Oiux097x8bHhhZXW/i6PUA224vEx7y3oGx/F/2KHJNUsXgWlQIDAQABo4IBSTCCAUUwCQYDVR0TBAIwADAdBgNVHQ4EFgQUUfxz+mNcKWG/Q0HjptQhQHTnbJgwHwYDVR0jBBgwFoAUvNTDavTTBIBKzSn/5KMu2nea4LgwCQYDVR0RBAIwADBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL3MzLmV1LXdlc3QtMi5hbWF6b25hd3MuY29tL2stY2VydHMvc3VjY2Vzcy1mdWxsLWpvdXJuZXkuY3JsMIGJBggrBgEFBQcBAQR9MHswJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLmtvbnNlbnR1cy5jb20wUgYIKwYBBQUHMAKGRmh0dHBzOi8vczMuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vay1jZXJ0cy9zdWNjZXNzLWZ1bGwtam91cm5leS1jYS5wZW0wCwYDVR0PBAQDAgTwMA0GCSqGSIb3DQEBBQUAA4IBAQBjQABl0OZEo4gm7KsVuBIrLZVFMnlPnPbsUz9xdqWpWXCB1y/FARDL2DZto2BSIMV3RWCpRbcKqE20reCyBrWcTO9Yp8VoUV59H5EdQxFyfzB/VCB741Q3+gGrzQoeQLJHBEcPZkaoUP7HwBiejswYJHXn6V5GhB3CpKjW/xlQBS7mfYo7w448CfLP45uLIQ4xDvNGUcB6gN0YAxbqPNAmwNxnXnPvidGfIpHrebcbkICzugZXZawomM1rrm+PkZ6WTjWpC1nTlySR2yINWK3/eTsdIHtAFA17eoMg6gG/Bm0f3YAWlLqPkmNXQdBpBJ/kEAT0mJqWdesR+dVjFxsW";
		byte[] decoded = base64.decode((cert.getBytes()));
		System.out.println("Decoded: " + decoded);

		CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509");

			X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));
			if (certificate != null) {
				System.out.println("Subject DN from certificate: " + certificate.getSubjectDN());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}