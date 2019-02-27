import java.io.IOException;

import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.openig.tools.JwtUtil;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

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

public class JWTTest {
	public static void main(String[] args) {
		String jwt = "eyJraWQiOiJkOTdmNmFlNzg3MmM4MGZlYjVjM2Y2MWZjZDE1MjlkMjEyYmZkMWJhIiwiYWxnIjoiUlMyNTYifQ.eyJ0b2tlbl9lbmRwb2ludF9hdXRoX3NpZ25pbmdfYWxnIjoiUlMyNTYiLCJyZXF1ZXN0X29iamVjdF9lbmNyeXB0aW9uX2FsZyI6IlJTQS1PQUVQLTI1NiIsImdyYW50X3R5cGVzIjpbImF1dGhvcml6YXRpb25fY29kZSIsInJlZnJlc2hfdG9rZW4iLCJjbGllbnRfY3JlZGVudGlhbHMiXSwiaXNzIjoiNWM1MDcyYzE4ODYxMGUwMDM1YmQyOTMwIiwicmVkaXJlY3RfdXJpcyI6WyJodHRwczpcL1wvd3d3Lmdvb2dsZS5jb20iXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2QiOiJwcml2YXRlX2tleV9qd3QiLCJzb2Z0d2FyZV9zdGF0ZW1lbnQiOiJleUpyYVdRaU9pSm1OekEyWlRRMlpXUmlNekV3WldRMU56ZGlORFptTXpObU9UTmlNelE0WVdReFpHWmtPVE5tSWl3aVlXeG5Jam9pVWxNeU5UWWlmUS5leUp2Y21kZmFuZHJjMTlsYm1Sd2IybHVkQ0k2SWxSUFJFOGlMQ0p6YjJaMGQyRnlaVjl0YjJSbElqb2lWRVZUVkNJc0luTnZablIzWVhKbFgzSmxaR2x5WldOMFgzVnlhWE1pT2xzaWFIUjBjRHBjTDF3dmFtVnVhMmx1Y3k1cGRITnRZWEowYzNsemRHVnRjeTVsZFRvNE1EZ3hYQzloY0c5c2JHOHRjMmh2Y0NJc0ltaDBkSEJ6T2x3dlhDOTNkM2N1WjI5dloyeGxMbU52YlNJc0ltaDBkSEJ6T2x3dlhDOXNiMmRwYmk1d2MyUXlZV05qWld4bGNtRjBiM0p6TG1aeWFXUmhiUzVoWldWMExXWnZjbWRsY205amF5NWpiMjFjTDI5d1pXNWhiU0pkTENKdmNtZGZjM1JoZEhWeklqb2lRV04wYVhabElpd2ljMjltZEhkaGNtVmZZMnhwWlc1MFgyNWhiV1VpT2lKSlUxTWdWRkJRSWl3aWMyOW1kSGRoY21WZlkyeHBaVzUwWDJsa0lqb2lOV00xTURjeVl6RTRPRFl4TUdVd01ETTFZbVF5T1RNd0lpd2lhWE56SWpvaVJtOXlaMlZTYjJOcklpd2ljMjltZEhkaGNtVmZZMnhwWlc1MFgyUmxjMk55YVhCMGFXOXVJam9pVkZCUUlGVnpaV1FnWm05eUlIUmxjM1JwYm1jZ2NIVnljRzl6WlhNaUxDSnpiMlowZDJGeVpWOXFkMnR6WDJWdVpIQnZhVzUwSWpvaWFIUjBjSE02WEM5Y0wzTmxjblpwWTJVdVpHbHlaV04wYjNKNUxtOWlMbVp2Y21kbGNtOWpheTVtYVc1aGJtTnBZV3c2TkRRelhDOWhjR2xjTDNOdlpuUjNZWEpsTFhOMFlYUmxiV1Z1ZEZ3dk5XTTFNRGN5WXpFNE9EWXhNR1V3TURNMVltUXlPVE13WEM5aGNIQnNhV05oZEdsdmJsd3ZhbmRyWDNWeWFTSXNJbk52Wm5SM1lYSmxYMmxrSWpvaU5XTTFNRGN5WXpFNE9EWXhNR1V3TURNMVltUXlPVE13SWl3aWIzSm5YMk52Ym5SaFkzUnpJanBiWFN3aWIySmZjbVZuYVhOMGNubGZkRzl6SWpvaWFIUjBjSE02WEM5Y0wyUnBjbVZqZEc5eWVTNXZZaTVtYjNKblpYSnZZMnN1Wm1sdVlXNWphV0ZzT2pRME0xd3ZkRzl6WEM4aUxDSnZjbWRmYVdRaU9pSTFZelV3Tm1VME5EZzROakV3WlRBd016VmlaREk1TW1ZaUxDSnpiMlowZDJGeVpWOXFkMnR6WDNKbGRtOXJaV1JmWlc1a2NHOXBiblFpT2lKVVQwUlBJaXdpYzI5bWRIZGhjbVZmY205c1pYTWlPbHNpUTBKUVNVa2lMQ0pRU1ZOUUlpd2lRVWxUVUNJc0lrUkJWRUVpWFN3aVpYaHdJam94TlRVd05qWTVNRGszTENKdmNtZGZibUZ0WlNJNkltUmhibWxsYkM1amIyMWhia0JwZEhOdFlYSjBjM2x6ZEdWdGN5NWxkU0lzSW05eVoxOXFkMnR6WDNKbGRtOXJaV1JmWlc1a2NHOXBiblFpT2lKVVQwUlBJaXdpYVdGMElqb3hOVFV3TURZME1qazNMQ0pxZEdraU9pSmlZbVJrWW1NeFppMDNNVGMzTFRRM1kySXRPV001WVMwMU9UWmxOekZrTldJd1ltSWlmUS5Jc1pMb1VJazRTNUExUVN5Nk42Vk4yQXRIaUFBOEJENXdnd2dyQkMwNUpKVzFwSFUxbmFKRWJtc21kakNFUWNfeHUxUlNtaWtfUG8tMTlicTF4aU9Xako5clpvTHNsWlpFTWYtOWNrNWxBYWJYbDlMcVkzbzdzbFRYVkNpZzlZaURkRGJzLVBoYS1ZV2RHUU9xU0pNdDJUaXRxNXRtb0NCd0RBLW5NNGtKSFNqUmY1ZTRvN1ROakpuV29Udk9Ld0ZRemZaYWk4Y3NmVkI3cmtPUGxVTEluSm11d212d1NYYmN0QTR6dEkxZGVxTFR0SE03bC1ndnM5ZTBOUFBJejVJTTcwWnROUnBYNGx4c05mdGJzSjZhYXpnZklVVy1XSkZ2OS0tV0dTXzJxbDItY2N6cXJ3ZmZDY3YwbEZES2VWbUFEVkRoV254UkJpZFM1Q21yQ3Rrc1EiLCJzY29wZSI6Im9wZW5pZCBhY2NvdW50cyBwYXltZW50cyIsInJlcXVlc3Rfb2JqZWN0X3NpZ25pbmdfYWxnIjoiUlMyNTYiLCJleHAiOjE1NTAwNjQ2MTAsInJlcXVlc3Rfb2JqZWN0X2VuY3J5cHRpb25fZW5jIjoiQTEyOENCQy1IUzI1NiIsImlhdCI6MTU1MDA2NDMwMSwianRpIjoiZmQwYjExNGItNWU3NC00ZWQ2LThhMWMtYzA2N2FiMWUzZWZjIiwicmVzcG9uc2VfdHlwZXMiOlsiY29kZSBpZF90b2tlbiJdLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYifQ.CvbrrEKKJddzOuVgLJVARrqP21XVZTbId6KtDOdGe0rMgjC0Mu5BR6fkn0cOJP4U9NvbI50i39EOtnxMML9wKHyoc2x-kPT6RlN5Kj0oXgM2u8bux4w_o6PvBKXZHTrraSVAB8WGXYYFZpV7RwxKOCOsq5J8rhNfAIwu83NP_Ct4C3eHc3AdU9ILXlJw_zUVFejedwtenAZLVsGAeZwzTkepuBmsiMqXAqL4vc8xkqxsC41JBJ5U7h0wTj1OK7p0z95EaPMbeF_TcPR3QyRbZmCWY19f0sM6NNM0FRpWEacpEfda0DRrS20YD0kR5v-2qZitDcSvLp9ijZDQ6a_06A";
		Jwt registrationJwt = JwtUtil.reconstructJwt(jwt, Jwt.class);
		String claims = registrationJwt.getClaimsSet().build();
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode node;
		try {
			node = (ObjectNode) mapper.readTree(claims);
			node.remove("software_statement");
			System.out.println("TEST: " + node.toString());
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
}