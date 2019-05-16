import org.bouncycastle.asn1.x500.style.BCStyle;
import org.forgerock.openig.ob.utils.CertificateUtils;

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

public class CertificateTests {
	public static void main(String[] args) {
		String cert = "MIIFZjCCBE6gAwIBAgIUJwwA3CKWsl1i8NCRHGvA2SNBLBcwDQYJKoZIhvcNAQELBQAwezELMAkGA1UEBhMCVUsxDTALBgNVBAgTBEF2b24xEDAOBgNVBAcTB0JyaXN0b2wxEjAQBgNVBAoTCUZvcmdlUm9jazEcMBoGA1UECxMTZm9yZ2Vyb2NrLmZpbmFuY2lhbDEZMBcGA1UEAxMQb2JyaS1leHRlcm5hbC1jYTAgFw0xODAzMTgwNDQzNDBaGA8yMTE5MDIyMjA0NDM0MFowgbExITAfBgNVBAMMGDVjOTM2M2M0MDNmMGRmMDAxZDNhMmQ2OTEhMB8GA1UECwwYNWM2MTNmYTY4ODYxMGUwMDM1YmQyOTlkMRIwEAYDVQQKDAlGb3JnZVJvY2sxEDAOBgNVBAcMB0JyaXN0b2wxDTALBgNVBAgMBEF2b24xCzAJBgNVBAYTAlVLMScwJQYDVQRhDB5QU0RHQi01YzYxM2ZhNjg4NjEwZTAwMzViZDI5OWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4Pbs1NU12jFh9miMmHT6QZaQy4XUgeK/NaH6g1wnwmY2w6UUP7KjJK2Mog0np8yayKYs07HPvhA45NOogPSbIxrOYSC45UykssxCZWAgAlwIo2x5K9LjFak36Ky4XpOT1MhHPcdyvDYlpwMSOlG/ypJQigrvlYBmOrQW1gF1c8EOerkbc0KfHDgv+PfPFq9EUdM51rG5dqm1ZRwMGNYPPTRxzbMuo7l+RwMSl0vsaKBmiV43aL9fAPeO+nt258U1weBcH9BNnTGwPzwDpY8YECSnsbpH94LcFHhD+qqAaVJAjTDZo+qIneS0b6G7Q3sNUyARcEmYF4wJzqteZLnAxAgMBAAGjggGnMIIBozCBygYIKwYBBQUHAQEEgb0wgbowWwYIKwYBBQUHMAKGT2h0dHBzOi8vc2VydmljZS5kaXJlY3Rvcnkub2IuZm9yZ2Vyb2NrLmZpbmFuY2lhbDo0NDMvYXBpL2RpcmVjdG9yeS9rZXlzL2p3a191cmkwWwYIKwYBBQUHMAGGT2h0dHBzOi8vc2VydmljZS5kaXJlY3Rvcnkub2IuZm9yZ2Vyb2NrLmZpbmFuY2lhbDo0NDMvYXBpL2RpcmVjdG9yeS9rZXlzL2p3a191cmkwgdMGCCsGAQUFBwEDBIHGMIHDMAgGBgQAjkYBATAJBgcEAI5GAQYDMAkGBwQAi+xJAQIwgaAGBgQAgZgnAjCBlTBqMCkGBwQAgZgnAQQMHkNhcmQgQmFzZWQgUGF5bWVudCBJbnN0cnVtZW50czAeBgcEAIGYJwEDDBNBY2NvdW50IEluZm9ybWF0aW9uMB0GBwQAgZgnAQIMElBheW1lbnQgSW5pdGlhdGlvbgwdRm9yZ2VSb2NrIEZpbmFuY2lhbCBBdXRob3JpdHkMCEZSLUFBQUFBMA0GCSqGSIb3DQEBCwUAA4IBAQBDN18WvXy7QyIh8n+RwqldfZ1TkLQml4BymGdqC8T82vSJP75psaZBM//UtGsA7R+PfIBvg44jbQfFj2SFT/q2i22ww03o8+hlAUe4Ha6gpObBeOkPFOl3Qzi3tW2ANA0PhHa5hWBn1iSHPToS/CmvVoAcRgk5xzQL0RZn4cWH0dEtMLw31DAISN329UarefAS9QGPMnSoAWPO3RCoqYozAe7LUm52VXfEHcu6d67hIz+QHWWGo+PTBCgtW+YdmU2yn17g8Ts65QC5lEllqZ685MZEMBOIxTlaUEBfZrCJJu7M36hKd4qrMbY7M5R+1fTVlBt0B7UqE+Dxl7ayU0KX";

		CertificateUtils.getCertificateSubjectDnProperty(CertificateUtils.initializeCertificate(cert), BCStyle.OU);
	}
}