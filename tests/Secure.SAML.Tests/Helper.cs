using System.Collections.Generic;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Secure.SAML.Tests
{
    public static class Helper
    {
        public static X509Certificate2 GetCertificate()
        {
            var signedStream = typeof (Helper)
                .Assembly.GetManifestResourceStream("Secure.SAML.Tests.SelfSignedKey.pfx");
            var signingCertRawData = new byte[signedStream.Length];
            signedStream.Read(signingCertRawData, 0, (int) signedStream.Length);
            return new X509Certificate2(signingCertRawData, "password", X509KeyStorageFlags.Exportable);
        }
        public static Parameters GetParameters(SigningAlgorithm algorithm) => new Parameters
        (
                    issuer: "http://ninjacorp.com",
                    recipient: "https://xyz.target-link.co.uk:443/saml/api",
                    audienceRestrictions: new[] { "xyz.target-link.co.uk" },
                    namedId: "NIN0123456",
                    nameIdFormat: NameIdFormat.Unspecified,
                    attributes: new Dictionary<string, string> { { "Custom_key", "value" } },
                    signatureType: SignType.Response,
                    notOnOrAfterInMins: 10,
                    signingAlgorithm: algorithm,
                    samlId: Guid.Parse("95AD6A84-95C1-4B39-AE5E-FE1E700C406C"),
                    assertionId: Guid.Parse("B3CA912A-4A6B-4F31-9FD8-FC5E55837656"),
                    timestamp: DateTime.Parse("2018-02-27T09:36:44.0665619Z")
        );
    }
}