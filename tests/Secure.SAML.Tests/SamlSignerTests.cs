using NUnit.Framework;
using Secure.SAML.Signing;

namespace Secure.SAML.Tests
{
    [TestFixture]
    public class SamlSignerTests
    {
        [TestCase(SigningAlgorithm.SHA1)]
        [TestCase(SigningAlgorithm.SHA256)]
        [TestCase(SigningAlgorithm.SHA512)]
        public void TestSamlSignerWithGivenAlgorithm(SigningAlgorithm signingAlgorithm)

        {
            var response = new v2.SAML(Helper.GetCertificate).Create(Helper.GetParameters(signingAlgorithm));            
            Assert.That(SamlSigner.VerifySignature(response.OuterXml, Helper.GetCertificate()));
        }
    }
}
