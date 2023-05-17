using System;
using System.Security.Cryptography.Xml;
using NUnit.Framework;

namespace Secure.SAML.Tests
{
    [TestFixture]
    public class SHA1SigningAlgorithmTests
    {
        [Test]
        public void TestSigningAlgorithmForCorrectSettings()
        {
            var encryptionMethod = new Signing.Sha1SigningAlgorithm();

            Assert.That(encryptionMethod.SignatureMethod, Is.EqualTo("http://www.w3.org/2000/09/xmldsig#rsa-sha1"));
            Assert.That(encryptionMethod.CanonicalizationMethod, Is.EqualTo("http://www.w3.org/2001/10/xml-exc-c14n#"));
            Assert.That(encryptionMethod.DigestMethod, Is.EqualTo("http://www.w3.org/2000/09/xmldsig#sha1"));

            var reference = new Reference();
            encryptionMethod.AddTransforms(reference);

            Assert.IsTrue(reference.TransformChain[0] is XmlDsigEnvelopedSignatureTransform);
            Assert.IsTrue(reference.TransformChain[1] is XmlDsigExcC14NTransform);

            var xmlDsigExcC14NTransform = (XmlDsigExcC14NTransform)reference.TransformChain[1];
            Assert.That(xmlDsigExcC14NTransform.InclusiveNamespacesPrefixList, Is.EqualTo("#default saml ds xs xsi"));
        }

        [Test]
        public void TestAddTransformsForNullArgumentToThrowException()
        {
            var encryptionMethod = new Signing.Sha1SigningAlgorithm();
            Assert.Throws<ArgumentException>(() => encryptionMethod.AddTransforms(null));
        }
    }
}