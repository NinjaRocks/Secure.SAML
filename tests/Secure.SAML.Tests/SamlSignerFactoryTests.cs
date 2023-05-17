using System;
using NUnit.Framework;
using Secure.SAML.Signing;

namespace Secure.SAML.Tests
{
    [TestFixture]
    public class SamlSignerFactoryTests
    {
        [TestCase(SigningAlgorithm.SHA1, typeof(Sha1SigningAlgorithm))]
        [TestCase(SigningAlgorithm.SHA256, typeof(Sha256SigningAlgorithm))]
        [TestCase(SigningAlgorithm.SHA512, typeof(Sha512SigningAlgorithm))]
        public void TestFactoryForReturningCorrectSignerType(SigningAlgorithm encryptionMethod, Type type)
        {
            var signerFactory = new SamlSignerFactory(Helper.GetCertificate);
            var signer = (SamlSigner)signerFactory.Create(encryptionMethod);
            Assert.IsAssignableFrom(type, signer.SigningAlgorithm);
        }
    }
}
