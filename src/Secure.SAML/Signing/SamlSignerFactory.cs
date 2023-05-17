using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Secure.SAML.Signing
{
    internal class SamlSignerFactory : ISamlSignerFactory
    {
        private readonly IDictionary<SigningAlgorithm, ISigningAlgorithm> encrytionMethods;
        private readonly Func<X509Certificate2> certificateFactory;

        public SamlSignerFactory(Func<X509Certificate2> certificateFactory)
        {
            this.certificateFactory = certificateFactory;
            encrytionMethods = GetEncryptionMethods();
        }

        private IDictionary<SigningAlgorithm, ISigningAlgorithm> GetEncryptionMethods()
        {
            return new Dictionary<SigningAlgorithm, ISigningAlgorithm>
            {
                {SigningAlgorithm.SHA1, new Sha1SigningAlgorithm()},
                {SigningAlgorithm.SHA256, new Sha256SigningAlgorithm()},
                {SigningAlgorithm.SHA512, new Sha512SigningAlgorithm()},
            };
        }

        public ISamlSigner Create(SigningAlgorithm encryptionMethod)
        {
            var certificate = certificateFactory();
            return new SamlSigner(encrytionMethods[encryptionMethod], certificate);
        }
    }
}