using System;
using System.Security.Cryptography.Xml;

namespace Secure.SAML.Signing
{
    internal class Sha1SigningAlgorithm : ISigningAlgorithm
    {
        public string CanonicalizationMethod { get; } = "http://www.w3.org/2001/10/xml-exc-c14n#";
        public string SignatureMethod { get; } = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        public string DigestMethod { get; } = "http://www.w3.org/2000/09/xmldsig#sha1";

        public void AddTransforms(Reference reference)
        {
            if (reference == null)
                throw new ArgumentException("reference parameter is null");

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform("#default saml ds xs xsi"));
        }
    }
}