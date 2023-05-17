using System;
using System.Security.Cryptography.Xml;

namespace Secure.SAML.Signing
{
    internal class Sha256SigningAlgorithm : ISigningAlgorithm
    {
        public string CanonicalizationMethod { get; } = SignedXml.XmlDsigExcC14NTransformUrl;
        public string SignatureMethod { get; } = SignedXml.XmlDsigRSASHA256Url;
        public string DigestMethod { get; } = SignedXml.XmlDsigSHA256Url;

        public void AddTransforms(Reference reference)
        {
            if (reference == null)
                throw new ArgumentException("reference parameter is null");

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform("#default saml ds xs xsi"));
        }
    }
}