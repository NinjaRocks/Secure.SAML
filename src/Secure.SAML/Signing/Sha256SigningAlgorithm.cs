using System;
using System.Security.Cryptography.Xml;

namespace Secure.SAML.Signing
{
    internal class Sha256SigningAlgorithm : ISigningAlgorithm
    {
        // http://www.w3.org/2001/10/xml-exc-c14n#
        public string CanonicalizationMethod { get; } = SignedXml.XmlDsigExcC14NTransformUrl;
        //SignedXml.XmlDsigExcC14NTransformUrl;
        //var r =  //http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
        public string SignatureMethod { get; } = SignedXml.XmlDsigRSASHA256Url;
        //SignedXml.XmlDsigSHA256Url;
        public string DigestMethod { get; } = SignedXml.XmlDsigSHA256Url;
            // "http://www.w3.org/2001/04/xmlenc#sha256";

        public void AddTransforms(Reference reference)
        {
            if (reference == null)
                throw new ArgumentException("reference parameter is null");

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform("#default saml ds xs xsi"));
        }
    }
}