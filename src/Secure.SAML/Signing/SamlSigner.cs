using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Secure.SAML.Signing
{
    internal class SamlSigner : ISamlSigner
    {
        internal readonly ISigningAlgorithm SigningAlgorithm;
        private readonly X509Certificate2 certificate;

        public SamlSigner(ISigningAlgorithm signingAlgorithm, X509Certificate2 certificate)
        {
            SigningAlgorithm = signingAlgorithm;
            this.certificate = certificate;
        }

        public XmlElement Sign(XmlDocument xmlDoc, string referenceId, string referenceValue)
        {
            var signingkey = certificate.GetRSAPrivateKey();

            var signedXml = new SamlSignedXml(xmlDoc, referenceId) { SigningKey = signingkey };

            // Set canonical method to Exclusive Canonical XML.
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            
            // Set signature method to signed XML.
            signedXml.SignedInfo.SignatureMethod = SigningAlgorithm.SignatureMethod;

            // Create a reference to be signed. 
            var reference = new Reference { Uri = "#" + referenceValue };

                  
            // Add an enveloped transformation to the reference. 
            SigningAlgorithm.AddTransforms(reference);

            // Set digest method of reference to be signed.
            reference.DigestMethod = SigningAlgorithm.DigestMethod;


            // Add the reference to the SignedXml object. 
            signedXml.AddReference(reference);

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate). 
            var keyInfo = new KeyInfo();
            var keyData = new KeyInfoX509Data(certificate);

            keyInfo.AddClause(keyData);

            signedXml.KeyInfo = keyInfo;

            // Compute the signature. 
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save it to an XmlElement object. 
            var xmlDigitalSignature = signedXml.GetXml();

            return xmlDigitalSignature;
        }

        internal static bool VerifySignature(string xml, X509Certificate2 certificate)
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xml);

            var key = certificate.PublicKey.Key;

            var result = true;

            foreach (XmlElement node in xmlDoc.SelectNodes("//*[local-name()='Signature']"))
            {
                var doc = new XmlDocument();
                doc.LoadXml(node.ParentNode.OuterXml);

                var signedXml = new SignedXml(node.ParentNode as XmlElement);
                signedXml.LoadXml(node);
                result &= signedXml.CheckSignature(key);
            }

            return result;
        }
    }
}