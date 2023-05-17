using System.Xml;

namespace Secure.SAML.Signing
{
    internal interface ISamlSigner
    {
        /// <summary>
        /// Signs an XML Document for a Saml Response
        /// </summary>
        /// <param name="xmlDoc"></param>
        /// <param name="referenceId"></param>
        /// <param name="referenceValue"></param>
        /// <returns></returns>
        XmlElement Sign(XmlDocument xmlDoc, string referenceId, string referenceValue);
    }
}