using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace Secure.SAML.v2
{
    internal static class SamlExtensions
    {
        internal static string ToSamlFormat(this DateTime date)
        {
            return date.ToString("s") + "Z";
        }

        internal static string ToSamlString(this NameIdFormat nameIdFormat)
        {
            switch (nameIdFormat)
            {
                case NameIdFormat.EmailAddress:
                    return "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress";

                case NameIdFormat.Transient:
                    return "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

                case NameIdFormat.Persistent:
                    return "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

                default:
                    return "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
            }
        }

        internal static string ToSamlXML(this ResponseType response)
        {
            var responseSerializer = new XmlSerializer(response.GetType());

            using (var stringWriter = new StringWriter())
            {
                var settings = new XmlWriterSettings
                {
                    OmitXmlDeclaration = true,
                    Indent = true,
                    Encoding = Encoding.UTF8
                };

                var namespaceMgr = new XmlSerializerNamespaces();
                namespaceMgr.Add("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
                namespaceMgr.Add("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

                var responseWriter = XmlWriter.Create(stringWriter, settings);
                responseSerializer.Serialize(responseWriter, response, namespaceMgr);

                var samlString = stringWriter.ToString();

                return samlString;
            }
        }
    }
}