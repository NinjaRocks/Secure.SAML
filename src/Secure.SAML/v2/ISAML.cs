using System.Xml;

namespace Secure.SAML.v2
{
    public interface ISAML
    {
        XmlDocument Create(Parameters parameters);

        string CreateEncoded(Parameters parameters);
    }
}