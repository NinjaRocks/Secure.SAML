using System.Security.Cryptography.Xml;

namespace Secure.SAML.Signing
{
    internal interface ISigningAlgorithm
    {
        string CanonicalizationMethod { get; }
        string SignatureMethod { get; }
        string DigestMethod { get; }
        void AddTransforms(Reference reference);
    }
}