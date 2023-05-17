using System;
using NUnit.Framework;
using Secure.SAML.v2;

namespace Secure.SAML.Tests
{
    [TestFixture]
    public class SamlExtensionTests
    {
        [Test]
        public void TestToSamlDateFormatForCorrectUTCCharacters()
        {
            var date = DateTime.Parse("2018-02-27T09:36:44.0665619Z");
            var dateTime = date.ToSamlFormat();
            Assert.That(dateTime, Is.EqualTo("2018-02-27T09:36:44Z"));
        }

        [TestCase(NameIdFormat.EmailAddress, "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress")]
        [TestCase(NameIdFormat.Transient, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")]
        [TestCase(NameIdFormat.Persistent, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")]
        [TestCase(NameIdFormat.Unspecified, "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified")]
        public void TestToSamlStringFormatForCorrectNameIdFormat(NameIdFormat nameIdFormat, string urn)
        {
            var samlUrn = nameIdFormat.ToSamlString();
            Assert.That(samlUrn, Is.EqualTo(urn));
        }

        [Test]
        public void TestToSamlXMLExtensionForCorrectNamespaces()
        {
            var samlResponse = new ResponseType();
            var samlXml = samlResponse.ToSamlXML();

            Assert.That(samlXml.Contains(@"xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"""));
            Assert.That(samlXml.Contains(@"xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"""));
        }
    }
}