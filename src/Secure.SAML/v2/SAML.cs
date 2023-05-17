using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Secure.SAML.Signing;

namespace Secure.SAML.v2
{
    public class SAML : ISAML
    {
        private readonly ISamlSignerFactory samlSignerFactory;

        public SAML(Func<X509Certificate2> certificateFactory)
        : this(new SamlSignerFactory(certificateFactory))
        {
        }

        internal SAML(ISamlSignerFactory samlSignerFactory)
        {
            this.samlSignerFactory = samlSignerFactory;
        }

        /// <summary>
        /// Creates Base64 encoded SAML Response.
        /// </summary>
        /// <param name="parameters">Saml parameters</param>
        /// <returns>Base64String</returns>
        public string CreateEncoded(Parameters parameters)
        {
            var document = Create(parameters);
            var base64EncodedBytes = Encoding.UTF8.GetBytes(document.OuterXml);
            var encoded = Convert.ToBase64String(base64EncodedBytes);
            return encoded;
        }

        /// <summary>
        /// Creates a SAML Response.
        /// </summary>
        /// <param name="parameters">Saml parameters</param>
        /// <returns>XmlDocument</returns>
        public XmlDocument Create(Parameters parameters)
        {
            parameters.Validate();

            var response = new ResponseType
            {
                ID = "_" + parameters.SamlId.ToString("N"),
                Destination = parameters.Recipient,
                Version = "2.0",
                IssueInstant = parameters.Timestamp.ToSamlFormat(),
                Issuer = new NameIDType { Value = parameters.Issuer.Trim() },
                Status = new StatusType
                {
                    StatusCode = new StatusCodeType { Value = "urn:oasis:names:tc:SAML:2.0:status:Success" }
                }
            };

            var assertionType = CreateSamlAssertion(parameters);

            response.Items = new AssertionType[] { assertionType };

            var samlString = response.ToSamlXML();

            samlString = AppendSubjectConfirmationData(parameters, samlString);

            var doc = new XmlDocument();
            doc.LoadXml(samlString);

            var samlSigner = samlSignerFactory.Create(parameters.SigningAlgorithm);
            var signature = samlSigner.Sign(doc, "ID", parameters.IsSignedResponse ? response.ID : assertionType.ID);

            if (parameters.IsSignedResponse)
            {
                doc.DocumentElement.InsertBefore(signature, doc.DocumentElement.ChildNodes[1]);
                return doc;
            }

            var assertionNode = doc.DocumentElement.GetElementsByTagName("saml:Assertion")[0];
            assertionNode.InsertBefore(signature, assertionNode.ChildNodes[1]);

            return doc;
        }

        private static string AppendSubjectConfirmationData(Parameters config, string samlString)
        {
            samlString = config.NotOnOrAfterInMinutes > 0
                ? samlString.Replace("SubjectConfirmationData",
                    $"SubjectConfirmationData NotOnOrAfter=\"{config.Timestamp.AddMinutes(config.NotOnOrAfterInMinutes).ToSamlFormat()}\" Recipient=\"{config.Recipient}\"")
                : samlString.Replace("SubjectConfirmationData", $"SubjectConfirmationData Recipient=\"{config.Recipient}\"");
            return samlString;
        }

        private AssertionType CreateSamlAssertion(Parameters config)
        {
            var attributes = config.Attributes ?? new Dictionary<string, string>();

            var assertion = new AssertionType
            {
                ID = "_" + config.AssertionId.ToString("N"),
                Issuer = new NameIDType { Value = config.Issuer.Trim() },
                IssueInstant = config.Timestamp.ToSamlFormat(),
                Version = "2.0"
            };

            if (config.AudienceRestrictions != null && config.AudienceRestrictions.Any())
            {
                var conditions = new ConditionsType
                {
                    Items = new ConditionAbstractType[]
                    {
                        new AudienceRestrictionType
                        {
                            Audience = config.AudienceRestrictions
                        }
                    }
                };

                if (config.NotOnOrAfterInMinutes > 0)
                {
                    conditions.NotBefore = config.Timestamp.AddMinutes(-1.0).ToSamlFormat();
                    conditions.NotBeforeSpecified = true;
                    conditions.NotOnOrAfter = config.Timestamp.AddMinutes(config.NotOnOrAfterInMinutes).ToSamlFormat();
                    conditions.NotOnOrAfterSpecified = true;
                }

                assertion.Conditions = conditions;
            }

            var nameIdentifier = new NameIDType
            {
                Value = config.NamedId.Trim()
            };

            if (config.NameIdFormat != NameIdFormat.None)
                nameIdentifier.Format = config.NameIdFormat.ToSamlString();

            var subjectConfirmation = new SubjectConfirmationType
            {
                Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer",
                SubjectConfirmationData = new SubjectConfirmationDataType()
            };

            var samlSubject = new SubjectType { Items = new object[] { nameIdentifier, subjectConfirmation } };

            assertion.Subject = samlSubject;

            var authStatement = new AuthnStatementType
            {
                AuthnInstant = config.Timestamp.ToSamlFormat(),
                AuthnContext = new AuthnContextType
                {
                    ItemsElementName = new[] { ItemsChoiceType5.AuthnContextClassRef },
                    Items = new object[] { "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" }
                }
            };

            AttributeStatementType attrStatement = null;
            if (attributes.Any())
            {
                attrStatement = new AttributeStatementType { Items = new AttributeType[attributes.Count] };
                var i = 0;

                foreach (var attribute in attributes)
                {
                    var attr = new AttributeType
                    {
                        Name = attribute.Key,
                        NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                        AttributeValue = new[] { attribute.Value }
                    };
                    attrStatement.Items[i] = attr;
                    i++;
                }
            }

            assertion.Items = attrStatement != null
                ? new StatementAbstractType[] { authStatement, attrStatement }
                : new StatementAbstractType[] { authStatement };

            return assertion;
        }
    }
}