using System;
using System.Collections.Generic;

namespace Secure.SAML
{
    public class Parameters
    {
        internal Parameters(string issuer
       , string recipient
       , string[] audienceRestrictions
       , string namedId
       , NameIdFormat nameIdFormat
       , Dictionary<string, string> attributes
       , SignType signatureType
       , int notOnOrAfterInMins
       , SigningAlgorithm signingAlgorithm
       , Guid samlId = default(Guid)
       , Guid assertionId = default(Guid)
       , DateTime timestamp = default(DateTime))
        {
            Issuer = issuer;
            Recipient = recipient;
            AudienceRestrictions = audienceRestrictions;
            NamedId = namedId;
            NameIdFormat = nameIdFormat;
            Attributes = attributes;
            SignatureType = signatureType;
            NotOnOrAfterInMinutes = notOnOrAfterInMins;
            SignatureType = signatureType;
            SamlId = samlId;
            AssertionId = assertionId;
            Timestamp = timestamp;
            SigningAlgorithm = signingAlgorithm;
        }

        public Parameters()
        {
            AssertionId = Guid.NewGuid();
            SamlId = Guid.NewGuid();
            NotOnOrAfterInMinutes = 10;
            SignatureType = SignType.Response;
            NameIdFormat = NameIdFormat.Unspecified;
            Timestamp = DateTime.UtcNow;
            SigningAlgorithm = SigningAlgorithm.SHA512;
        }

        /// <summary>
        /// Issuers name
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Recipient name (ConsumerServiceUrl)
        /// </summary>
        public string Recipient { get; set; }

        /// <summary>
        /// Audience Restrictions
        /// </summary>
        public string[] AudienceRestrictions { get; set; }

        /// <summary>
        /// Name Identity or subject
        /// </summary>
        public string NamedId { get; set; }

        /// <summary>
        /// Name Identity Format
        /// </summary>
        public NameIdFormat NameIdFormat { get; set; }

        /// <summary>
        /// Custom attributes
        /// </summary>
        public Dictionary<string, string> Attributes { get; set; }

        /// <summary>
        /// Signature type wether sign response or assertion.
        /// </summary>
        public SignType SignatureType { get; set; }

        /// <summary>
        /// NotOnOrAfter value in minutes (default is timestamp not added when not supplied)
        /// </summary>
        public int NotOnOrAfterInMinutes { get; }

        /// <summary>
        /// date time stamp for the message
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Signing Algorithm (SHA512, SHA256, SHA1). Default is SHA512.
        /// </summary>
        public SigningAlgorithm SigningAlgorithm { get; set; }

        /// <summary>
        /// Saml Id
        /// </summary>
        internal Guid SamlId { get; set; }

        /// <summary>
        /// Assertion Id
        /// </summary>
        internal Guid AssertionId { get; set; }

        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(Issuer))
                throw new ArgumentNullException($"{nameof(Issuer)} is null");
            if (string.IsNullOrWhiteSpace(Recipient))
                throw new ArgumentNullException($"{nameof(Recipient)} is null");
            if (string.IsNullOrWhiteSpace(NamedId))
                throw new ArgumentNullException($"{nameof(NamedId)} is null");
        }

        public bool IsSignedResponse
        {
            get { return SignatureType == SignType.Response; }
        }
    }
}