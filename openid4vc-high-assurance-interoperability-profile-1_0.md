%%%
title = "OpenID4VC High Assurance Interoperability Profile 1.0 - Editor's draft"
abbrev = "openid4vc-high-assurance-interoperability-profile"
ipr = "none"
workgroup = "Digital Credentials Protocols"
keyword = ["security", "openid4vc", "sd-jwt", "sd-jwt-vc", "mdoc"]

[seriesInfo]
name = "Internet-Draft"
value = "openid4vc-high-assurance-interoperability-profile-1_0-04"
status = "standard"

[[author]]
initials="K."
surname="Yasuda"
fullname="Kristina Yasuda"
organization="SPRIND"
   [author.address]
   email = "kristina.yasuda@sprind.org"

[[author]]
initials="T."
surname="Lodderstedt"
fullname="Torsten Lodderstedt"
organization="SPRIND"
   [author.address]
   email = "torsten@lodderstedt.net"

%%%

.# Abstract

This document defines a profile of OpenID for Verifiable Credentials in combination with the credential formats IETF SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc [@!ISO.18013-5]. The aim is to select features and to define a set of requirements for the existing specifications to enable interoperability among Issuers, Wallets and Verifiers of Credentials where a high level of security and privacy is required. The profiled specifications include OpenID for Verifiable Credential Issuance [@!OIDF.OID4VCI], OpenID for Verifiable Presentations [@!OIDF.OID4VP], IETF SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc], and ISO mdoc [@!ISO.18013-5].

{mainmatter}

# Introduction

This document defines a set of requirements for the existing specifications to enable interoperability among Issuers, Wallets and Verifiers of Credentials where a high level of security and privacy is required. This document is an interoperability profile that can be used by implementations in various contexts, be it a certain industry or a certain regulatory environment.

This document is not a specification, but a profile. It refers to the specifications required for implementations to interoperate among each other and for the optionalities mentioned in the referenced specifications, defines the set of features to be mandatory to implement.

The profile uses OpenID for Verifiable Credential Issuance [@!OIDF.OID4VCI] and OpenID for Verifiable Presentations [@!OIDF.OID4VP] as the base protocols for issuance and presentation of Credentials, respectively. The credential formats used are IETF SD-JWT VC as specified in [@!I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc [@!ISO.18013-5]. Additionally, considerations are given on how the issuance of Credentials in both IETF SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc [@ISO.18013-5] formats can be performed in the same transaction.

A full list of the open standards used in this profile can be found in Overview of the Open Standards Requirements (reference).

## Audience Target audience/Usage

The audience of the document is implementers who require a high level of security and privacy for their solutions. A non-exhaustive list of the interested parties includes anyone implementing [eIDAS 2.0](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401183), [California Department of Motor Vehicles](https://www.dmv.ca.gov/portal/), [Open Wallet Foundation (OWF)](https://openwallet.foundation/), [IDunion](https://idunion.org/?lang=en), [GAIN](https://gainforum.org/), and [the Trusted Web project of the Japanese government](https://trustedweb.go.jp/en), but is expected to grow to include other jurisdictions and private sector companies.

# Terminology

This specification uses the terms "Holder", "Issuer", "Verifier", "Wallet", "Wallet Attestation", "Credential Type" and "Verifiable Credential" as defined in [@!OIDF.OID4VCI] and [@!OIDF.OID4VP].

# Scope

This specification enables interoperable implementations of the following flows:

* Issuance of IETF SD-JWT VC using OpenID4VCI
* Presentation of IETF SD-JWT VC using OpenID4VP
* Presentation of IETF SD-JWT VC using OpenID4VP over W3C Digital Credentials API
* Presentation of ISO mdocs using OpenID4VP over W3C Digital Credentials API

Implementations of this specification do not have to implement all of the flows listed above, but they MUST be compliant to all of the requirements for a particular flow they chose to implement.

A parameter that is listed as optional to be implemented in a specification that is being profiled (i.e., OpenID4VCI, OpenID4VP, W3C Digital Credentials API, IETF SD-JWT VC, and ISO mdoc) remains optional unless it is stated otherwise in this specification.

Profile of OpenID4VCI defines Wallet Attestation and Key Attestation.

Profile of IETF SD-JWT VC defines the following aspects:

  * Status management of the Credentials, including revocation
  * Cryptographic Key Binding
  * Issuer key resolution
  * Issuer identification (as prerequisite for trust management)

Mandatory to implement crypto suites are defined for all of the flows.

Note that when OpenID4VP is used, the Wallet and the Verifier can either be remote or in-person.

## Assumptions

Assumptions made are the following:

* The Issuers and Verifiers cannot pre-discover Wallet’s capability
* The Issuer is talking to the Wallet supporting the features defined in this profile (via Wallet invocation mechanism)
* There are mechanisms in place for Verifiers to discover Wallets' and Issuers' capabilities
* There are mechanisms in place for Wallets to discover Verifiers' capabilities  
* There are mechanisms in place for Issuers to discover Wallets' capabilities

## Scenarios/Business Requirements

* Combined Issuance of IETF SD-JWT VC and ISO mdoc
* Both issuer-initiated and wallet-initiated issuance
* Presentation and Issuance of PID and (Q)EAA as defined in Architecture and Reference Framework [@EU.ARF] implementing [@eIDAS2.0].

## Standards Requirements

The standards that are being profiled in this specification are:

* OpenID for Verifiable Credential Issuance [@!OIDF.OID4VCI]
* OpenID for Verifiable Presentations [@!OIDF.OID4VP]
* W3C Digital Credentials API [@w3c.digital_credentials_api]
* SD-JWT-based Verifiable Credentials (SD-JWT VC) [@!I-D.ietf-oauth-sd-jwt-vc]
* ISO/IEC 18013-5:2021 Personal identification — ISO-compliant driving licence Part 5: Mobile driving licence (mDL) application [@!ISO.18013-5]

Note that these standards in turn build upon other underlying standards, and requirements in those underlying standards also need to be followed.

## Out of Scope

The following items are out of scope for the current version of this document, but might be added in future versions:

* Trust Management refers to authorization of an Issuer to issue certain types of credentials, authorization of the Wallet to be issued certain types of credentials, authorization of the Verifier to receive certain types of credentials. Although X.509 PKI is extensively utilized in this profile, the methods for establishing trust or obtaining root certificates are out of the scope of this specification.
* Protocol for presentation of Verifiable Credentials for offline use-cases, e.g. over BLE.
* Profile of OpenID4VCI to issue ISO mdoc [@!ISO.18013-5] is defined in ISO 23220-3.
* Profile of OpenID4VP without using W3C Digital Credentials API to present ISO mdocs is
defined in [@ISO.18013-7]. For more details, also see Annex B.3 in [@!OIDF.OID4VP].

# OpenID for Verifiable Credential Issuance

Both the Wallet and the Credential Issuer:

* MUST support the authorization code flow.
* MUST support at least one of the following Credential Format Profiles defined in (#vc_profiles): SD-JWT VC or ISO mdoc. Ecosystems SHOULD clearly indicate which of these formats, SD-JWT VC, ISO mdoc, or both, are required to be supported.
* MUST support sender-constrained tokens using the mechanism defined in [@!RFC9449].
* MUST support [@!RFC7636] with `S256` as the code challenge method.

Both Wallet initiated and Issuer initiated issuance are supported.

## Issuer Metadata

When ecosystem policies require Issuer Authentication to a higher level than possible with TLS alone, signed Credential Issuer Metadata as specified in Section 11.2.3 in [@!OIDF.OID4VCI]
MUST be supported by both the Wallet and the Issuer. Key resolution to validate the signed Issuer
Metadata MUST be supported using the `x5c` JOSE header parameter as defined in [@!RFC7515].

If the Issuer supports Credential Configurations that require key binding, as indicated by the presence of `cryptographic_binding_methods_supported`, the `nonce_endpoint` MUST be present in the Credential Issuer Metadata.

## Credential Offer

* The Grant Type `authorization_code` MUST be supported as defined in Section 4.1.1 in [@!OIDF.OID4VCI]
* For Grant Type `authorization_code`, the Issuer MUST include a scope value in order to allow the Wallet to identify the desired Credential Type. The Wallet MUST use that value in the `scope` Authorization parameter.
* As a way to invoke the Wallet, at least a custom URL scheme `haip://` MUST be supported. Implementations MAY support other ways to invoke the Wallets as agreed by trust frameworks/ecosystems/jurisdictions, not limited to using other custom URL schemes.

Note: The Authorization Code flow does not require a Credential Offer from the Issuer to the Wallet. However, it is included in the feature set to allow for Issuer initiated Credential issuance.

Both Issuer and Wallet MUST support Credential Offer in both same-device and cross-device flows.

## Authorization Endpoint

* MUST use Pushed Authorization Requests (PAR) [@!RFC9126] to send the Authorization Request.
* Wallets MUST authenticate themselves at the PAR endpoint using the same rules as defined in (#token-endpoint) for client authentication at the token endpoint.
* MUST use the `scope` parameter to communicate Credential Type(s) to be issued. The scope value MUST map to a specific Credential Type. The scope value may be pre-agreed, obtained from the Credential Offer, or the Credential Issuer Metadata.
* The `client_id` value in the PAR request MUST be a string that the Wallet has used as the `sub` value in the client attestation JWT.

## Token Endpoint {#token-endpoint}

* The Wallets MUST perform client authentication as defined in (#wallet-attestation).
* Refresh tokens are RECOMMENDED to be supported for Credential refresh. For details, see Section 13.5 in [@!OIDF.OID4VCI].

Note: Issuers SHOULD be mindful of how long the usage of the refresh token is allowed to refresh a credential, as opposed to starting the issuance flow from the beginning. For example, if the User is trying to refresh a Credential more than a year after its original issuance, the usage of the refresh tokens is NOT RECOMMENDED.

### Wallet Attestation {#wallet-attestation}

Wallets MUST use Wallet Attestations as defined in Annex E of [@!OIDF.OID4VCI].

The public key certificate, and optionally a trust certificate chain, used to validate the signature on the Wallet Attestation MUST be included in the `x5c` JOSE header of the Client Attestation JWT.

Individual Wallet Attestations MUST be used for each Issuer and they MUST not contain unique identifiers that would enable linkability between issuance processes. See section 14.4.4 of [@!OIDF.OID4VCI] for details on the Wallet Attestation subject.

## Credential Endpoint

* The following proof types MUST be supported:
  * `jwt` proof type using `key_attestation`
  * `attestation` proof type

### Key Attestation {#key-attestation}

Wallets MUST support key attestations as defined in Annex D of [@!OIDF.OID4VCI]. If batch issuance is used, all public keys used in Credential Request SHOULD be attested within a single key attestation.

## Issuer Metadata

The Authorization Server MUST support metadata according to [@!RFC8414].

The Credential Issuer MUST support metadata retrieval according to Section 12.2.2 of [@!OIDF.OID4VCI].
The Credential Issuer metadata MUST include a scope for every Credential Configuration it supports.

# OpenID for Verifiable Presentations profile for IETF SD-JWT VC

Requirements for both the Wallet and the Verifier:

* As a way to invoke the Wallet, at least a custom URL scheme `haip://` MUST be supported. Implementations MAY support other ways to invoke the Wallets as agreed by trust frameworks/ecosystems/jurisdictions, not limited to using other custom URL schemes.
* Response type MUST be `vp_token`.
* Response mode MUST be `direct_post.jwt`. The Verifier MUST return `redirect_uri` in response to the HTTP POST request from the Wallet, where the Wallet redirects the User to, as defined in Section 8.2 of [@!OIDF.OID4VP]. Implementation considerations for the response mode `direct_post.jwt` are given in Section 14.3 of [@!OIDF.OID4VP].
* Authorization Request MUST be sent using the `request_uri` parameter as defined in JWT-Secured Authorization Request (JAR) [@!RFC9101].
* The Client Identifier Prefix `x509_hash` MUST be used by the Verifier and accepted by the Wallet (see Section 5.9.3 of [@!OIDF.OID4VP]).
* The Authority Key Identifier (`aki`)-based Trusted Authority Query (`trusted_authorities`) for DCQL, as defined in section 6.1.1.1 of [@!OIDF.OID4VP], MUST be supported.

# OpenID for Verifiable Presentations over W3C Digital Credentials API

The following requirements apply for both, the Wallet and the Verifier, unless specified otherwise:

* MUST support Annex A in [@!OIDF.OID4VP] that defines how to use OpenID4VP over the W3C Digital Credentials API.
  * The Wallet MUST support both signed and unsigned requests as defined in Annex A.3.1 and A.3.2 of [@!OIDF.OID4VP]. The Verifier MAY support signed requests, unsigned requests, or both.
* Wallet Invocation is done via the W3C Digital Credentials API or an equivalent platform API. Any other mechanism, including Custom URL schemes, MUST NOT be used.
* Response Mode MUST be `dc_api.jwt`. The response MUST be encrypted.
* Response encryption MUST be performed as specified in [@!OIDF.OID4VP, section 8.3]. The JWE `alg` (algorithm) header parameter (see [@!RFC7516, section 4.1.1])
  value `ECDH-ES` (as defined in [@!RFC7518, section 4.6]), with key agreement utilizing keys on the `P-256` curve (see [@!RFC7518, section 6.2.1.1]) MUST be supported.
  The JWE `enc` (encryption algorithm) header parameter (see [@!RFC7516, section 4.1.2]) value `A128GCM` (as defined in [@!RFC7518, section 5.3]) MUST be supported.
* The Authority Key Identifier (`aki`)-based Trusted Authority Query (`trusted_authorities`) for DCQL, as defined in section 6.1.1.1 of [@!OIDF.OID4VP], MUST be supported.

Note that the Authority Key Identifiers mechanism can be used to support multiple X.509-based trust mechanisms, such as ISO mDL VICAL (as introduced in [@ISO.18013-5]) or ETSI Trusted Lists [@ETSI.TL]. This is achieved by collecting the relevant X.509 certificates for the trusted Issuers and including the encoded KeyIdentifers from the certificates in the `aki` array .

## ISO mdoc specific requirements for OpenID for Verifiable Presentations over W3C Digital Credentials API

Requirements for both the Wallet and the Verifier:

* ISO mdoc Credential Format specific DCQL parameter, `intent_to_retain` defined in Annex B.3.1 of [@!OIDF.OID4VP] MUST be present.
* When multiple ISO mdocs are being returned, each ISO mdoc MUST be returned in a separate `DeviceResponse` (as defined in 8.3.2.1.2.2 of [@!ISO.18013-5]), each matching to a respective DCQL query. Therefore, the resulting `vp_token` contains multiple `DeviceResponse` instances.

Note that the Credential Format Identifier and `SessionTranscript` CBOR structure are defined in [@!OIDF.OID4VP].


## IETF SD-JWT VC specific requirements for OpenID for Verifiable Presentations over W3C Digital Credentials API

Requirements for both the Wallet and the Verifier:

* The Credential Format identifier MUST be `dc+sd-jwt`.
* IETF SD-JWT VC Credential Format specific DCQL parameters as defined in Section 6.4.1 of [@!OIDF.OID4VP] MUST be used.

# SD-JWT VCs {#sd-jwt-vc}

This profile defines the following additional requirements for IETF SD-JWT VCs as defined in [@!I-D.ietf-oauth-sd-jwt-vc].

* Compact serialization MUST be supported as defined in [@!I-D.ietf-oauth-selective-disclosure-jwt]. JSON serialization MAY be supported.
* The following JWT Claims MUST be supported Content (differentiate issuance & presentation)

| Claim | SD-JWT as issued by the Issuer | Normative Definition |
|:--- |:--- |:--- |
| iss | MUST |[@!RFC7519], Section 4.1.1 |
| iat | MUST |[@!RFC7519], Section 4.1.6 |
| exp | SHOULD (at the discretion of the Issuer) | [@!RFC7519], Section 4.1.4 |
| cnf |	MUST |	[@!RFC7800]|
| vct |	MUST | [@!I-D.ietf-oauth-sd-jwt-vc]|
|status| SHOULD (at the discretion of the Issuer)| [@!I-D.ietf-oauth-status-list]|

* The Issuer MUST NOT make any of the JWT Claims in the table above to be selectively disclosable, so that they are always present in the SD-JWT-VC presented by the Holder.
* It is at the discretion of the Issuer whether to use `exp` claim and/or a `status` claim to express the validity period of an SD-JWT-VC. The Wallet and the verifier  MUST support both mechanisms.
* The `iss` claim MUST be an HTTPS URL.
* The `vct` JWT claim as defined in [@!I-D.ietf-oauth-sd-jwt-vc].
* The `cnf` claim [@!RFC7800] MUST conform to the definition given in [@!I-D.ietf-oauth-sd-jwt-vc]. Implementations conforming to this profile MUST include the JSON Web Key [@!RFC7517] in the `jwk` sub claim.
* The public key used to validate the signature on the Status List Token MUST be included in the `x5c` JOSE header of the Token.

Any of the flows defined in this specification MUST be used with cryptographic holder binding.

Note: Re-using the same Credential across Verifiers, or re-using the same JWK value across multiple Credentials gives colluding Verifiers a mechanism to correlate the User. There are currently two known ways to address this with SD-JWT VCs. First is to issue multiple instances of the same Credentials with different JWK values, so that if each instance of the Credential is used at only one Verifier, it can be reused multiple times. Another is to use each Credential only once (ephemeral Credentials). It is RECOMMENDED to adopt one of these mechanisms.

Note: If there is a requirement to communicate information about the verification status and identity assurance data of the claims about the subject, the syntax defined by [@!OIDF.ekyc-ida] SHOULD be used. It is up to each jurisdiction and ecosystem, whether to require it to the implementers of this profile.

Note: If there is a requirement to provide the Subject’s identifier assigned and maintained by the Issuer, the `sub` claim MAY be used. There is no requirement for a binding to exist between the `sub` and `cnf` claims. See the Implementation Considerations section in [@!I-D.ietf-oauth-sd-jwt-vc].

Note: In some Credential Types, it is not desirable to include an expiration date (eg: diploma attestation). Therefore, this profile leaves its inclusion to the Issuer, or the body defining the respective Credential Type.

## Issuer identification and key resolution to validate an issued Credential {#issuer-key-resolution}

This profile mandates the support for X.509 certificate-based key resolution to validate the issuer signature of an SD-JWT VC. This MUST be supported by all entities (Issuer, Wallet, Verifier). The SD-JWT VC MUST contain the credential issuer's certificate along with a trust chain in the `x5c` JOSE header parameter as described in section 3.5 of [@!I-D.ietf-oauth-sd-jwt-vc].

### Cryptographic Holder Binding between VC and VP

* For Cryptographic Holder Binding, a KB-JWT, as defined in [@!I-D.ietf-oauth-sd-jwt-vc], MUST always be present when presenting an SD-JWT VC.

## OpenID4VC Credential Format Profile {#vc_profiles}

Credential Format Profiles are defined as follows:
- SD-JWT VCs (as specified in [@!I-D.ietf-oauth-sd-jwt-vc]):
  - [@!OIDF.OID4VCI] – Annex A.3
  - [@!OIDF.OID4VP] – Annex B.3
- ISO mdocs:
  - [@!OIDF.OID4VCI] – Annex A.2
  - [@!OIDF.OID4VP] – Annex B.2

# Crypto Suites

Cryptography is required by the following operations:

- to sign and validate the signature on the Wallet Attestation and its proof of possession
- to sign and validate the Issuer's signature on the Verifiable Credential
- to sign and validate the Holder's signature on the Verifiable Presentation
- to sign and validate the Verifier's signature on the Presentation Request

Issuers, Holders, and Verifiers MUST support P-256 (secp256r1) as a key type with the ES256 JWT algorithm [@!RFC7518] for the creation and the verification of the above signatures.

When using this profile alongside other cryptosuites, each entity SHOULD make it explicit in its metadata which other algorithms and key types are supported for the cryptographic operations.

# Hash Algorithms

The hash algorithm SHA-256 MUST be supported by all the entities to generate and validate the digests in the IETF SD-JWT VC and ISO mdoc.

When using this profile alongside other hash algorithms, each entity SHOULD make it explicit in its metadata which other algorithms are supported.

# Implementations Considerations

## Validity Period of the Signature and the Claim Values

`iat` and `exp` JWT claims express both the validity period of both the signature and the claims about the subject, unless there is a separate claim used to express the validity of the claims.

# Security Considerations {#security_considerations}

The security considerations in [@!OIDF.OID4VCI] and [@!OIDF.OID4VP] apply.

{backmatter}

<reference anchor="OIDF.OID4VCI" target="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">
        <front>
          <title>OpenID for Verifiable Credential Issuance</title>
          <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
            <organization>yes.com</organization>
          </author>
          <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
            <organization>Microsoft</organization>
          </author>
          <author initials="T." surname="Looker" fullname="Tobias Looker">
            <organization>Mattr</organization>
          </author>
          <date day="20" month="June" year="2022"/>
        </front>
</reference>

<reference anchor="OIDF.OID4VP" target="https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html">
      <front>
        <title>OpenID for Verifiable Presentations - draft 24</title>
        <author initials="O." surname="Terbu" fullname="Oliver Terbu">
         <organization>Mattr</organization>
        </author>
        <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
          <organization>SPRIND</organization>
        </author>
        <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
          <organization>SPRIND</organization>
        </author>
        <author initials="T." surname="Looker" fullname="Tobias Looker">
          <organization>Mattr</organization>
        </author>
       <date day="27" month="January" year="2025"/>
      </front>
</reference>

<reference anchor="OIDF.ekyc-ida" target="https://openid.net/specs/openid-connect-4-identity-assurance-1_0-ID4.html">
  <front>
    <title>OpenID Connect for Identity Assurance 1.0</title>
    <author ullname="Torsten Lodderstedt ">
      <organization>yes</organization>
    </author>
    <author fullname="Daniel Fett">
      <organization>yes</organization>
    </author>
 <author fullname="Mark Haine">
      <organization>Considrd.Consulting Ltd</organization>
    </author>
     <author fullname="Alberto Pulido">
      <organization>Santander</organization>
    </author>
     <author fullname="Kai Lehmann">
      <organization>1&amp;1 Mail &amp; Media Development &amp; Technology GmbH</organization>
    </author>
     <author fullname="Kosuke Koiwai">
      <organization>KDDI Corporation</organization>
    </author>
   <date day="19" month="August" year="2022"/>
  </front>
</reference>

<reference anchor="ISO.18013-5" target="https://www.iso.org/standard/69084.html">
        <front>
          <title>ISO/IEC 18013-5:2021 Personal identification — ISO-compliant driving license — Part 5: Mobile driving license (mDL)  application</title>
          <author>
            <organization>ISO/IEC JTC 1/SC 17 Cards and security devices for personal identification</organization>
          </author>
          <date year="2021"/>
        </front>
</reference>

<reference anchor="EU.ARF" target="https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/latest/">
        <front>
          <title>European Digital Identity Wallet Architecture and Reference Framework</title>
          <author>
            <organization>European Commission</organization>
          </author>
          <date year="2025"/>
        </front>
</reference>

<reference anchor="eIDAS2.0" target="https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401183">
        <front>
          <title>REGULATION (EU) 2024/1183 OF THE EUROPEAN PARLIAMENT AND OF THE COUNCIL of 11 April 2024 amending Regulation (EU) No 910/2014 as regards establishing the European Digital Identity Framework</title>
          <author>
            <organization>European Union</organization>
          </author>
          <date year="2024"/>
        </front>
</reference>

<reference anchor="ISO.18013-7" target="https://www.iso.org/standard/82772.html">
        <front>
          <title>ISO/IEC DTS 18013-7 Personal identification — ISO-compliant driving license — Part 7: Mobile driving license (mDL) add-on functions</title>
          <author>
            <organization> ISO/IEC JTC 1/SC 17 Cards and security devices for personal identification</organization>
          </author>
          <date year="2024"/>
        </front>
</reference>

<reference anchor="ISO.23220-3" target="https://www.iso.org/standard/79125.html">
        <front>
          <title>ISO/IEC DTS 23220-3 Cards and security devices for personal identification — Building blocks for identity management via mobile devices</title>
          <author>
            <organization> ISO/IEC JTC 1/SC 17 Cards and security devices for personal identification</organization>
          </author>
          <date year="2023"/>
        </front>
</reference>

<reference anchor="w3c.digital_credentials_api" target="https://wicg.github.io/digital-credentials/">
        <front>
          <title>Digital Credentials API</title>
		  <author fullname="Marcos Caceres">
            <organization>Apple Inc.</organization>
          </author>
          <author fullname="Sam Goto">
            <organization>Google</organization>
          </author>
          <author fullname="Tim Cappalli">
            <organization>Okta</organization>
          </author>
        </front>
</reference>

<reference anchor="VC-DATA" target="https://www.w3.org/TR/vc-data-model-2.0/">
        <front>
        <title>Verifiable Credentials Data Model v2.0</title>
        <author fullname="Manu Sporny">
            <organization>Digital Bazaar</organization>
        </author>
        <author fullname="Dave Longley">
            <organization>Digital Bazaar</organization>
        </author>
        <author fullname="David Chadwick">
            <organization>Crossword Cybersecurity PLC</organization>
        </author>
        <date day="4" month="May" year="2023"/>
        </front>
</reference>

<reference anchor="ETSI.TL" target="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.01.01_60/ts_119612v020101p.pdf">
        <front>
          <title>ETSI TS 119 612 V2.3.1 Electronic Signatures and Infrastructures (ESI); Trusted Lists </title>
          <author>
            <organization>European Telecommunications Standards Institute (ETSI)</organization>
          </author>
          <date month="Nov" year="2024"/>
        </front>
</reference>

# Acknowledgements {#Acknowledgements}

We would like to thank Paul Bastian, Christian Bormann, Mike Jones, Oliver Terbu, Daniel Fett, and Giuseppe De Marco for their valuable feedback and contributions to this specification.

# Notices

Copyright (c) 2025 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft, Final Specification, or Final Specification Incorporating Errata Corrections solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts, Final Specifications, and Final Specification Incorporating Errata Corrections based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy (found at openid.net) requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. OpenID invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.

# Document History

   [[ To be removed from the final specification ]]

   -04

   * mandate support for aki trusted_authorities method
   * remove presentation exchange reference since it was removed in openid4vp
   * Authorization Server and Credential Issuer must support metadata
   * x509_san_dns & verifier_attestations client id prefixes are no longer permitted, x509_hash must be used
   * x.509 certificates are now the mandatory mechanism for SD-JWT VC issuer key resolution
   * `x5c` header in Status List Token must be present
   * clarify that Wallet Attestations must not contain linkable information.
   * Add signed Issuer Metadata
   * add key attestation to OpenID4VCI
   * clarify text regarding mdoc specific parameters
   * Add small note that establishing trust in and retrieving root certs is out scope
   * Update wording from Client Identifier Scheme to Client Identifier Prefix #182
   * fix reference to ARF #177
   * Old link in section 8 & clarify a note on claim based binding in OpenID4VP in HAIP #183
   * Clarify clause 4.1 statement #169
   * add a list of all specifications being profiled #145

   -03

   * Add initial security considerations section
   * Update notices section to match latest OIDF process document

   -02

   * Mandate DCQL instead of presentation exchange
   * Refactor HAIP and add details for mdoc profile over DC API
   * Add specific requirements for response encryption
   * Add SessionTranscript requirements
   * Update OID4VP reference to draft 24

   -01

   * Remove the Wallet Attestation Schema and point to OpenID4VCI instead
   * Rename specification to enable non-SD-JWT credential formats to be included
   * Require encrypted responses
   * Remove reference to `client_id_scheme` parameter that no longer exists in OpenID4VP
   * Refresh tokens are now optional

   -00

   *  initial revision
