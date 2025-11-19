%%%
title = "OpenID4VC High Assurance Interoperability Profile 1.0 - Editor's draft"
abbrev = "openid4vc-high-assurance-interoperability-profile"
ipr = "none"
workgroup = "Digital Credentials Protocols"
keyword = ["security", "openid4vc", "sd-jwt", "sd-jwt-vc", "mdoc"]

[seriesInfo]
name = "Internet-Draft"
value = "openid4vc-high-assurance-interoperability-profile-1_0-06"
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

[[author]]
initials="C."
surname="Bormann"
fullname="Christian Bormann"
organization="SPRIND"
    [author.address]
    email = "chris.bormann@gmx.de"

[[author]]
initials="J."
surname="Heenan"
fullname="Joseph Heenan"
organization="Authlete"
    [author.address]
    email = "joseph@heenan.me.uk"

%%%

.# Abstract

This specification defines a profile of OpenID for Verifiable Credentials in combination with the credential formats IETF SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc [@!ISO.18013-5]. The aim is to select features and to define a set of requirements for the existing specifications to enable interoperability among Issuers, Wallets, and Verifiers of Credentials where a high level of security and privacy is required. The profiled specifications include OpenID for Verifiable Credential Issuance [@!OIDF.OID4VCI], OpenID for Verifiable Presentations [@!OIDF.OID4VP], IETF SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc], and ISO mdoc [@!ISO.18013-5].

{mainmatter}

# Introduction

This specification defines a set of requirements for the existing specifications to enable interoperability among Issuers, Wallets, and Verifiers of Credentials where a high level of security and privacy is required. This specification is an interoperability profile that can be used by implementations in various contexts, be it a certain industry or a certain regulatory environment. Note that while this specification is aimed at high assurance use-cases, it can also be used for lower assurance use-cases.

This specification aims to achieve a level of security and privacy that includes the following properties:

* Authenticity of claims: There is strong assurance that the claims within a Credential or Presentation are valid and bound to the correct Holder. This involves the policies and procedures used to collect and maintain the claims, the authentication of the Holder during issuance, and the protection of claim authenticity both at rest (in the wallet) and during presentation. The scope for this specification is: security of the issuance process, protection of issued credentials, and mechanisms for the Verifiers to access trustworthy information about the Issuer.
* Holder authentication: There is strong assurance that the Credential is presented by its legitimate Holder in a given transaction. This involves proof of Holder binding, which can be validated through several methods. The scope for this specification includes secure presentation of key-bound credentials and supporting Claim-based Binding when built on top of this functionality.

Note: This specification defines the technical means by which holder authentication can be proven and claim authenticity can be protected using certain protocol and credential format features. Out of scope are concrete holder authentication mechanisms (which ensure only the holder can sign the presentation) and policies and procedures (as this is a technical interoperability profile and not a policy definition).

Note: This specification fulfils some, but not all, of the requirements to meet the "High" Level of Assurance (LoA) as defined in the eIDAS Regulation [@eIDAS2.0]. While this specification defines features intended for scenarios targeting a high level of security, these features must be combined with additional measures outside of the scope of HAIP to achieve LoA High compliance.

This specification contains profiles of other specifications. It refers to the specifications required for implementations to interoperate among each other and for the optionalities mentioned in the referenced specifications, defines the set of features to be mandatory to implement.

The specification uses OpenID for Verifiable Credential Issuance [@!OIDF.OID4VCI] and OpenID for Verifiable Presentations [@!OIDF.OID4VP] as the base protocols for issuance and presentation of Credentials, respectively. The credential formats used are IETF SD-JWT VC as specified in [@!I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc [@!ISO.18013-5]. Credentials in both IETF SD-JWT VC [@!I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc [@ISO.18013-5] formats can be issued following a single interaction with the Authorization Server.

A full list of the open standards used in this specification can be found in (#standards-requirements).

## Target Audience/Usage

The target audience of this specification is implementers who require a high level of security and privacy for their solutions. A non-exhaustive list of the interested parties includes anyone implementing [eIDAS 2.0](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401183), [California Department of Motor Vehicles](https://www.dmv.ca.gov/portal/), [Open Wallet Foundation (OWF)](https://openwallet.foundation/), [IDunion](https://idunion.org/?lang=en), [GAIN](https://gainforum.org/), and [the Trusted Web project of the Japanese government](https://trustedweb.go.jp/en), but is expected to grow to include other jurisdictions and private sector companies.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

# Terminology

This specification uses the terms "Holder", "Issuer", "Verifier", "Wallet", "Wallet Attestation", "Credential Type" and "Verifiable Credential" as defined in [@!OIDF.OID4VCI] and [@!OIDF.OID4VP].

This specification also defines the following term. In the case where a term has a definition that differs, the definition below is authoritative.

Ecosystem:
: A group of Issuers, Wallets and Verifiers that have a common set of rules by which they operate. The rules may be determined, for example, by a regulation, law or domain/sector.

# Scope {#scope}

This specification enables interoperable implementations of the following flows:

* Issuance of Credentials using OpenID for Verifiable Credential Issuance
* Presentation of Credentials using OpenID for Verifiable Presentations with redirects
* Presentation of Credentials using OpenID for Verifiable Presentations with the W3C Digital Credentials API

Implementations of this specification do not have to implement all the flows listed above, but they MUST be compliant to all the requirements for a flow they choose to implement, as well as the requirements in the non-flow specific sections.

For each flow, at least one of the Credential profiles defined in (#vc-profiles) MUST be supported:

* IETF SD-JWT VC
* ISO mdocs

A parameter listed as optional to be implemented in a specification that is being profiled (e.g., OpenID4VCI, OpenID4VP, W3C Digital Credentials API, IETF SD-JWT VC, and ISO mdoc) remains optional unless stated otherwise in this specification.

The Profile of OpenID4VCI defines Wallet Attestation and Key Attestation.

The Profile of IETF SD-JWT VC defines the following aspects:

  * Status management of the Credentials, including revocation
  * Cryptographic Key Binding
  * Issuer key resolution
  * Issuer identification (as prerequisite for trust management)

Note that when OpenID4VP is used, the Wallet and the Verifier can either be remote or in-person.

## Assumptions

Assumptions made are the following:

* The Issuer uses the Wallet features defined in this specification (via Wallet invocation mechanism)
* There are mechanisms in place for Verifiers to discover Wallets' and Issuers' capabilities
* There are mechanisms in place for Wallets to discover Verifiers' capabilities
* There are mechanisms in place for Issuers to discover Wallets' capabilities

## Additional scenarios

Below is a non-exhaustive list of scenarios that can be realized with this specification:

* Combined Issuance of IETF SD-JWT VC and ISO mdoc
* Both issuer-initiated and wallet-initiated issuance
* Issuance and presentation of Credentials with and without cryptographic holder binding

## Standards Requirements {#standards-requirements}

The standards that are being profiled in this specification are:

* OpenID for Verifiable Credential Issuance [@!OIDF.OID4VCI]
* OpenID for Verifiable Presentations [@!OIDF.OID4VP]
* W3C Digital Credentials API [@w3c.digital_credentials_api]
* SD-JWT-based Verifiable Credentials (SD-JWT VC) [@!I-D.ietf-oauth-sd-jwt-vc]
* ISO/IEC 18013-5:2021 Personal identification — ISO-compliant driving licence Part 5: Mobile driving licence (mDL) application [@!ISO.18013-5]

Note that these standards in turn build upon other underlying standards, and requirements in those underlying standards also need to be followed.

## Out of Scope

The following items are out of scope for the current version of this specification, but might be added in future versions:

* Trust Management refers to authorization of an Issuer to issue certain types of credentials, authorization of the Wallet to be issued certain types of credentials, authorization of the Verifier to receive certain types of credentials. Although X.509 PKI is extensively utilized in this specification, the methods for establishing trust or obtaining root certificates are out of the scope of this specification.
* Protocol for presentation of Verifiable Credentials for offline use-cases, e.g. over BLE.

# OpenID for Verifiable Credential Issuance

When implementing OpenID for Verifiable Credential Issuance, both the Wallet and the Credential Issuer:

* MUST support the authorization code flow.
* MUST support at least one of the following Credential Format Profiles defined in (#vc-profiles): IETF SD-JWT VC or ISO mdoc. Ecosystems SHOULD clearly indicate which of these formats, IETF SD-JWT VC, ISO mdoc, or both, are required to be supported.
* MUST comply with the provisions of [@!FAPI2_Security_Profile] that are applicable to this specification. This includes, but is not limited to using PKCE [@!RFC7636] with `S256` as the code challenge method, Pushed Authorization Requests (PAR) [@!RFC9126] (where applicable) and the `iss` value in the Authorization response [@!RFC9207].

The following aspects of [@!FAPI2_Security_Profile] are further profiled:

  * Sender-constrained access token: MUST support DPoP as defined in [@!RFC9449]. Note that this requires Wallets to be prepared to handle the `DPoP-Nonce` HTTP response header from the Credential Issuer’s Nonce Endpoint, as well as from other applicable endpoints of the Credential Issuer and Authorization Server.

The following aspects of [@!FAPI2_Security_Profile] do not apply to this specification:

  * Client authentication: Wallet Attestation as defined in (#wallet-attestation) can be used.
  * Pushed Authorization Requests (PAR): Only required when using the Authorization Endpoint as defined in Section 5 of [@!OIDF.OID4VCI].
  * Cryptography and secrets: (#crypto-suites) overrides the requirements in Section 5.4.1 clause 1.

Note that some optional parts of [@!FAPI2_Security_Profile] are not applicable when using only OpenID for Verifiable Credential Issuance, e.g., MTLS or OpenID Connect.

Ecosystems SHOULD clearly indicate whether the Wallets and the Issuers need to support Issuer-initiated, Wallet-initiated Issuance or both, including how to send Credential Offer. If Issuer-initiated flows are supported, they MUST use the Credential Offer as defined in Section 4.1 of [@!OIDF.OID4VCI].

Note that ecosystems that aim for a stronger separation between the different Issuers and Wallets are expected to prefer the Issuer-initiated issuance flows and those with stronger integration into wallets (more wallet-centric ecosystems) will likely prefer the Wallet-initiated Issuance.

If batch issuance is supported, the Wallet SHOULD use it rather than making consecutive requests for a single Credential of the same Credential Dataset. The Issuer MUST indicate whether batch issuance is supported by including or omitting the `batch_credential_issuance` metadata parameter. The Issuer’s decision may be influenced by various factors, including, but not limited to, trust framework requirements, regulatory constraints, applicable laws or internal policies.

Additional requirements for OpenID4VCI are defined in (#crypto-suites) and (#hash-algorithms).

## Issuer Metadata {#issuer-metadata}

The Authorization Server MUST support metadata according to [@!RFC8414].

The Credential Issuer MUST support metadata retrieval according to Section 12.2.2 of [@!OIDF.OID4VCI].
The Credential Issuer metadata MUST include a scope for every Credential Configuration it supports.

When ecosystem policies require Issuer Authentication to a higher level than possible with TLS alone, signed Credential Issuer Metadata as specified in Section 11.2.3 in [@!OIDF.OID4VCI]
MUST be supported by both the Wallet and the Issuer. Key resolution to validate the signed Issuer
Metadata MUST be supported using the `x5c` JOSE header parameter as defined in [@!RFC7515]. In this case, the X.509 certificate of the trust anchor MUST NOT be included in the `x5c` JOSE header of the signed request. The X.509 certificate signing the request MUST NOT be self-signed.

Wallets that render images provided by the Credential Issuer in its metadata defined in Section 12.2.4 of [@!OIDF.OID4VCI] (e.g., the logo of a specific credential) have certain requirements. Such wallets MUST support both the SVG and PNG formats. They also MUST support images conveyed through both data URIs and HTTPS URLs.

If the Issuer supports Credential Configurations that require key binding, as indicated by the presence of `cryptographic_binding_methods_supported`, the `nonce_endpoint` MUST be present in the Credential Issuer Metadata.

## Credential Offer {#credential-offer}

* The Grant Type `authorization_code` MUST be supported as defined in Section 4.1.1 in [@!OIDF.OID4VCI]
* For Grant Type `authorization_code`, the Issuer MUST include a scope value in order to allow the Wallet to identify the desired Credential Type. The Wallet MUST use that value in the `scope` Authorization parameter.
* As a way to invoke the Wallet the custom URL scheme `haip-vci://` MAY be supported. Implementations MAY support other ways to invoke Wallets as agreed upon by trust frameworks/ecosystems/jurisdictions, including but not limited to using other custom URL schemes or claimed "https" scheme URIs.

Note: The Authorization Code flow does not require a Credential Offer from the Issuer to the Wallet. However, it is included in the feature set to allow for Issuer initiated Credential issuance.

Both Issuer and Wallet MUST support Credential Offer in both same-device and cross-device flows.

## Authorization Endpoint

* Wallets MUST authenticate themselves at the PAR endpoint using the same rules as defined in (#token-endpoint) for client authentication at the token endpoint.
* MUST use the `scope` parameter to communicate Credential Type(s) to be issued. The scope value MUST map to a specific Credential Type. The scope value may be pre-agreed, obtained from the Credential Offer, or the Credential Issuer Metadata.

## Token Endpoint {#token-endpoint}

* Refresh tokens are RECOMMENDED to be supported for Credential refresh. For details, see Section 13.5 in [@!OIDF.OID4VCI].

Note: Issuers SHOULD consider how long a refresh token is allowed to be used to refresh a credential, as opposed to starting the issuance flow from the beginning. For example, if the User is trying to refresh a Credential more than a year after its original issuance, the usage of the refresh tokens is NOT RECOMMENDED.

### Wallet Attestation {#wallet-attestation}

Wallets MUST use, and Issuers MUST require, an OAuth2 Client authentication mechanism at OAuth2 Endpoints that support client authentication (such as the PAR and Token Endpoints).

Ecosystems that desire wallet-issuer interoperability on the level of Wallet Attestations SHOULD require Wallets to support the authentication mechanism and Wallet Attestation format specified in Annex E of [@!OIDF.OID4VCI]. When doing so, they might need to define additional ecosystem-specific claims contained in the attestation. Alternatively, ecosystems MAY choose to rely on other Wallet Attestation formats.

 Additional rules apply when using the format defined in Annex E of [@!OIDF.OID4VCI]:

* the public key certificate, and optionally a trust certificate chain excluding the trust anchor, used to validate the signature on the Wallet Attestation MUST be included in the `x5c` JOSE header of the Client Attestation JWT
* Wallet Attestations MUST NOT be reused across different Issuers. They MUST NOT introduce a unique identifier specific to a single Wallet instance. The subject claim for the Wallet Attestation MUST be a value that is shared by all Wallet instances using the present type of wallet implementation. See section 15.4.4 of [@!OIDF.OID4VCI] for details on the Wallet Attestation subject.
* if applicable, the `client_id` value in the PAR request MUST be the string in the `sub` value in the client attestation JWT.
* Wallets MUST perform client authentication with the Wallet Attestation at OAuth2 Endpoints that support client authentication.

## Credential Endpoint

### Key Attestation {#key-attestation}

Wallets MUST support key attestations. Ecosystems that desire wallet-issuer interoperability on the level of key attestations SHOULD require Wallets to support the format specified in Annex D of [@!OIDF.OID4VCI], in combination with the following proof types:

* `jwt` proof type using `key_attestation`
* `attestation` proof type

When using the format specified in Appendix D of [@!OIDF.OID4VCI]:

* The public key used to validate the signature on the key attestation MUST be included in the `x5c` JOSE header of the key attestation
* The X.509 certificate of the trust anchor MUST NOT be included in the `x5c` JOSE header of the key attestation.
* The X.509 certificate signing the key attestation MUST NOT be self-signed.
* The X.509 certificate profiles to be used are out of scope of this specification.

Alternatively, ecosystems MAY choose to rely on other key attestation formats, meaning they would need to use a proof type other than `attestation`, define a new proof type, or expand the `jwt` proof type to support other key attestation formats.

If batch issuance is used and the Credential Issuer has indicated (via `cryptographic_binding_methods_supported` metadata parameter) that cryptographic holder binding is required, all public keys used in Credential Request SHOULD be attested within a single key attestation.

# OpenID for Verifiable Presentations {#openid-for-verifiable-presentations}

The following requirements apply to OpenID for Verifiable Presentations, irrespective of the flow and Credential Format:

* The Wallet and Verifier MUST support at least one of the following Credential Format Profiles defined in (#vc-profiles): IETF SD-JWT VC or ISO mdoc. Ecosystems SHOULD clearly indicate which of these formats, IETF SD-JWT VC, ISO mdoc, or both, are required to be supported.
* The Response type MUST be `vp_token`.
* For signed requests, the Verifier MUST use, and the Wallet MUST accept the Client Identifier Prefix `x509_hash` as defined in Section 5.9.3 of [@!OIDF.OID4VP]. The X.509 certificate of the trust anchor MUST NOT be included in the `x5c` JOSE header of the signed request. The X.509 certificate signing the request MUST NOT be self-signed. X.509 certificate profiles to be used with `x509_hash` are out of scope of this specification.
* The DCQL query and response MUST be used as defined in Section 6 of [@!OIDF.OID4VP].
* Response encryption MUST be performed as specified in [@!OIDF.OID4VP, section 8.3]. The JWE `alg` (algorithm) header parameter (see [@!RFC7516, section 4.1.1])
  value `ECDH-ES` (as defined in [@!RFC7518, section 4.6]), with key agreement utilizing keys on the `P-256` curve (see [@!RFC7518, section 6.2.1.1]) MUST be supported.
  The JWE `enc` (encryption algorithm) header parameter (see [@!RFC7516, section 4.1.2]) value `A128GCM` (as defined in [@!RFC7518, section 5.3]) MUST be supported.
* Verifiers MUST supply ephemeral encryption public keys specific to each Authorization Request passed via client metadata as specified in Section 8.3 of [@!OIDF.OID4VP].
* The Authority Key Identifier (`aki`)-based Trusted Authority Query (`trusted_authorities`) for DCQL, as defined in section 6.1.1.1 of [@!OIDF.OID4VP], MUST be supported. Note that the Authority Key Identifiers mechanism can be used to support multiple X.509-based trust mechanisms, such as ISO mDL VICAL (as introduced in [@ISO.18013-5]) or ETSI Trusted Lists [@ETSI.TL]. This is achieved by collecting the relevant X.509 certificates for the trusted Issuers and including the encoded Key Identifiers from the certificates in the `aki` array .

Additional requirements for OpenID4VP are defined in (#oid4vp-redirects), (#oid4vp-dc-api), (#oid4vp-credential-formats), (#crypto-suites) and (#hash-algorithms).

Note that while this specification does not define profiles for X.509 certificates used in Verifier authentication (e.g., with the `x509_hash` Client Identifier Prefix), ecosystems are encouraged to select suitable certificate issuing policies and certificate profiles (for example, an mDL ecosystem can use the Reader Authentication Certificate profile defined in Annex B of ISO/IEC 18013-5 with `x509_hash`), or define new ones if there is a good reason to do so. Such policies and profiles MAY specify how information in the certificate corresponds to information in the presentation flows. For example, an ecosystem might require that the Wallet verifies that the `redirect_uri`, `response_uri`, `origin`, or `expected_origin` request parameters match with information contained in the Verifier's end-entity certificate (e.g., its DNS name).

## OpenID for Verifiable Presentations via Redirects {#oid4vp-redirects}

The following requirements apply to OpenID for Verifiable Presentations via redirects:

* As a way to invoke the Wallet, the custom URL scheme `haip-vp://` MAY be supported by the Wallet and the Verifier. Implementations MAY support other ways to invoke the Wallets as agreed upon by trust frameworks/ecosystems/jurisdictions, including but not limited to using other custom URL schemes or claimed "https" scheme URIs.
* Signed Authorization Requests MUST be used by utilizing JWT-Secured Authorization Request (JAR) [@!RFC9101] with the `request_uri` parameter.
* Response encryption MUST be used by utilizing response mode `direct_post.jwt`, as defined in Section 8.3 of [@!OIDF.OID4VP]. Security considerations in Section 14.3 of [@!OIDF.OID4VP] MUST be applied.
* Verifiers and Wallets MUST support the "same-device" flow. Verifiers are RECOMMENDED to use only the "same-device" flow unless the Verifier does not rely on session binding for phishing resistance, e.g. in a proximity scenario. If "same-device" flow is used, then:
  * Verifiers MUST include `redirect_uri` in the HTTP response to the Wallet's HTTP POST to the `response_uri`, as defined in Section 8.2 of [@!OIDF.OID4VP].
  * Wallets MUST follow the redirect to `redirect_uri`.
  * Verifiers MUST reject presentations if Wallets do not follow the redirect back or the redirect back arrives in a different user session to the one the request was initiated in.
  * Implementation considerations can be found in Section 13.3 of [@!OIDF.OID4VP] and security considerations in Section 14.2 of [@!OIDF.OID4VP].

## OpenID for Verifiable Presentations via W3C Digital Credentials API {#oid4vp-dc-api}

The following requirements apply to OpenID for Verifiable Presentations via the W3C Digital Credentials API:

* The Wallet MUST support Wallet Invocation via the W3C Digital Credentials API or an equivalent platform API. The Verifier MUST use Wallet Invocation via the W3C Digital Credentials API or an equivalent platform API.
* The Wallet MUST support the Response Mode `dc_api.jwt`. The Verifier MUST use the Response Mode `dc_api.jwt`.
* The Verifier and Wallet MUST use Annex A in [@!OIDF.OID4VP] that defines how to use OpenID4VP over the W3C Digital Credentials API.
* The Wallet MUST support both signed and unsigned requests as defined in Annex A.3.1 and A.3.2 of [@!OIDF.OID4VP]. The Verifier MAY support signed requests, unsigned requests, or both.

Note that unsigned requests depend on the origin information provided by the platform and the web PKI for request integrity protection and to authenticate the Verifier. Signed requests introduce a separate layer for request integrity protection and Verifier authentication that can be validated by the Wallet.

## Requirements specific to Credential Formats {#oid4vp-credential-formats}

### ISO Mobile Documents or mdocs (ISO/IEC 18013 and ISO/IEC 23220 series)

The following requirements apply to all OpenID4VP flows when the mdoc Credential Format is used (as defined in Annex B.2. of [@!OIDF.OID4VP]):

* The Credential Format identifier MUST be `mso_mdoc`.
* When multiple ISO mdocs are being returned, each ISO mdoc MUST be returned in a separate `DeviceResponse` (as defined in 8.3.2.1.2.2 of [@!ISO.18013-5]), each matching to a respective DCQL query. Therefore, the resulting `vp_token` contains multiple `DeviceResponse` instances.
* The Credential Issuer MAY include the MSO revocation mechanism in the issued mdoc. When doing so, it MUST use one of the mechanisms defined in ISO/IEC 18013-5 ([@!ISO.18013-5.second.edition]).

### IETF SD-JWT VC

The following requirements apply to all OpenID4VP flows when the SD-JWT VC Credential Format is used:

* The Credential Format identifier MUST be `dc+sd-jwt`.

# OpenID4VC Credential Format Profiles {#vc-profiles}

Credential Format Profiles are defined as follows:

- IETF SD-JWT VCs (as specified in [@!I-D.ietf-oauth-sd-jwt-vc]), subject to the additional requirements defined in (#sd-jwt-vc):
  - [@!OIDF.OID4VCI] – Annex A.3
  - [@!OIDF.OID4VP] – Annex B.3
- ISO mdocs:
  - [@!OIDF.OID4VCI] – Annex A.2
  - [@!OIDF.OID4VP] – Annex B.2

## IETF SD-JWT VC Profile {#sd-jwt-vc}

This specification defines the following additional requirements for IETF SD-JWT VCs as defined in [@!I-D.ietf-oauth-sd-jwt-vc].

* Compact serialization MUST be supported as defined in [@!I-D.ietf-oauth-selective-disclosure-jwt]. JSON serialization MAY be supported.
* It is RECOMMENDED that Issuers limit the validity period when issuing SD-JWT VC. When doing so, the Issuer MUST use an `exp` claim, a `status` claim, or both.
* The `cnf` claim [@!RFC7800] MUST conform to the definition given in [@!I-D.ietf-oauth-sd-jwt-vc]. Implementations conforming to this specification MUST include the JSON Web Key [@!RFC7517] in the `jwk` member if the corresponding Credential Configuration requires cryptographic holder binding.
* The `status` claim, if present, MUST contain `status_list` as defined in [@!I-D.ietf-oauth-status-list]
* The public key used to validate the signature on the Status List Token defined in [I-D.ietf-oauth-status-list] MUST be included in the `x5c` JOSE header of the Token. The X.509 certificate of the trust anchor MUST NOT be included in the `x5c` JOSE header of the Status List Token. The X.509 certificate signing the request MUST NOT be self-signed.

Each Credential MUST have its own unique, unpredictable status list index, even when multiple Credentials reference the same status list URI (see section 13.2 of [@!I-D.ietf-oauth-status-list]). Refer to section 12.5 of [@!I-D.ietf-oauth-status-list] for additional privacy considerations on unlinkability.

Note: For guidance on preventing linkability by colluding parties, such as Issuer/Verifier pairs, multiple Verifiers, or repeated interactions with the same Verifier, see Section 15.4.1 of [@!OIDF.OID4VCI] and Section 15.5 of [@!OIDF.OID4VP].

Note: If there is a requirement to communicate information about the verification status and identity assurance data of the claims about the subject, the syntax defined by [@!OIDF.ekyc-ida] SHOULD be used. It is up to each jurisdiction and ecosystem, whether to require it to the implementers of this specification.

Note: If there is a requirement to provide the Subject’s identifier assigned and maintained by the Issuer, the `sub` claim MAY be used. There is no requirement for a binding to exist between the `sub` and `cnf` claims. See the Implementation Considerations section in [@!I-D.ietf-oauth-sd-jwt-vc].

Note: In some Credential Types, it is not desirable to include an expiration date (e.g., diploma attestation). Therefore, this specification leaves its inclusion to the Issuer, or the body defining the respective Credential Type.

### Issuer identification and key resolution to validate an issued Credential {#issuer-key-resolution}

This specification mandates the support for X.509 certificate-based key resolution to validate the issuer signature of an SD-JWT VC. This MUST be supported by all entities (Issuer, Wallet, Verifier). The SD-JWT VC MUST contain the credential issuer's signing certificate along with a trust chain in the `x5c` JOSE header parameter as described in section 3.5 of [@!I-D.ietf-oauth-sd-jwt-vc]. The X.509 certificate of the trust anchor MUST NOT be included in the `x5c` JOSE header of the SD-JWT VC. The X.509 certificate signing the request MUST NOT be self-signed.

#### Cryptographic Holder Binding between VC and VP

* If the credential has cryptographic holder binding, a KB-JWT, as defined in [@!I-D.ietf-oauth-sd-jwt-vc], MUST always be present when presenting an SD-JWT VC.

# Requirements for Digital Signatures {#crypto-suites}


Issuers, Verifiers, and Wallets MUST, at a minimum, support ECDSA with P-256 and SHA-256 (JOSE algorithm identifier `ES256`; COSE algorithm identifier `-7` or `-9`, as applicable) for the purpose of validating the following:

- Issuers
  - Wallet Attestations (including PoP) when Annex E of [@!OIDF.OID4VCI] is used;
  - Key Attestations when Annex D of [@!OIDF.OID4VCI] is used.
  - `jwt` proof type as specified in Appendix E of [@!OIDF.OID4VCI]
- Verifiers
  - the signature of the Verifiable Presentation, e.g., KB-JWT of an SD-JWT VC, or `deviceSignature` CBOR structure in case of ISO mdocs. Verifiers are assumed to determine in advance the cryptographic suites supported by the ecosystem, e.g. mDL Issuers/Verifiers implementing ISO mdocs.
  - the status information of the Verifiable Credential or Wallet Attestation.
- Wallets
  - signed presentation requests.
  - signed Issuer metadata.

Ecosystem-specific profiles of this specification MAY mandate additional cryptographic suites.

When using this specification alongside other crypto suites, each entity SHOULD make it explicit in its metadata which other algorithms and key types are supported for the cryptographic operations.

# Hash Algorithms {#hash-algorithms}

The hash algorithm SHA-256 MUST be supported by all the entities to generate and validate the digests in the IETF SD-JWT VC and ISO mdoc.

Ecosystem-specific profiles of this specification MAY mandate additional hashing algorithms.

When using this specification alongside other hash algorithms, each entity SHOULD make it explicit in its metadata which other algorithms are supported.

# Implementation Considerations

## Requirements for browser/OS support of specific features

This specification relies on certain prerequisites, such as browser or operating system support for specific features. When these prerequisites are mandatory for a flow (e.g., the W3C Digital Credentials API or an equivalent platform API), an implementer might be unable to support that flow due to factors beyond their control. In other cases (e.g., custom URL schemes), the prerequisites are optional, allowing implementers to achieve the same flow through alternative mechanisms.

## Interoperable Key Attestations

Wallet implementations using the key attestation format specified in Annex D of [@!OIDF.OID4VCI] might need to utilize a transformation (backend) service to create such attestations based on data as provided in other formats by the respective platform or secure key management module. The dependency on such a service might impact the availability of the wallet app as well as the performance of the issuance process. This could be mitigated by creating keys and obtaining the respective key attestations in advance.

## Ecosystem Implementation Considerations

This specification intentionally leaves certain extensions for ecosystems to define, in order to enable broad compatibility across differing or even conflicting requirements. Below are the extension points listed in this specification:

- Which flow(s) to adopt: presentation, issuance, or both (see (#scope))
- For presentation, whether to use the W3C Digital Credentials API, Redirects with custom URL schemes, and/or Redirects with claimed `https` scheme URIs (see (#scope))
- Which Credential Format to support across issuance and presentation (see (#scope))
- Whether to use Signed Issuer Metadata or not (see (#issuer-metadata))
- How to make a Credential Offer available to the Wallet (see (#credential-offer))
- Which Key Attestation format to use (see (#key-attestation))
- Which Wallet Attestation format to use (see (#wallet-attestation))
- Which X.509 certificate profile to use (see (#openid-for-verifiable-presentations), (#wallet-attestation) and (#key-attestation))
- Support or restriction of additional cryptographic suites and hash algorithms (see (#crypto-suites))

### Non-normative Examples of Ecosystem-specific Extensions of this Specification

Below are two non-normative examples illustrating how an ecosystem may define the above elements to achieve its specific goals and preferences.

#### Example 1: Baseline Interoperability without pre-existing relationships

An Ecosystem that prioritizes interoperability among all Wallets, Issuers and Verifiers, without requiring any pre-existing relationships, could define the following ecosystem-specific extensions of this specification:

- Use this specification for both presentation and issuance with the following requirements:
  - No additional cryptographic suites and hash algorithms are defined.
  - For each Credential, Wallets support both mdoc and sd-jwt-vc Credential Formats, Issuers have a choice to issue in either format, and Verifiers accept the Credential Format that the Issuer of a requested Credential supports.
- For issuance, the following requirements apply:
  - Issuers use and Wallets support unsigned Issuer Metadata.
  - Wallets register for the `haip-vci://` custom scheme, where possible. This custom scheme is also used to communicate Credential Offer.
  - Wallets and Issuers both support Key Attestations in the format specified in Annex D of [@!OIDF.OID4VCI]. Both `jwt` proof type using `key_attestation` and `attestation` proof type are supported.
  - Wallets and Issuers both support Wallet Attestations in the format specified in Annex E of [@!OIDF.OID4VCI] and (#wallet-attestation) of this specification.
- for presentation, the following requirements apply:
  - Wallets use DC API where possible and when they have credentials available. As a fallback mechanism when DC API is not available, Wallets register for the `haip-vp://` custom scheme, where possible.
  - No additional X.509 certificate profile is defined.

Making these choices maximizes interoperability between the parties in the ecosystem while minimizing the burden on Issuers and Verifiers. This comes at the expense of an increased burden on Wallets as well as the potential privacy and security issues in (#interop-key-attestations).

#### Example 2: Achieving Compatibility with Existing Deployments of ISO/IEC 18013-5

An Ecosystem that prioritizes achieving compatibility with existing deployments could define the following ecosystem-specific extensions of this specification:

- Use this specification only for presentation with the following requirements:
  - Wallets and Verifiers support only the mdoc Credential Format.
  - Wallets register and use the `haip-vp://` custom scheme, where possible.
  - As X.509 certificate profile, Wallets and Verifiers use the Reader Authentication Certificate profile defined in Annex B of [@!ISO.18013-5].
  - Verifiers support all curves from Cipher Suite 1 listed in table 22 of [@!ISO.18013-5].
  - Verifiers support all hash algorithms listed in table 21 of [@!ISO.18013-5].

Making these choices ensures interoperability at the increased cost on the Verifier.

# Security Considerations {#security_considerations}

Note that security considerations for OpenID for Verifiable Credential Issuance are defined in Section 13 of [@!OIDF.OID4VCI] and for OpenID for Verifiable Presentations in Section 14 (for redirect based flows) or Section A.5 (for DC API) of [@!OIDF.OID4VP].

## Incomplete or Incorrect Implementations of the Specifications and Conformance Testing

To achieve the full security benefits, it is important that the implementation of this specification, and the underlying specifications, are both complete and correct.

The OpenID Foundation provides tools that can be used to confirm that an implementation is correct and conformant:

https://openid.net/certification/conformance-testing-for-openid-for-verifiable-credential-issuance/

https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/

## Key sizes

Implementers need to ensure appropriate key sizes are used. Guidance can be found in, for example, [@NIST.SP.800-131A], [@NIST.SP.800-57], [@BSI.TR-02102-1], or [@ECCG.ACM2].

# Privacy Considerations

Note that privacy considerations for OpenID for Verifiable Credential Issuance are defined in Section 15 of [@!OIDF.OID4VCI] and for OpenID for Verifiable Presentations in Section 15 (for redirect based flows) or Section A.6 (for DC API) of [@!OIDF.OID4VP].

## Interoperable Key Attestations {#interop-key-attestations}

Wallet implementations using the key attestation format specified in Annex D of [@!OIDF.OID4VCI] might need to utilize a transformation (backend) service to create such attestations based on data as provided in other formats by the respective platform or secure key management module. Such a backend service MUST be designed considering the privacy of its users. For example, the service could be stateless and just perform the transformation of the attestation data without binding the process in any way to a unique user identifier.

{backmatter}

<reference anchor="OIDF.OID4VCI" target="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">
        <front>
          <title>OpenID for Verifiable Credential Issuance 1.0</title>
          <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
            <organization>SPRIND</organization>
          </author>
          <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
            <organization>SPRIND</organization>
          </author>
          <author initials="T." surname="Looker" fullname="Tobias Looker">
            <organization>Mattr</organization>
          </author>
          <author initials="P." surname="Bastian" fullname="Paul P. Bastian">
            <organization>Bundesdruckerei</organization>
          </author>
          <date day="16" month="September" year="2025"/>
        </front>
</reference>

<reference anchor="OIDF.OID4VP" target="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">
      <front>
        <title>OpenID for Verifiable Presentations 1.0</title>
        <author initials="O." surname="Terbu" fullname="Oliver Terbu">
         <organization>Mattr</organization>
        </author>
        <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
          <organization>SPRIND</organization>
        </author>
        <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
          <organization>SPRIND</organization>
        </author>
        <author initials="D." surname="Fett" fullname="Daniel Fett">
          <organization>Authlete</organization>
        </author>
        <author initials="J." surname="Heenan" fullname="Joseph Heenan">
          <organization>Authlete</organization>
        </author>
       <date day="9" month="July" year="2025"/>
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

<reference anchor="FAPI2_Security_Profile" target="https://openid.net/specs/fapi-security-profile-2_0.html">
  <front>
    <title>FAPI 2.0 Security Profile</title>
    <author initials="D." surname="Fett" fullname="Daniel Fett">
      <organization>Authlete</organization>
    </author>
    <author initials="D." surname="Tonge" fullname="Dave Tonge">
      <organization>Moneyhub Financial Technology Ltd.</organization>
    </author>
    <author initials="J." surname="Heenan" fullname="Joseph Heenan">
      <organization>Authlete</organization>
    </author>
   <date day="22" month="Feb" year="2025"/>
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

<reference anchor="ISO.18013-5.second.edition" target="https://www.iso.org/standard/91081.html">
        <front>
          <title>ISO/IEC 18013-5:xxxx Personal identification — ISO-compliant driving license — Part 5: Mobile driving license (mDL)  application edition 2</title>
          <author>
            <organization>ISO/IEC JTC 1/SC 17 Cards and security devices for personal identification</organization>
          </author>
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

<reference anchor="w3c.digital_credentials_api" target="https://www.w3.org/TR/digital-credentials/">
        <front>
          <title>Digital Credentials API</title>
          <author fullname="Marcos Caceres">
            <organization>Apple Inc.</organization>
          </author>
          <author fullname="Tim Cappalli">
            <organization>Okta</organization>
          </author>
          <author fullname="Mohamed Amir Yosef">
            <organization>Google Inc.</organization>
          </author>
          <date day="17" month="Sep" year="2025"/>
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

<reference anchor="ETSI.TL" target="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
        <front>
          <title>ETSI TS 119 612 V2.4.1 Electronic Signatures and Trust Infrastructures (ESI); Trusted Lists </title>
          <author>
            <organization>European Telecommunications Standards Institute (ETSI)</organization>
          </author>
          <date month="Aug" year="2025"/>
        </front>
</reference>

<reference anchor="IANA.URI.Schemes" target="https://www.iana.org/assignments/uri-schemes">
  <front>
    <title>Uniform Resource Identifier (URI) Schemes</title>
    <author>
      <organization>IANA</organization>
    </author>
    <date/>
  </front>
</reference>

<reference anchor="NIST.SP.800-131A" target="https://csrc.nist.gov/pubs/sp/800/131/a/r2/final">
  <front>
    <title>NIST SP 800-131A: Transitioning the Use of Cryptographic Algorithms and Key Lengths</title>
    <author fullname="Elaine Barker">
        <organization>NIST</organization>
    </author>
    <author fullname="Allen Roginsky">
        <organization>NIST</organization>
    </author>
    <date month="Mar" year="2019"/>
  </front>
</reference>

<reference anchor="NIST.SP.800-57" target="https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final">
  <front>
    <title>NIST SP 800-57 Part 1: Recommendation for Key Management: Part 1 – General</title>
    <author fullname="Elaine Barker">
        <organization>NIST</organization>
    </author>
    <date month="May" year="2020"/>
  </front>
</reference>

<reference anchor="BSI.TR-02102-1" target="https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile">
  <front>
    <title>Cryptographic Mechanisms: Recommendations and Key Lengths</title>
    <author>
        <organization>Federal Office for Information Security (BSI)</organization>
    </author>
    <date month="Jan" year="2025"/>
  </front>
</reference>

<reference anchor="ECCG.ACM2" target="https://certification.enisa.europa.eu/document/download/a845662b-aee0-484e-9191-890c4cfa7aaa_en">
  <front>
    <title>Agreed Cryptographic Mechanisms 2.0</title>
    <author>
        <organization>European Cybersecurity Certification Group, Sub-group on Cryptography</organization>
    </author>
    <date month="April" year="2025"/>
  </front>
</reference>


# IANA Considerations

## Uniform Resource Identifier (URI) Schemes Registry

This specification registers the following URI schemes in the IANA "Uniform Resource Identifier (URI) Schemes" registry [@IANA.URI.Schemes].

### haip-vci

* Scheme name: haip-vci
* Status: Permanent
* Applications/protocols that use this scheme name: Wallets that implement the OIDF HAIP specification to offer a Credential using OpenID for Verifiable Credential Issuance
* Contact: OpenID Foundation Digital Credentials Protocols Working Group - openid-specs-digital-credentials-protocols@lists.openid.net
* Change Controller: OpenID Foundation Digital Credentials Protocols Working Group - openid-specs-digital-credentials-protocols@lists.openid.net
* Reference: (#credential-offer) of this specification

### haip-vp

* Scheme name: haip-vp
* Status: Permanent
* Applications/protocols that use this scheme name: Verifiers invoking Wallets that implement the OIDF HAIP specification to request the presentation of Credentials using OpenID for Verifiable Presentations
* Contact: OpenID Foundation Digital Credentials Protocols Working Group - openid-specs-digital-credentials-protocols@lists.openid.net
* Change Controller: OpenID Foundation Digital Credentials Protocols Working Group - openid-specs-digital-credentials-protocols@lists.openid.net
* Reference: (#oid4vp-redirects) of this specification

# Acknowledgements {#Acknowledgements}

We would like to thank Patrick Amrein, Paul Bastian, Brian Campbell, Lee Campbell, Tim Cappalli, Stefan Charsley, Gabe Cohen, Andrii Deinega,  Rajvardhan Deshmukh, Daniel Fett, Pedro Felix, Ryan Galluzzo, Timo Glastra, Martijn Haring, Bjorn Hjelm, Alen Horvat, Łukasz Jaromin, Mike Jones, Markus Kreusch, Philipp Lehwalder, Tobias Looker, Hicham Lozi, Mirko Mollik, Andres Olave, Gareth Oliver, Oliver Terbu, Giuseppe De Marco, Mikel Pintor, Joel Posti, Dima Postnikov, Andreea Prian, Bob Reynders, Samuel Rinnetmäki, Peter Sorotokin, Jan Vereecken, Jin Wen, Hakan Yildiz and David Zeuthen for their valuable feedback and contributions to this specification.

# Notices

Copyright (c) 2025 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft, Final Specification, or Final Specification Incorporating Errata Corrections solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts, Final Specifications, and Final Specification Incorporating Errata Corrections based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy (found at openid.net) requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. OpenID invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.

# Document History

   [[ To be removed from the final specification ]]

   -06

   * add cose alg identifer -9 (fully specified)
   * clarify that DCQL applies in HAIP as defined in OpenID4VP and all REQUIRED and OPTIONAL requirements remain the same
   * add reference to ECCG Agreed Cryptographic Mechanisms 2.0
   * require x5c header in the OID4VCI Appendix D key attestation
   * add "Non-normative Examples of Ecosystem-specific Extensions of this Specification" section

   -05

   * mandate support for same device flow for redirect-based OpenID4VP
   * add ecosystem guidance section
   * change wallet attestation format from mandatory to recommended
   * update crypto suites to require at least ECDSA w/ P-256 and SHA-256 for verifying signed artificats; and made ecosystem-specific exceptions for crypto suites and hash algorithms if certain criteria is not met
   * removed intent_to_retain mandatory
   * add small note about signed requests
   * clarify batch issuance requirements
   * remove text about `iat` and `exp` in JWT claims
   * resolve contradictory text about key attestation support requirements
   * add "Requirements Notation and Conventions" section
   * remove requirement that SD-JWT `iss` is a https url
   * add section about the OIDF conformance tests
   * add implementation considers around browser/OS limitations
   * combine text about ecosystem profiling of X.509 certifications
   * add guidance around key sizes
   * require wallets (that render images from credential metadata) to support png and svg, and data: and https: urls
   * clarity text around flows that are defined in this specification
   * add requirement on status list index uniqueness
   * add recommendation that SD-JWT VC validity period is limited then it must use `exp` or a token status list
   * explain intent of 'high assurance' in document title
   * require compliance with (most of) FAPI2 Security Profile for VCI
   * add requirement that, if implementing mdoc revocation, one of methods defined in 2nd edition draft of ISO 18013-5 must be used
   * update editors/contributors

   -04

   * update etsi tl and DC API references
   * update VP & VCI references to be to 1.0 Final
   * add separate custom url schemes for issuance and presentation to replace the haip:// scheme
   * support for haip-vp:// and haip-vci:// custom url schemes is now an ecosystem decision
   * allow ecosystems the option to use key attestations other than those defined in Annex D of [@!OIDF.OID4VCI] in some cases
   * clarify nonce endpoint must be present when cryptographic_binding_methods_supported is
   * remove various requirements around claims present in SD-JWT VC as upstream spec covers them
   * require ephemeral encryption keys in VP
   * add note that lower assurance credentials can also be conveyed using this specification
   * add note on verifier certificate profiling
   * added support for credentials without cryptographic holder binding
   * mandate support for aki trusted_authorities method
   * remove presentation exchange reference since it was removed in openid4vp
   * Authorization Server and Credential Issuer must support metadata
   * x509_san_dns & verifier_attestations client id prefixes are no longer permitted, x509_hash must be used
   * x.509 certificates are now the mandatory mechanism for SD-JWT VC issuer key resolution
   * `x5c` header in Status List Token must be present
   * clarify that Wallet Attestations must not contain linkable information.
   * add signed Issuer Metadata
   * require key attestation for OpenID4VCI
   * clarify text regarding mdoc specific parameters
   * add small note that establishing trust in and retrieving root certs is out scope
   * update wording from Client Identifier Scheme to Client Identifier Prefix #182
   * fix reference to ARF #177
   * remove old link in section 8 & clarify a note on claim based binding in OpenID4VP in HAIP #183
   * Clarify clause 4.1 statement #169
   * add a list of all specifications being profiled #145
   * say something about DPoP nonces
   * refactor to separate generic and SD-JWT clauses
   * add support for ISO mdoc isssuance
   * add support for ISO mdoc when using redirect-based OID4VP
   * remove requirement to support batch endpoint (it was removed from OID4VP)
   * remove SIOPv2 (webauthn is now the recommended way to handle pseudonymous login)
   * prohibit self-signed certificates for signing with `x509_hash`
   * trust anchor certificates must not be included in `x5c` headers

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
