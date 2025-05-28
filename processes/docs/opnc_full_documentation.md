# Plug and Charge Ecosystems

**Interface description Version DOC_DATE**

## Introduction

Plug&Charge (PnC) Ecosystems enable EV OEMs, Mobility Operators and Charge Point Operators to use the ISO 15118 standard for the Plug&Charge functionalities.
PnC-Ecosystems manage certificates from V2G-, OEM- and eMSP-PKIs. It manages the publication in pools  and offers signing services for trusted data. V2G Root CAs can be a trust anchor for all participants of ISO 15118. The V2G-, OEM- and eMSP-CAs are published in the Root Certificate Pools of a Plug&Charge Ecosystem. It is possible to operate also parts like just a RCP, PCP, CPS, CCP or PKI Signing Services

The interfaces of the OPCP are fully compatible with ISO 15118-2:2014 and the VDE application rule (“VDE Anwendungsregel”). It aims to also cover all of the use cases described in the CharIN "PKI Interoperability Guide". It is also fully interoperable for all relaying parties. The specific implementation/description is based on international best practices, security of communication and protection of data.

The Ecosystem components can be divided into three main categories:
 * The Plug&Charge Certificate pools and Certificate Provisioning Service
 * The Plug&Charge PKI Services
 * The Plug&Charge Callback Service

Plug&Charge PKI Services are managed services of V2G Root Operators, to provide all necessary certificates for EV OEMs, Mobility Operators, Certificate Provisioning Services and Charge Point Operators.

The Certificate pools and the Certificate Provisioning Service are for publishing certificates and contract certificates between all ISO 15118 involved actors.

## Related documents

 * [DIN EN ISO 15118-2:2014: Road vehicles - Vehicle-to-Grid Communication Interface - Part 2: Network and application protocol requirements (ISO 15118-2:2014)](https://www.din.de/en/getting-involved/standards-committees/naautomobil/publications/wdc-beuth:din21:250999944)
 * [VDE Anwendungsregel: VDE-AR-E 2802-100-1, Anwendungsregel: 2017-10, „Zertifikats-Handhabung für E-Fahrzeuge, Ladeinfrastruktur und Backend-Systeme im Rahmen der Nutzung von ISO/IEC 15118“](https://www.vde-verlag.de/normen/0800432/vde-ar-e-2802-100-1-anwendungsregel-2017-10.html)
 * [Whitepaper of Charging Interface Initiative e.V. "Interoperability Guide – Public Key Infrastructure (PKI) use casesVersion 1.0"](https://www.charin.global/media/pages/technology/knowledge-base/f50187baf9-1683808407/charin_interoperability_guide-pki_use_cases_v1.0.pdf)

## Further reading

 * [Abbreviations](./01_abbreviations.md)
 * [Business Processes](./02_PnC_business-processes.md)
 * [Publications and Repository Responsibilities](./03_publications-and-repository-responsibilities.md)
 * [Authentication](./04_authentication.md)
 * [Handling of IDs](./05_handling-of-ids.md)

## System-Components

This section describes the components of the Plug&Charge Ecosystem and their purpose of use.

* [Root Certificate Pool (RCP)](./components/01_root-certificate-pool.md) – stores and distributes root certificates of all participating PKIs.
* [Provisioning Certificate Pool (PCP)](./components/02_provisioning-certificate-pool.md) – stores OEM provisiong certificates and makes them available to the eMSPs.
* [Certificate Provisioning Service (CPS)](./components/03_certificate-provisioning-service.md) – provisions contract certificates to prepare them to get installed in the EV.
* [Contract Certificate Pool (CCP)](./components/04_contract-certificate-pool.md) – stores provisioned contract certificates waiting to get installed.
* [Plug&Charge PKI Services](./components/05_v2g-pki-services.md)
* [Plug&Charge Webhook Service](./components/06_webhook-service.md)


---

# Versioning

## Interface version

Version number syntax: `M.m.d`

* **M**ajor version: Incremented when API changes are not compatible with the former version.
* **m**inor version: Incremented when new functionality is added or compatible changes are made.
* **d**ocumentation: Incremented when the documentation has changed without functional impact.

The individual API definition files have separate version numbers. This allows to update only one service while the others remain unchanged. For compatibility reasons the major versions need to be the same over all services. For this reason the interface description documents are geeting released by interface major version and date. E.g. `1-2020-07-31`.


## URI structure

The unified URI structure is as follows:
```
https://{domain}/opnc/{version}/{service}/{object}
```
 * `domain`: Domain name of the plug&Charge actor with a server exposing OPNC services. May be organized into subdomains according to the region (us, eu,etc..) and the nature (staging, production, etc..) of the actor's platform  
 * `version`: Version tag of the API, e.g. _1.1.0_ or _1.2.3_.
 * `service`: ID of the ecosystems microservice to adress, e.g. _root_ for the RCP. See API definition.
 * `object`: Name of the object to modify, e.g. _rootCerts_. See API definition.

<!-- theme: warning -->

>  API consumers should be able to configure the parameters _region_, _stage_ and _domain_ per deployment.


---

# List of Abbreviations

 * __CA__: Certificate authority
 * __CCP__: Contract certificate pool
 * __CN__: Common name
 * __CP__: Certificate Policy
 * __CPO__: Charge point operator
 * __CPS__: Certificate provisioning service
 * __CRL__: Certificate revocation list
 * __CSR__: Certificate signing request
 * __DHPublicKey__: Diffie–Hellman public key
 * __DN__: Distinguished name
 * __EMAID__: e-mobility account identifier
 * __EVSE__: Electric vehicle supply equipment
 * __HSM__: Hardware secure module
 * __eMSP__: e-Mobility Service Provider
 * __OCSP__: Online certificate status protocol
 * __OEM__: Original equipment manufacturer
 * __PCP__: Provisioning certificate pool
 * __PE__: Private environment
 * __PCID__: Provisioning certificate identifier
 * __PKI__: Public key infrastructure
 * __PnC__: Plug&Charge
 * __QA__: Quality Assurance
 * __RCP__: Root certificate pool
 * __SECC__: Supply equipment communication controller
 * __V2G__: Vehicle to grid
 * __VDE__: Verband der Elektrotechnik Elektronik Informationstechnik e. V.
 * __VDE-AR__: Handling of certificates for electric vehicles, charging infrastructure and backend systems within the framework of ISO 15118 – English translation of VDE-AR-E 2802-100-1:2019-12
 * __VIN__: Vehicle identification number
 * __WMI__: World manufacturer identifier


# Usage of abbreviations and acronyms in the API

To make the API more consistent, the casing of all methods and properties will get aligned to [camel case](https://en.wikipedia.org/wiki/Camel_case#Programming_and_coding). For acronyms and abbreviations applies:

> (…) treat abbreviations as if they were lowercase words and write "oldHtmlFile", "parseDbmXml" or "sqlServer". (Wikipedia)

<!-- theme: warning -->

> In Version 1 there are exceptions to this rule!


---

# Business Processes

This section summarizes the processes of Plug and Charge as described as _Certificate Provisioning_ in ISO 15118-2:2014 Section 7.9.2.5 and explained in more detail in Appendix E.3.

The VDE Application Rule focusses on these processes and details each process flow for further understanding. The following figure shows the overall process with components and flows, which are based on the VDE Application Rule.

![Overview on the overall process](../assets/images/plug&charge_process_overview.png)

Note: It does not cover all processes (use-cases) to enable Plug and Charge, e.g. charging station certificate management. Further details are descibed in the "Interoperability Guide – Public Key Infrastructure (PKI) use cases". 

During contract provisioning, several sub-processes are also required, which can be divided into four main parts:

 1. **Vehicle production and preparation of contract based billing**
   - The OEM generates a Provisioning Certificate for each electric vehicle during production.
   - The OEM installs a trust store containing all relevant Root Certificates from the Root Certificate Pool.
 2. **Contract conclusion and vehicle assignment**
   - The eMSP concludes a charging contract for a specific customer's electric vehicle, using the vehicles Provisioning Certificate from the Provisioning Certificate Pool.
   - Providing contract data to the Certificate Provisioning Service or
   - Providing contract information to V2G Mobility Operator CA
  3. **(Periodic) provisioning of contract data**
   - Signing contract data and storing in the CCP
   - Generating contract data in V2G Mobility Operator CA and storing in the CCP
 4. **Installation of contract data**
   - Providing signed contract data to CPO-backend on request
   - Delivery of signed contract data to OEM-backend


## Business Processes relevant for all participants

#### Providing Root Certificates for Public Charging and Contract-Based Billing
The mutual trust between participants is a precondition for ISO 15118 and thus Plug&Charge to function. For this purpose, a Root Certificate Pool is set up for the storage of all Root certificates. Each participant gets access to receive the Root certificates of other participants to validate the trust chain of each certificate.

![Providing root certificates for public charging and contract-based billing](../assets/images/process_providing_root_certificates.png)



## Business Processes relevant for the CPO

### Providing Signed Contract Data to CPO-Backend on Request

Alternative to the OEM backend, is the installation of signed contract data via the charging station. The OEMs, which do not use an OEM backend, can use this process for the delivery of contract data.
After a successful handshake between EV and charging device, the EV sends a certificateInstallationRequest to the charging device, which will be forwarded via the CPO backend to the CCP.
The CCP finds the contracts of this EV, verifies the validity of each certificate and delivers it back to the CPO backend.

![Providing signed contract data to CPO backend on request](../assets/images/process_providing_signed_contract_data_to_cpo_backend_on_request.png)


## Business Processes relevant for the eMSP

### Contract Conclusion and Vehicle Assignment

This process describes, the conclusion of contract between customer and eMSP and delivery of OEM provisioning certificate of vehicle to the eMSP.
The eMSP must receive the contract information from a customer including the PCID of the vehicle. The eMSP can retrieve the Provisioning Certificate from the PCP with the supplied PCID. This Provisioning Certificate must've been sent by the OEM to the PCP beforehand. The PCP delivers the OEM provisioning certificate, including the corresponding Sub CA chain (See Figure 5).

After verifying the authenticity of the trust chain with the OEM root certificate (which has been received from the Root Certificate Pool), the eMSP can generate a unique e-mobility account identifier for this contract. To create a contract for the customer, eMSPs have two possibilities:

 - Create and send the contract data to the CPS using the eMSPs own CA, which is described in the “Providing Contract Data to Certificate Provisioning Service” process
 - Or use V2G-PKI eMSP CA services to create, sign and store the contract data


### Providing Contract Data to Certificate Provisioning Service

If the eMSP uses its own CA, it must create a contract data with the following parts:
 - contractSignatureCertChain,
 - dhPublicKey,
 - contractSignatureEncryptedPrivateKey,
 - EMAID

The created contract data must be signed by the CPS.

Moving forward, eMSPs have two possibilities:
 - signing and storing of signed contract data in the CCP
 - signing the contract data and receive the signed contract data without storing them in the CCP


### Provisioning of Contract Data

Signing Contract Data and Storing in CCP:
The CPS signs the delivered contract data with the V2G Root CA derived Provisioning Certificate private key. Then the CPS either stores it in the CCP for provisioning for the CPO and OEM backends or sends it back to the eMSP.
In this latter method, the eMSP would have to use addSignedContractData to store contract data into a CCP. 
![Signing contract data and storing in CCP](../assets/images/process_signing_contract_data_and_storing_in_ccp.png)


### Generating Contract Data with CPS Mobility Operator Service and Storing in CCP

If the eMSP does not create and sign the contract data (using createSignedContractData method), the V2G eMSP CA Operator and CPS Operator can generate a contract data with the received contract information from the eMSP. The CPS Operator would then send the contract data to the CPS for signing and then store the signed contract data in the CCP.

## Business Processes relevant for the OEM

### Production of Vehicles and Storing Provisioning Certificate

With the production of the vehicle, the OEM must create a provisioning certificate for each vehicle with a unique provisioning certificate identifier – PCID. The OEM sends this unique OEM provisioning certificate corresponding subordinate CA (Sub CA) certificates securely to the Provisioning Certificate Pool.
The customers shall also receive the PCID of their vehicles to give it to the eMSPs, during the conclusion of a charging contract.
The required V2G root certificates shall also be installed and stored in the vehicle for the trusted communication with charging devices and to verify contract data.

![Production of vehicles and storing provisioning certificate](../assets/images/process_production_of_vehicles_and_storing_provisioning_certificate.png)


## Pool management
 * Cleanup of RCP, PCP and CCP by:
   * Revoked certificate shall be removed on regular basis from pools.
   * Expired certificates shall be removed on regular basis from pools.
  
 ## Pool Interoperability between Plug&Charge Ecosystems
The OPNC is designed and prepared for pool interoperability. The outcome is based on the research project between multiple stakeholders in 2022
[PKI-for-ISO-15118-2022-pdf](https://elaad.nl/wp-content/uploads/downloads/PKI-for-ISO-15118-2022-pdf.pdf).
The Project incl. a live Demo showed the technical feasibility. The concept is based on broadcasting of requests between ecosystems if the native ecosystem can not process the request from the directly connected CPO, MSP or OEM. For that in the PCP, CPS and CCP a so-called broadcast flag is defined. Setting that flag will prevent ecosystems to go into infinity broadcastings. As one example:

1. EMSP A -> \<get provisioning certificate fpr PCID XYZ \> PCP 1
2. PCP1 -> does not have the provisioning certificate for that EV OEM
3. PCP1 ->  \<get provisioning certificate fpr PCID XYZ - BROADCAST\> PCP2|PCP3 etc
4. PCP2 -> \<HTTP 404 - Not found\> PCP1
5. PCP3 -> \<HTTP 200 - Body with Provisioning Certificate for PCID XYZ\> PCP1 
6. PCP1 -> \<HTTP 200 - Body with Provisioning Certificate for PCID XYZ\> EMSP A

 


---

# Publications and Repository Responsibilities

##	Repositories
In accordance with VDE-AR, the following repositories (except for OSCP and CRL) must be maintained to provide online access via a standard interface to certificates and related data for the participants of the ecosystem.

### The Root Certificate Pool RCP:
The Root Certificate Pool securely stores V2G-, OEM- and eMSP Root CA certificates participating in the PKI. The RCP operator verifies the authenticity of the root certificate owner before stroring them into the Root Certificate Root.

#### Fingerprint:
The fingerprint must have been authentically obtained via second channel from the corresponding root CA and must correspond to the fingerprint of the certificate.

#### Revocation:
The status of the Root certificate shall be confirmed by the owner of the root certificate company.

####	Requirements of ISO 15118
The certificate structure must comply with the specification in ISO 15118.

#### Restriction in access
Write access to the RCP is restricted to certain employees and IT systems of RCP operator and requires authentication.

####	All activities at the RCP shall be documented and archived.

### The OEM Provisioning Certificate Pool RCP:
The PCP securely stores the OEM provisioning certificate that is installed individually in each EV an OEM produces. Furthermore, the OEM Provisioning Certificate Pool stores the OEM Sub1-CA certificate and the OEM Sub2-CA certificate to allow signature verification along the OEM certificate chain. All certificates are stored together with the unique OEM provisioning certificate ID (PCID) that is also written in the subject’s common name field of the OEM provisioning certificate. 

###	The Contract Certificate Pool CCP:
The Contract Certificate Pool securely stores pre-compiled contractData which have been signed by the provisioning certificates as described by VDE_AR and provided by a certificate provisioning service CPS. This data are ready to send in life time as certificateInstallationResponse message to the OEM or CPO.

---

# Authentication

This section describes the most important aspects of authentication and authorization for an PnC EcoSystem. All Endpoints shall be secured and can only be reached after a successful authentication. 

To establish secure connections via HTTPS, Transport Layer Security via TLS 1.3 is recommended.

## Oauth2

It is recommended in using [OAuth2](https://tools.ietf.org/html/rfc6749) as authentication method. You will need to issue a [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519) that can be obtained by different ways as described in the following sections. The token may contain information about what you are allowed to do, e.g. role (CPO, eMSP, OEM, CPS), what APIs you are allowed to use and which EMAIDs or PCIDs you are allowed to check.

The issued token will contain all necessary information to access the system (you can check this online on your own e.g. [jwt.io](https://jwt.io/)). 

## Roles&Rights

Depending on the role and the company the access rights are distinct. 

### OEM
Depending on the WMI in the PCID (first 3 characters), the OEM has read/write access to its data. Please always inform the ecosystem operator of the needed WMIs actively. If the correct data are not configured, the Plug&Charge Ecosystem will deny the access to perform the action.

### eMSP
Depending on the EMAID (first 5 characters - CountryCode + ProviderID), the eMSP has read/write access to its data. Please always inform the ecosystem operator of the needed Country Codes and ProviderIDs activity. If the correct data are not configured, the Plug&Charge Ecosystem will deny the access to perform the action.

### CPO
Depending on the EVSEID (first 5 characters - CountryCode + OperatorID), the CPO has read/write access to its data. Please always inform the ecosystem operator of the needed Country Codes and OperatorID activity. If the correct data are not configured, the Plug&Charge Ecosystem will deny the access to perform the action.


| Service | Access rights                                            | Method                                            | Access Rights | OEM       | CPO       | eMSP with own PKI | eMSP without own PKI | CPS       |
|---------|----------------------------------------------------------|---------------------------------------------------|---------------|-----------|-----------|-------------------|----------------------|-----------|
| RCP     | OEM, CPO, eMSP                                           | GetRootCertificate                                | Read          | Access    | Access    | Access            | Access               | Access    |
| RCP     | OEM, CPO, eMSP                                           | GetRootCertificates                               | Read          | Access    | Access    | Access            | Access               | Access    |
| RCP     | Admin                                                    | DeleteRootCertificate                             | write         | No Access | No Access | No Access         | No Access            | No Access |
| RCP     | Admin                                                    | PutRootCertificate                                | write         | No Access | No Access | No Access         | No Access            | No Access |
| PCP     | OEM (Only those with the corresponding WMI)              | AddProvisioningCertificate                        | Write         | Access    | No Access | No Access         | No Access            | No Access |
| PCP     | OEM (Only those with the corresponding WMI)              | DeleteProvisioningCertificate                     | Delete        | Access    | No Access | No Access         | No Access            | No Access |
| PCP     | OEM,eMSP                                                 | GetProvisioningCertificate                        | Read          | Access    | No Access | Access            | Access               | Access    |
| PCP     | OEM,eMSP                                                 | lookupVehicle                                     | Read          | Access    | No Access | Access            | Access               | Access    |
| CPS     | OEM,eMSP,CPO,CPS                                         | GetCpsCertificates                                | Read          | Access    | Access    | Access            | Access               | Access    |
| CPS     | eMSP with own PKI (external PKI) (only their own EMAIDS) | SignContractData                                  | Write         | No Access | No Access | Access            | No Access            | No Access |
| CPS     | eMSP without own PKI (V2G PKI) (only their own EMAIDS)   | GenerateAndSignContractData                       | Write         | No Access | No Access | No Access         | Access               | No Access |
| CCP     | CPO                                                      | GetSignedContractDataByCertificateInstallationReq | Read          | No Access | Access    | No Access         | No Access            | No Access |
| CCP     | eMSP                                                     | DeleteSignedContractDataByEmaid                   | Delete        | No Access | No Access | Access            | Access               | No Access |
| CCP     | eMSP                                                     | GetContractDataByEmaid                            | Read          | No Access | No Access | Access            | Access               | No Access |
| CCP     | OEM                                                      | GetContractDataByPcid                             | Read          | Access    | No Access | No Access         | No Access            | No Access |
| CCP     | OEM                                                      | GetSignedContractDataByEmaidAndPcid               | Read          | Access    | No Access | No Access         | No Access            | No Access |
| CCP     | eMSP,CPS                                                 | AddSignedContractData                             | Write         | POST      | No Access | Access            | Access               | Access    |
| CCP     | OEM                                                      | SetSignedContractDataAsDefault                    | Read          | Access    | No Access | No Access         | No Access            | No Access |
| PKI     | OEM                                                      | simpleEnroll - OEM                                | Read & Write  | Access    | No Access | No Access         | No Access            | No Access |
| PKI     | OEM                                                      | caCerts - OEM                                     | Read          | Access    | No Access | No Access         | No Access            | No Access |
| PKI     | CPO                                                      | simpleEnroll - CPO                                | Read & Write  | No Access | Access    | No Access         | No Access            | No Access |
| PKI     | CPO                                                      | caCerts - CPO                                     | Read          | No Access | Access    | No Access         | No Access            | No Access |
| PKI     | eMSP                                                     | simpleEnroll - eMSP                               | Read & Write  | No Access | No Access | No Access         | Access               | No Access |
| PKI     | eMSP                                                     | caCerts - eMSP                                    | Read          | No Access | No Access | No Access         | Access               | No Access |
| PKI     | CPS                                                      | simpleEnroll - CPS                                | Read & Write  | No Access | No Access | No Access         | Access               | Access    |
| PKI     | CPS                                                      | caCerts - CPS                                     | Read          | No Access | No Access | No Access         | Access               | Access    |
| PKI     | OEM, CPO, eMSP                                           | revokeCert                                        | write         | Access    | Access    | No Access         | Access               | No Access |
| WEBHOOK | OEM, CPO, eMSP, CPS                                      | Get all endpoints                                 | Read          | Access    | Access    | Access            | Access               | Access    |
| WEBHOOK | OEM, CPO, eMSP, CPS                                      | GetEndpointById                                   | Read          | Access    | Access    | Access            | Access               | Access    |
| WEBHOOK | OEM, CPO, eMSP, CPS                                      | PostEndpoint                                      | Write         | Access    | Access    | Access            | Access               | Access    |
| WEBHOOK | OEM, CPO, eMSP, CPS                                      | UpdateEndpointById                                | Write         | Access    | Access    | Access            | Access               | Access    |
| WEBHOOK | OEM, CPO, eMSP, CPS                                      | DeleteEndpointById                                | Write         | Access    | Access    | Access            | Access               | Access    |


---



# Handling of IDs

## EMAID (E-Mobility Authentication Identifier)

EMAIDs in the definition of ISO-15118 have some representational flexibility due to optional elements. The Plug and Charge ecosystem will therefore normalize all incoming IDs to match the following expression: `/[A-Z]{2}[\dA-Z]{3}[\dA-Z]{9}/i`
However the version with optional seperators (“-”) and check digit is allowed : `/[a-z]{2}(-?)[\da-z]{3}\1[\da-z]{9}(\1[\da-z])?/i`. Nevertheless the ecosystem will always remove Hyphens from the EMAID due to the ISO15118-2 Protocol, where just max. 15 characters can be transfered between EV and EVSE.

ABNF from the ISO 15118-2:2014(E):

`<EMAID>` = `<Country Code>` `<S>` `<Provider ID>` `<S>` `<eMA Instance>` `<S>` `<Check Digit>`

Clients can still use it but the system will normalize to the form above (no seperators and captial letters).

## PCID (Provisioning Certificate Identifier)

PCIDs in the definition of ISO-15118 are represented by the WMI (3 Characters) of the OEM, followed by 14 alphanumeric characters which uniquely identifies the vehicle and an optional check digit/alpha. The Plug and Charge ecosystem checks all incoming IDs to match the following expression: `^[a-zA-Z0-9]{17,18}$`

ABNF from VDE-AR-E 2802-100-1:2019-12 (en)
`<PCID>` = `<WMI>` `<OEM's own unique ID>` `<check digit>`

## EVSE ID (Electric Vehicle Supply Equipment ID)

The EVSE ID shall match the following structure (the notation corresponds to the augmented Backus-Naur Form (ABNF) as defined in IETF RFC 5234):

ABNF from the ISO 15118-2:2014(E):

`<EVSEID>` = `<Country Code>` `<S>` `<EVSE Operator ID>` `<S>` `<ID Type>` `<Power Outlet ID>`

An example for a valid EVSE ID is `DE*ICE*E45B*78C` with `DE` indicating Germany, `ICE` representing Hubjects EVSE Operator ID, `E` indicating that it is of type *EVSE*, `45B` representing the number of this EVSE and `78C` representing one particular power outlet of this specific EVSE.

---

# Root Certificate Pool

The Root Certificate Pool is used as a trusted source of root certificates from various ecosystem certificate authorities (V2G, OEM, eMSP) by the participants (OEM, CPO, eMSP, CPS). 
The stored root certificates are checked before addition to the pool, and regularly with automated processes. Expired or revoked certificates will be invalidated. The storage of root certificates is executed manually by RCP Authority administrators.

Other systems of a PnC Ecosystem use this pool as the mutual trust store.


## API

The root certificate pool offers a REST API to request registered root certificates.

![RCP interfaces](../../assets/images/interfaces_rcp.png)

The documenatation can be found at [rcp.v1.json](../../specification/apis/rcp/rcp.api.v1.json).

## Processes

The root certificate pool is involved in multiple processes across the ecosystem. The Direct Processes are described bellow:

### 1. Deliver Root Certificates

The delivery of root certificates of the OEM, V2G, eMSP, and possibly PE-CAs to the Root Certificate Pool is an organizational process, which can be proceeded by different methods, like signed email, SFTP, OFTP2 or similar methodologies. After approval the new root certificates are added to the root certificate pool by the RCP Operator. Therefore the PUT and DELETE interfaces of the pool are restricted for authorized administrative use only.


### 2. Request Root Certificates

All participants of the PKI may request root certificates published in the RCP. The connected systems may request the list of certificates on regular basis.


### 3. Data Cleansing

The Root Certificate Pool watches all contained root certificates on regular basis. 

## Additional notes

If a Root CA revokes a root certificate, the Plug&Charge Ecosystem operator should not immediately revoke all related certificates, including the contract certificates. This can cause deletion of all related certificates and the charging service to stop working. For this case, an organizational process _must_ be defined between the Operator and the respective customers to ensure a customer friendly transition to another Root CA.

Until the delivery of a new root certificate, it will not be possible to send any new leaf certificate. Because the validation of the trust chain of the certificate cannot be proceeded. For more information about the validation process please see chapter interface description.


---

# Provisioning Certificate Pool

The Provisioning Certificate Pool provides interfaces to exchange OEM Provisioning Certificates between OEMs and eMSPs,under the following workflows: 

1. OEMs publish their OEM Provisioning Certificates on the pool after their generation, e.g. after the car get manufactured. eMSPs request foreign Provisioning Certificates from the pool by PCID.
2. eMSP sends the PCID of a Provisioning Certificate issued by the OEM, and receives the OEM Provisioning Certificate with the corresponding certificate chain.

The PCP communicates with the following actors and services:
 * OEM
 * Mobility Operator
 * Contract Certificate Pool
 * OCSP Responders of the Provisioning Certificates
 * Root Certificate Pool


## Data Access

It is ensured that the safety precautions of ISO 15118 are complied with, and only trustworthy eMSPs have granted access. In addition, no confidential OEM data, such as the number of available electric vehicles, can be displayed when querying the available OEM Provisioning Certificates.

Every authorized eMSP access is granted to all available Provisioning Certificates in the pool.

The Provisioning Certificates of each OEM are separated by access rules. The defined access rules prevent access to other OEM containers. Each OEM can only manage (create/update/delete) Provisioning Certificates of their company. To achieve this, the client credentials of each OEM get white-listed for a list of World manufacturer identifier (WMI) codes (see ISO 3780).

## API

The Provisioning Certificate Pool offers a REST API to request registered Provisioning Certificates.

![PCP interfaces](../../assets/images/interfaces_pcp.png)

All documentation can be found in the PCP API Schema at [pcp.v1.json](../../specification/apis/pcp/pcp.v1.json).



## Processes

The Provisioning Certificate Pool (PCP) is involved in multiple processes across the ecosystem. The Direct Processes are described bellow:


### 1. Publish a Provisioning Certificate

With the production of a vehicle, the OEM must create a Provisioning Certificate for the vehicle. Each Provisioning Certificate must have an unique Provisioning Certificate Identifier (PCID). The OEM then publishes this Provisioning Certificate as well as its certification chain by sending it to the Provisioning Certificate Pool.

The PCID is the identifier for a vehicle and must match the ISO pattern [PCID Format](../05_handling-of-ids.md). The Provisioning Certificate Pool authorizes the OEM client based on this code. [see Data Access](#data-access)

With the publication of a Provisioning Certificate to the pool, no information is given automatically to an eMSP. Trusted eMSPs can only retrieve individual Provisioning Certificates if they request them through the PCID.

Therefore the OEM's costumers shall also receive the PCID of their vehicles to give it to the eMSPs during the conclusion of a charging contract.

The required V2G root certificates shall be stored in the vehicle for the trusted communication with charging devices.

Before the storage of the Provisioning Certificate, the Provisioning Certificate Pool proceeds the following control steps:

 1. Verifies the PCIDs world manufacturer identifier (WMI) against the OEM accounts authorized WMI list.
 2. Verifies the validity date (validUntil) of each certificate from leaf to root to be in the future. (Validity shell model)
 3. Verifies the certificate status of each delivered certificate (leaf and chain) from it's OCSP responder or CRL.
 4. Verifies the trust chain to the OEM root certificate

The PCP responds with an corresponding error code for the first occurring error and stops the processing.


### 2. Update a Provisioning Certificate

In case an OEM needs to renew a Provisioning Certificate, they may do so by sending an updated Certificate to the pool.

The update process overwrites the existing Provisioning Certificate with the same PCID.

<!-- theme: info -->

> An update of a Provisioning Certificate in the pool triggers an instant push notification to all eMSPs subscribed to the corresponding WMI if the key pair has changed. See [Webhooks Service](./06_webhook-service.md)


### 3. Delete a Provisioning Certificate

In case the Provisioning Certificate under one PCID shall be removed from the ecosystem, the OEM that owns it may delete it from the pool.

<!-- theme: info -->

> This operations triggers the Contract Certificate Pool to delete all existing Contract Certificates linked to this Provisioning Certificate. See [Webhooks Service](./06_webhook-service.md)


### 4. Request a Provisioning Certificate

Before creating the Contract Certificate Bundle, the eMSP has to request the current Provisioning Certificate by the Provisioning Certificate ID from the pool.

### 5. Lookup a Vehicle

This method can be used by the eMSP to determine for a given PCID if a Provisioning Certificate is available in the PCP.

## Data Cleansing

The stored OEM Provisioning Certificates are checked regularly with automated processes, expired and revoked certificates will be deleted. The deletion of a provisioning certificate triggers a deletion of all connected Contract Certificates from the [Contract Certificate Pool](./04_contract-certificate-pool.md)


---

# Certificate Provisioning Service

The CPS provides interfaces for generating and signing contract data of eMSPs. eMSPs can provide contract data to the CPS for signage directly or send contract information to generate contract data via the Mobility Operator CA. The signed contract data are either returned to the eMSP and/or stored in the CCP.


## API

The Certificate Provisioning Service can receive and sign contract data through a REST API, using one of the multiple endpoints. The signed data can be optionally stored into Contract Certificate Pool (this is usually the case).

![CPS interfaces](../../assets/images/interfaces_cps.png)

All CPS API documenatation can be found at [cps.v1.json](./../../../specification/apis/cps/cps.api.v1.json).



---

# Contract Certificate Pool

The CCP stores the signed contract data from the eMSPs, and provides it to the CPOs and OEMs. The CPO's backend can request a signed contract using the certificateInstallationRequest, as defined on ISO 15118-2:2014.

The CPS' signed contract data will be stored in the CCP, and assigned to their respective PCID. The CCP also enables multiple contracts storing for each PCID. 

The CCP keeps contracts of each eMSP separated. The defined access rules prevent unauthorized requests to others eMSP contracts. That means each eMSP can only manage (create/update/delete) contracts of their own company.

The Ecosystem Administration creates a node for each eMSP after the provider ID confirmation from the issuing authority.


## API

The Contract Certificate Pool offers a REST API supporting registered contract certificate requests.

All CCP API's documentation are available at [ccp.v1.json](../../../specification/apis/ccp/ccp.api.v1.json).

## Processes

The Contract Certificate Pool (CCP) is involved in multiple processes across the ecosystem. The Direct Processes are described bellow:

### 1. Publish a Contract Certificate

The Contract Certificate pool can receive contracts by two means: 
1- Contracts forwarded by the CPS 
2- Added contracts by the EMSPs

<!-- theme: info -->

> Publishing a Contract Certificate in the pool can trigger an instant push notification to the OEM enrolled in the WMI corresponding to the contract's PCID. See [Webhooks Service](./06_webhook-service.md)

### 2. Update a Contract Certificate

In case an eMSP needs to renew a Contract Certificate, they may do so by sending an updated Certificate to the pool.

The update process overwrites the existing Contract Certificate with the same EMAID.

<!-- theme: info -->

> An update of a Contract Certificate in the pool can trigger an instant push notification to the OEM enrolled in the WMI corresponding to the contract's PCID. See [Webhooks Service](./06_webhook-service.md)


### 3. Delete a Contract Certificate

In case the Contract Certificate under one EMAID needs be removed from the ecosystem, the eMSP that owns it may delete it from the pool.

<!-- theme: info -->

> A deletion of a contract certificate in the pool can trigger an instant push notification to the OEM enrolled in the WMI corresponding to the contract's PCID. See [Webhooks Service](./06_webhook-service.md)


### 4. Retrieving a Contract Certificate

In case a CPO or an OEM is requesting to get a Contract Certificate the CCP sends the contract data to the requesting endpoint.


## Data Cleansing
         
The Contract Certificate Pool should be cleaned regularly.


---

# V2G PKI Services

A Plug&Charge PKI Service includes all necessary components of a PKI infrastructure with the following components:

 * Certificate Manager
 * HSMs
 * OCSP responder (if applicable)
 * CRL distribution points (if applicable)
 * eMSP CA
 * OEM CA

These services provide interfaces to CPOs, eMSPs, CPSs and OEMs for issuing/signing certificates and also request certificate statuses.

![Plug&Charge V2G PKI Services Interfaces](../../assets/images/process_V2G_PKI_services.png)


## eMSP Plug&Charge Contract Service

eMSP Plug&Charge Contract Service can be part of Plug&Charge CPS Services and provides interfaces for eMSPs to issue and sign their contract certificates/bundles without the need for any own eMSP-PKI. This service creates certificates and performs all needed cryptographic operations to create ISO15118 compliant signed contract data.

![Mobility Operator CA Interfaces](../../assets/images/interfaces_mo-ca_service.png)


## EST interface

EST interface receives CSRs from CPOs, CPSs, eMSPs or OEMs, signs them and delivers an ISO 15118 leaf certificate. The PKI service provider Certificate Manager creates the leaf certificates from the regarding Sub 2 CA of the respective part of the V2G Root CA.

This interface can create certificates for CPOs (EVSE leaf certificate), eMSPs (contract leaf certificate), CPSs (certificate provisioning certificates) and OEMs (OEM provisioning certificates)

A valid authentication to the EST services is necessary to use this interface.

EST interface is a standard implementation, which is described in the [RFC7030](https://tools.ietf.org/html/rfc7030).

**Operations and their corresponding URIs:**

Operation| Operation path  | Details in RFC
---------|----------|---------
 Distribution of CA Certificates | /cacerts | [RFC Section 4.1](https://tools.ietf.org/html/rfc7030#section-4.1)
 Enrollment of Clients | /simpleenroll  | [RFC Section 4.2](https://tools.ietf.org/html/rfc7030#section-4.2)


The EST interface of the OPNC Plug&Charge PKI Services is fully compliant with RFC7030.

> For the implementation of an EST client, you can use the open source library [libest from CISCO](https://github.com/cisco/libest/tree/master/example/client-simple) or the EST package from [BouncyCastle](https://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/est/package-summary.html)

### EVSE leaf certificates (SECC certificate)
By means of the charge point certificate, the charge point provides its authentication to the vehicle. During a TLS handshake, the charge point establishes a TLS connection to the vehicle. That provides its authentication to the vehicle by sending its charge point certificate and the CPO sub-CA certificates. This certificate chain has been derived from a V2G root CA.
The associated private key of a charge point certificate is stored in the charge point.

The EVSE leaf certificate contains its EVSE ID as common name, the structure of which is defined in the [identifier description chapter](../05_handling-of-ids.md).

### Contract leaf certificates
The contract certificate is used in the case of the Plug & Charge authentication and authorisation modes at a charge point, in contrast to external identification means (EIM). It shall be assigned to a valid contractual relationship between the vehicle user (or owner) and mobility operator and shall be saved in the vehicle together with the private key that is associated with this contract certificate.

The electric vehicle accesses this digital certificate in order to prove the existence of a valid charging contract to the charge point. Contract certificates are derived – via intermediate sub-CAs – from eMSP Root CAs or V2G Root CAs.

The eMSP contract certificate contains an EMAID as common name, the structure of which is defined in the [identifier description chapter](../05_handling-of-ids.md)

### OEM provisioning certificates
An OEM provisioning certificate is issued individually for and saved in each electric vehicle. It shall be possible to renew the provisioning certificate in the vehicle if it is revoked. The process of renewing the certificate is specific to each OEM and can be carried out by a workshop or by means of an online process using the OEM backend and telematics link of the EV. It is used to verify the identity of the electric vehicle when provisioning a contract certificate. It is derived from the OEM Root CA or a V2G Root CA via a chain of OEM sub-CAs.

The OEM provisioning certificate contains a PCID as common name, the structure of which is defined in the [identifier description chapter](../05_handling-of-ids.md).

### CPS provisioning signing certificates
A CPS provisioning signing certificate is issued regularly for a CPS Operator by a V2G PKI Authority. It shall be possible to renew the provisioning signing certificate. It is used to sign contract data for secure installation into an EV. It is derived from the V2G root CA via a chain of CPS Sub-CAs.

### Certificate Signing Request
A CSR or Certificate Signing request contains a block of encoded text that is given to a Certificate Authority when applying for a digital Certificate. It is usually generated on the server/end-device, where the certificate will be installed, and contains information that will be included in the certificate, such as the organization name, common name (domain name), locality, and country. It also contains the public key that will be included in the certificate. A private key is usually created at the same time that you create the CSR, making a key pair, on the end-device. A CSR is generally encoded using ASN.1 according to the PKCS #10 specification.

A certificate authority will use a CSR to create your digital signed certificate, but it does not need your private key. You need to keep your private key secret. The certificate created with a particular CSR will only work with the private key that was generated with it. In the case of losing the private key, the certificate will no longer work.

#### Required CSR Datafields

Name|Explanantion|Example
----|--------|-----
Common Name|The unique [ISO15118 description](../05_handling-of-ids.md) for the certificate. This must match exactly to the ISO15118 and VDE Application Guide standard or you will receive a name mismatch error in the PnC Ecosystem|PCID: e.g. WP012345678901234
Organization|	The legal name of your organization. This should not be abbreviated and should include suffixes such as Inc, Corp, or LLC.|CharIN GmbH

#### CSR Example
```
-----BEGIN CERTIFICATE REQUEST-----
MIIByjCCATMCAQAwgYkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMR8w
HQYDVQQLExZJbmZvcm1hdGlvbiBUZWNobm9sb2d5MRcwFQYDVQQDEw53d3cuZ29v
Z2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApZtYJCHJ4VpVXHfV
IlstQTlO4qC03hjX+ZkPyvdYd1Q4+qbAeTwXmCUKYHThVRd5aXSqlPzyIBwieMZr
WFlRQddZ1IzXAlVRDWwAo60KecqeAXnnUK+5fXoTI/UgWshre8tJ+x/TMHaQKR/J
cIWPhqaQhsJuzZbvAdGA80BLxdMCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4GBAIhl
4PvFq+e7ipARgI5ZM+GZx6mpCz44DTo0JkwfRDf+BtrsaC0q68eTf2XhYOsq4fkH
Q0uA0aVog3f5iJxCa3Hp5gxbJQ6zV6kJ0TEsuaaOhEko9sdpCoPOnRBm2i/XRD2D
6iNh8f8z0ShGsFqjDgFHyF3o+lUyj+UC6H1QW7bn
-----END CERTIFICATE REQUEST-----
```

## OCSP Service

OCSP responders of the Plug&Charge V2G-PKI Service publishes the status information of the certificates, which are created by the Certificate Authority.

This endpoint does not require authentication.

OCSP interface is a standard implementation, which is described in [RFC6960](https://tools.ietf.org/html/rfc6960).




---

# Webhook Notification Service

PnC Ecosystem Operator uses webhooks so when some event happens in our ecosystem your backend system is notified, being able to automatically trigger reactions. 

Webhooks are particularly useful for asynchronous events like when a `contract created` or `root certificate expired`.

The following figure provides a high level overview on the interface concept of the webhook service. The service is subscribed to all relevant events within the ecosystem. The partners can register at the webhook service to observe assets in the ecosystem. Relevant events from the other ecosystem components are collected via an event service and forwarded to the partners system.

![Webhook service](../../assets/images/interfaces_event-service.png)

## What are webhooks 

A webhook enables an ecosystem to push real-time notifications to partner's backend systems. Webhooks Service uses HTTPS to send these notifications to the backend endpoint as a JSON payload. Partners can then use these notifications to execute actions in their backend systems.

### Available Events

| Relevant for Role | Event Name           | Description                                                                                                    | Message (Logging examples for customer)                                        |
|-------------------|----------------------|----------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| ALL               | root.cert.added      | A new root got added to the root pool (RCP), important for CPOs to check if a new V2G or eMSP Root CA needs to be pushed to the EVSEs for authentication. | "New root in RCP available"          |
| ALL               | root.cert.expired    | A root expired and it will be removed from the RCP. No emergency action is needed as it is a natural phase-out. | "Root Expired"                                                                   |
| ALL               | root.cert.revoked    | A root got revoked and it was removed from the RCP. This requires the action of multiple parties depending which root is affected. More manual communication will follow by the PKI provider. | "Root revoked"                                                                   |
| eMSP                | mo.prov.cert.deleted | The OEM Prov. The certificate got deleted from PCP. Hubject deleted all Contract Data for that PCID on CCP. | "PnC is currently disabled because the OEM Provisioning certificate was Deleted/Revoked." |
| eMSP                | mo.prov.cert.factory.reset | The OEM triggered the deletion of all Contracts for a PCID/OEM Prov. Certificate. The eMSP shall not create new Contracts for the EMAID. (e.g. Factory Reset, Car is sold). | "Factory Reset was performed. All contracts for PCID were removed." |
| eMSP                | mo.prov.cert.updated | The OEM Prov. The certificate got updated (different private and public key). Hubject deleted all existing Contract Data for that PCID on CCP as they are not valid anymore. The eMSP shall communicate with the Customer if the contract is recreated for the known PCID. (WERKSTATTFALL) | "Contract deleted, because of a new OEM Prov. A certificate was created. Sync with customer for next steps." |
| eMSP                | mo.contract.created.sent.to.oem | The contract information (oem.contract.created) has been sent to the OEM Backend. | "Contract information (oem.contract.created) has been sent to the OEM Backend." |
| eMSP                | mo.contract.updated.sent.to.oem | The contract information (oem.contract.updated) has been sent to the OEM Backend. | "Contract information (oem.contract.updated) has been sent to the OEM Backend." |
| eMSP                | mo.contract.deleted.sent.to.oem | The contract information (oem.contract.deleted) has been sent to the OEM Backend. | "Contract information (oem.contract.deleted) has been sent to the OEM Backend." |
| eMSP                | mo.contract.delivered.to.oem | "Successfully delivery of the Contract Data. The Contract Data with the given EMAID got either:<br>- Pulled from the OEM Backend<br>- Installed over EVSE (certificateInstallationRequest)" | "Signed Contract Certificate Bundle successfully delivered to OEM or CPO-Backend" |
| eMSP                | mo.contract.rejected.by.oem | The contract information Event got rejected by the OEM Backend. A negative response of the OEM Backend about new, updated or deleted contract data was received. Action stopped in case OEM send HTTP400 or HTTP409. Otherwise, retry started to OEM. | "Info about contract Creation/Updated/Deletion (oem.contract.*) could not be delivered to OEM." |
| eMSP                | mo.contract.queued.to.oem | Retry to OEM started for (oem.contract.*). OEM Backend is not answering properly. | "Retry started in direction of the OEM Backend from Hubject for (oem.contract.*) started." |
| OEM               | oem.contract.created | Info to OEM Backend about a new Contract Data available in CCP. | "New contract available for PCID … with EMAID…." |
| OEM               | oem.contract.updated | Info to OEM Backend about the update of the Contract Data in CCP. | "Updated contract data available for PCID… with EMAID…" |
| OEM               | oem.contract.deleted | Info to OEM Backend about the deletion of Contract Data in CCP. | "Deleted contract for PCID…. With EMAID…" |

The events can assigned to your webhook service in the API:
[Event Actions](../../specifications/apis/event/event.api.v1.endpoints.json)


## API

The webhooks service requires the partner to provide a simple payload-service with public endpoint to receive events as `POST` request.
The required API documentation can be found at [webhooks.v1.json](../../../specifications/apis/event/event.api.v1.endpoints.json).


## Error handling

The webhook service has a retry mechanism in place - for http 5xx Server Errors Operator will retry 3 times in 1 hour interval, after 3 times Operator will unload the event as a failed event.

## Payload structure
```
Request: POST /payload-path HTTP/1.1
Host: your-payload-url.com
Headers:

Content-Type: application/json
X-Operator-Signature: sha256=7808b566f4057216e64c6298bfd5a184d4d715ffec6599311e5266f48865XXXX

Body:
{
    "eventId": "caf56bee-f90d-4e81-a862-7e0d0f21d306",
    "eventType": "oem.contract.created",
    "payload": {
        "emaid": "TESTEMAID",
        "pcid": "TESTPCID",
        "contractCert": "CONTRACT_CERTIFICATE_BASE64"
    }
}
```

## Validating payloads

Operator can optionally sign the webhook events it sends to the partner's endpoints by including a signature in each event’s `X-Operator-Signature` header. This allows you to verify that the events were sent by the Operator, not by a third party.

In order to validate signature a `secret` of the endpoint is needed, it will be created when a new endpoint for the webhook is created or by retrieving the endpoint from the `webhooks` backend.

Operator generates signatures using a hash-based message authentication code [HMAC](https://en.wikipedia.org/wiki/HMAC) with [SHA-256](https://en.wikipedia.org/wiki/SHA-2). To prevent [downgrade attacks](https://en.wikipedia.org/wiki/Downgrade_attack) a custom solution is described below.

Step 1: Prepare the `message` string 
- Get the actual JSON payload (i.e., the request body)

Step 2: Determine the expected signature 
- Compute an HMAC with the SHA256 hash function. Use the endpoint’s signing secret as the key, and use the Request body string as the message.

Step 3: Compare the signature
- Compare the signature in the header to the expected signature.

For example, if you have a basic server that listens for webhooks, it might be configured similar to this:
```go
import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func Payload(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("I got some JSON: " + string(b))
}
```

Recommended way is to calculate a hash using your webhooks `secret`, and ensure that the result matches the Signature from Operator. Operator uses an HMAC hex digest to compute the hash, so you could reconfigure your server to look a little like this:

```go
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func Payload(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}

	operatorSig := r.Header.Get("X-Operator-Signature")
	sig, err := hex.DecodeString(operatorSig)

	if err != nil {
		w.WriteHeader(401)
		return
	}

	secret := os.Getenv("WEBHOOK_SECRET")
	expectedSignature := ComputeSignature(b, secret)

	if !hmac.Equal(expectedSignature, sig) {
		w.WriteHeader(401)
		fmt.Println("I got some invalid signature")
		return
	}

	fmt.Println("I got some JSON with valid signature: " + string(b))
}

func ComputeSignature(payload []byte, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return mac.Sum(nil)
}
```
### Java Example
```java

    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response payload(@Context HttpServletRequest request) throws IOException {
        String body = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
        String header = request.getHeader("X-Operator-Signature");
        try {
            verifyHeader(body, header, webhookSecret);
            logger.infof("valid signature in header %s", header);
            logger.infof("received body: %s", body);
        } catch (SignatureVerificationException e) {
            logger.errorf("Invalid signature %s", e.getMessage());
            return Response.status(HttpResponseStatus.FORBIDDEN.code()).build();
        }
        return Response.ok().build();
    }

    public static void verifyHeader(String payload, String sigHeader, String secret)
            throws SignatureVerificationException {

        if (sigHeader == null || "".equals(sigHeader)) {
            throw new SignatureVerificationException("Invalid X-Operator-Signature header");
        }

        // X-Operator-Signature will come in format of sha256=ABC...XYZ
        // therefore we should split it into 2 parts and get signature value
        String operatorSig = sigHeader.split("=")[1];

        // Compute expected signature
        String expectedSignature;
        try {
            expectedSignature = computeHmacSha256(payload, secret);
        } catch (Exception e) {
            throw new SignatureVerificationException("Unable to compute signature for payload");
        }
        // Check if expected signature is equal X-Operator-Signature signature
        if (!secureCompare(expectedSignature, operatorSig)) {
            throw new SignatureVerificationException("No signatures found matching the expected signature for payload");
        }
    }

    public static boolean secureCompare(String a, String b) {
        byte[] digesta = a.getBytes(StandardCharsets.UTF_8);
        byte[] digestb = b.getBytes(StandardCharsets.UTF_8);

        return MessageDigest.isEqual(digesta, digestb);
    }

    public static String computeHmacSha256(String message, String key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = hmac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder();
        for (byte b : hash) {
            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        }
        return result.toString();
    }

    private static class SignatureVerificationException extends Exception {
        public SignatureVerificationException(String message) {
            super(message);
        }
    }
```


NOTE:
 - Using a plain == operator is not advised. A method like secure_compare performs a "constant time" string comparison, which helps mitigate certain timing attacks against regular equality operators.
