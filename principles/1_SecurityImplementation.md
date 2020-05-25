# Introduction

## Safe Paths

### OWASP Principles
The following principles have been derived from OWASP (Open Web Application Security Project) principles applicable to mobile applications, and applicable to the Safe Paths app:

* MSTG-ARCH-1 All app components are identified and known to be needed.
* MSTG-ARCH-2 Security controls are never enforced only on the client side, but on the respective remote endpoints.
* MSTG-ARCH-3 A high-level architecture for the mobile app and all connected remote services has been defined and security has been addressed in that architecture
* MSTG-ARCH-4 Data considered sensitive in the context of the mobile app is clearly identified.
* MSTG-ARCH-5 All app components are defined in terms of the business functions and/or security functions they provide.
* MSTG-ARCH-6 A threat model for the mobile app and the associated remote services has been produced that identifies potential threats and countermeasures.
* MSTG-ARCH-8 There is an explicit policy for how cryptographic keys (if any) are managed, and the lifecycle of cryptographic keys is enforced. Ideally, follow a key management standard such as NIST SP 800-57.
* MSTG-ARCH-10 Security is addressed within all parts of the software development lifecycle.
* MSTG-CRYPTO-1 The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption.
* MSTG-CRYPTO-2 The app uses proven implementations of cryptographic primitives.
* MSTG-CRYPTO-3 The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices.
* MSTG-CRYPTO-4 The app does not use cryptographic protocols or algorithms that are widely considered deprecated for security purposes.
* MSTG-CRYPTO-5 The app doesn’t re-use the same cryptographic key for multiple purposes.
* MSTG-CRYPTO-6 All random values are generated using a sufficiently secure random number generator.
* MSTG-NETWORK-1 Data is encrypted on the network using Transport Level Security (TLS). The secure channel is used consistently throughout the app.
* MSTG-NETWORK-2 The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards.
* MSTG-NETWORK-3 The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted Certificate Authority (CA) are accepted.
* MSTG-NETWORK-6 The app only depends on up-to-date connectivity and security libraries.
* MSTG-PLATFORM-1 The app only requests the minimum set of permissions necessary
* MSTG-PLATFORM-2 All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the User Interface (UI), Inter-Process Communication (IPC) mechanisms such as intents, custom Uniform Resource Locators (URLs), and network sources.
* MSTG-PLATFORM-3 The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected.
* MSTG-PLATFORM-4 The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected.
* MSTG-PLATFORM-5 JavaScript is disabled in WebViews unless explicitly required.
* MSTG-PLATFORM-6 WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled.
* MSTG-PLATFORM-7 If native methods of the app are exposed to a WebView, verify that the WebView only renders JavaScript contained within the app package.
* WebView should not have debugging mode enabled in the App release.
* MSTG-PLATFORM-8 Object deserialization, if any, is implemented using safe serialization Application Programming Interfaces (APIs).
* MSTG-CODE-1 The app is signed and provisioned with a valid certificate, of which the private key is properly protected.
* MSTG-CODE-2 The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable).
* MSTG-CODE-3 Debugging symbols have been removed from native binaries.
* MSTG-CODE-4 Debugging code and developer assistance code (e.g. test code, backdoors, hidden settings) have been removed. The app does not log verbose errors or debugging messages.
* MSTG-CODE-5 All third party components used by the mobile app, such as libraries and frameworks, are identified, and checked for known vulnerabilities.
* MSTG-CODE-6 The app catches and handles possible exceptions.
* MSTG-CODE-7 Error handling logic in security controls denies access by default.
* MSTG-CODE-8 In unmanaged code, memory is allocated, freed and used securely.
* MSTG-CODE-9 Free security features offered by the toolchain, such as byte-code minification, stack protection, Position Independent Executable (PIE) support and automatic reference counting, are activated.
* MSTG-STORAGE-1: System credential storage facilities need to be used to store sensitive data, such as Personally Identifiable Information (PII), user credentials or cryptographic keys.
* MSTG-STORAGE-2: No sensitive data should be stored outside of the app container or system credential storage facilities.
* MSTG-STORAGE-3: No sensitive data is written to application logs.
* MSTG-STORAGE-4: No sensitive data is shared with third parties unless it is a necessary part of the architecture.
* MSTG-STORAGE-5: The keyboard cache is disabled on text inputs that process sensitive data.
* MSTG-STORAGE-6: No sensitive data is exposed via IPC mechanisms.
* MSTG-STORAGE-7: No sensitive data, such as passwords or pins, is exposed through the user interface.
* MSTG-STORAGE-8: No sensitive data is included in backups generated by the mobile operating system.
* MSTG-STORAGE-9: The app removes sensitive data from views when moved to the background.
* MSTG-STORAGE-10 The app does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use.
* At startup, rooting should be checked for in order to protect user devices against being controlled by malicious software and their personal data accessed.  If rooting is found, the user should be notified of the specific risk.
* Data should not be stored in files in plaintext at any point

## Safe Places

### General

* Whilst Safe Places deployment security best practices are the responsibility of the healthcare authority, developers shall make every effort to encourage healthcare authorities to deploy in a secure way, through documentation and technical means
* Access to sensitive data shall be logged and made visible to users
* Security and data access logs shall be immutable
* Aggregated data published from Safe Places shall not be accessible in plain text to a layman user or malicious actor
* Aggregated data published from Safe Places shall be obfuscated or encrypted so that concern points cannot be accessed

### OWASP Principles

Based on [this OWASP document](https://github.com/OWASP/ASVS/raw/master/4.0/OWASP%20Application%20Security%20Verification%20Standard%204.0-en.pdf)

#### 1.1 Secure Software Development Lifecycle Requirements

* Verify the use of threat modeling for every design change or sprint planning to identify threats, plan for countermeasures, facilitate appropriate risk responses, and guide security testing
* Verify documentation and justification of all the application's trust boundaries, components, and significant data flows
* Verify definition and security analysis of the application's high-level architecture and all connected remote services
* Verify implementation of centralized, simple (economy of design), vetted, secure, and reusable security controls to avoid duplicate, missing, ineffective, or insecure controls
* Verify availability of a secure coding checklist, security requirements, guideline, or policy to all developers and testers

#### 1.2 Authentication Architectural Requirements
* Verify the use of unique or special low-privilege operating system accounts for all application components, services, and servers.
* Verify that communications between application components, including APIs, middleware and data layers, are authenticated. Components should have the least
necessary privileges needed
* Verify that the application uses a single vetted authentication mechanism that is known to be secure, can be extended to include strong authentication, and has sufficient logging and monitoring to detect account abuse or breaches
* Verify that all authentication pathways and identity management APIs implement consistent authentication security control strength, such that there are no weaker alternatives per the risk of the application

#### 1.4 Access Control Architectural Requirements
* Verify that trusted enforcement points such as at access control gateways, servers, and serverless functions enforce access controls. Never enforce access controls on the client
* Verify that the chosen access control solution is flexible enough to meet the application's needs
* Verify enforcement of the principle of least privilege in functions, data files, URLs, controllers, services, and other resources. This implies protection against spoofing and elevation of privilege
* Verify the application uses a single and well-vetted access control mechanism for accessing protected data and resources. All requests must pass through this single mechanism to avoid copy and paste or insecure alternative paths.
* Verify that attribute or feature-based access control is used whereby the code checks the user's authorization for a feature/data item rather than just their role.  Permissions should still be allocated using roles

#### 1.5 Input and Output Architectural Requirements
* Verify that input and output requirements clearly define how to handle and process data based on type, content, and applicable laws, regulations, and other
policy compliance
* Verify that serialization is not used when communicating with untrusted clients. If this is not possible, ensure that adequate integrity controls (and possibly encryption if sensitive data is sent) are enforced to prevent deserialization attacks including object injection
* Verify that input validation is enforced on a trusted service layer
* Verify that output encoding occurs close to or by the interpreter for which it is intended.
* Verify that there is an explicit policy for management of cryptographic keys and that a cryptographic key lifecycle follows a key management standard such as NIST SP 800-57
* Verify that consumers of cryptographic services protect key material and other secrets by using key vaults or API based alternatives
* Verify that all keys and passwords are replaceable and are part of a well-defined process to re-encrypt sensitive data
* Verify that symmetric keys, passwords, or API secrets generated by or shared with clients are used only in protecting low risk secrets, such as encrypting local storage, or temporary ephemeral uses such as parameter obfuscation. Sharing secrets with clients is clear-text equivalent and architecturally should be treated as such.

#### 1.7 Errors, Logging and Auditing Architectural Requirements
* Verify that a common logging format and approach is used across the system
* Verify that logs are securely transmitted to a preferably remote system for analysis, detection, alerting, and escalation

#### 1.8 Data Protection and Privacy Architectural Requirements
* Verify that all sensitive data is identified and classified into protection levels
* Verify that all protection levels have an associated set of protection requirements, such as encryption requirements, integrity requirements, retention, privacy and other confidentiality requirements, and that these are applied in the architecture

#### V1.9 Communications Architectural Requirements
* Verify the application encrypts communications between components, particularly when these components are in different containers, systems, sites, or
cloud providers
* Verify that application components verify the authenticity of each side in a communication link to prevent person-in-the-middle attacks. For example, application components should validate TLS certificates and chains

#### 1.10 Malicious Software Architectural Requirements
* Verify that a source code control system is in use, with procedures to ensure that check-ins are accompanied by issues or change tickets. The source code control system should have access control and identifiable users to allow traceability of any changes

#### 1.11 Business Logic Architectural Requirements
* Verify the definition and documentation of all application components in terms of the business or security functions they provide
* Verify that all high-value business logic flows, including authentication, session management and access control, do not share unsynchronized state
* Verify that all high-value business logic flows, including authentication, session management and access control are thread safe and resistant to time-of-check and time-of-use race conditions

#### 1.12 Secure File Upload Architectural Requirements
* Verify that user-uploaded files are stored outside of the web root.
* Verify that user-uploaded files - if required to be displayed or downloaded from the application - are served by either octet stream downloads, or from an unrelated domain, such as a cloud file storage bucket. Implement a suitable content security policy to reduce the risk from XSS vectors or other attacks from
the uploaded file.

#### 1.14 Configuration Architectural Requirements
* Verify the segregation of components of differing trust levels through welldefined security controls, firewall rules, API gateways, reverse proxies, cloudbased security groups, or similar mechanisms.
* Verify that if deploying binaries to untrusted devices makes use of binary signatures, trusted connections, and verified endpoints.
* Verify that the build pipeline warns of out-of-date or insecure components and takes appropriate actions.
* Verify that the build pipeline contains a build step to automatically build and verify the secure deployment of the application, particularly if the application infrastructure is software defined, such as cloud environment build scripts.
* Verify that application deployments adequately sandbox, containerize and/or isolate at the network level to delay and deter attackers from attacking other
applications, especially when they are performing sensitive or dangerous actions such as deserialization.
* Verify the application does not use unsupported, insecure, or deprecated clientside technologies such as NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets.

# 2.1 Password Security Requirements
* Verify that user set passwords are at least 12 characters in length
* Verify that passwords 64 characters or longer are permitted
* Verify that passwords can contain spaces and truncation is not performed. Consecutive multiple spaces MAY optionally be coalesced
* Verify that Unicode characters are permitted in passwords. A single Unicode code point is considered a character, so 12 emoji or 64 kanji characters should be valid and permitted
* Verify users can change their password
* Verify that password change functionality requires the user's current and new password
* Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords either locally (such as the top 1,000 or 10,000 most common passwords which match the system's password policy) or using an external API. If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. If the password is breached, the application must require the user to set a new nonbreached password
* Verify that a password strength meter is provided to help users set a stronger password
* Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters
* Verify that there are no periodic credential rotation or password history requirements.
* Verify that "paste" functionality, browser password helpers, and external password managers are permitted.
* Verify that the user can choose to either temporarily view the entire masked password, or temporarily view the last typed character of the password on platforms that do not have this as native functionality.
