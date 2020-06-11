# Introduction

This document makes heavy use of the OWASP (Open Web Application Security Project) project.  It is best read in conjuction with the OWASP deliverables that explain acronyms, reference test procedures, and provide a glossary.

## Safe Paths

### OWASP Principles
The following principles have been derived from [OWASP principles applicable to mobile applications](https://owasp.org/www-project-mobile-security-testing-guide/), and applicable to the Safe Paths app:

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
* MSTG-STORAGE-1: System credential storage facilities need to be used to store sensitive data, such as Personally Identifiable Information (PII), user credentials or cryptographic keys. [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
* MSTG-STORAGE-2: No sensitive data should be stored outside of the app container or system credential storage facilities.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
* MSTG-STORAGE-3: No sensitive data is written to application logs.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
* MSTG-STORAGE-4: No sensitive data is shared with third parties unless it is a necessary part of the architecture.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
* MSTG-STORAGE-5: The keyboard cache is disabled on text inputs that process sensitive data.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
* MSTG-STORAGE-6: No sensitive data is exposed via IPC mechanisms.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
* MSTG-STORAGE-7: No sensitive data, such as passwords or pins, is exposed through the user interface.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
* MSTG-STORAGE-8: No sensitive data is included in backups generated by the mobile operating system.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
* MSTG-STORAGE-9: The app removes sensitive data from views when moved to the background.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/MSTSG_STORAGE.md)
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
Based on [this OWASP document](https://github.com/OWASP/ASVS/raw/master/4.0/OWASP%20Application%20Security%20Verification%20Standard%204.0-en.pdf) the correct principles have been included.  Specifically that includes Cookie-based Session Management and SOAP Web Service Verification Requirements (as we are using Tokens, and REST), Communications Security Requirements, Authentication Verification, SSRF Protection Requirements, Deployed Application Integrity Controls, Access Control, Build and Validate HTTP Request Header Requirements related requirements (as these are the responsiblity of the implementing Healthcare Authority).

#### 1.1 Secure Software Development Lifecycle Requirements
* Verify the use of threat modeling for every design change or sprint planning to identify threats, plan for countermeasures, facilitate appropriate risk responses, and guide security testing
* Verify documentation and justification of all the application's trust boundaries, components, and significant data flows
* Verify definition and security analysis of the application's high-level architecture and all connected remote services
* Verify implementation of centralized, simple (economy of design), vetted, secure, and reusable security controls to avoid duplicate, missing, ineffective, or insecure controls
* Verify availability of a secure coding checklist, security requirements, guideline, or policy to all developers and testers [![PASS](../images/pass.png?raw=true)](../README.md)

#### 1.2 Authentication Architectural Requirements
* Verify the use of unique or special low-privilege operating system accounts for all application components, services, and servers.  [![PARTIALLY TRUE](../images/partial.png?raw=true)](https://pathcheck.atlassian.net/browse/PLACES-272)
* Verify that communications between application components, including APIs, middleware and data layers, are authenticated. Components should have the least
necessary privileges needed
* Verify that the application uses a single vetted authentication mechanism that is known to be secure, can be extended to include strong authentication, and has sufficient logging and monitoring to detect account abuse or breaches
* Verify that all authentication pathways and identity management APIs implement consistent authentication security control strength, such that there are no weaker alternatives per the risk of the application

#### 1.4 Access Control Architectural Requirements
* Verify that trusted enforcement points such as at access control gateways, servers, and serverless functions enforce access controls. Never enforce access controls on the client
* Verify that the chosen access control solution is flexible enough to meet the application's needs
* Verify enforcement of the principle of least privilege in functions, data files, URLs, controllers, services, and other resources. This implies protection against spoofing and elevation of privilege
* Verify the application uses a single and well-vetted access control mechanism for accessing protected data and resources. All requests must pass through this single mechanism to avoid copy and paste or insecure alternative paths.
* Verify that attribute or feature-based access control is used whereby the code checks the user's authorization for a feature/data item rather than just their role.  Permissions should still be allocated using roles ![](../images/pass.oos?raw=true)

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
* Verify that a source code control system is in use, with procedures to ensure that check-ins are accompanied by issues or change tickets. The source code control system should have access control and identifiable users to allow traceability of any changes [![PASS](../images/pass.png?raw=true)](https://pathcheck.atlassian.net/wiki/spaces/SA/pages/50824646/2.+Contribution+Guidelines)

#### 1.11 Business Logic Architectural Requirements
* Verify the definition and documentation of all application components in terms of the business or security functions they provide
* Verify that all high-value business logic flows, including authentication, session management and access control, do not share unsynchronized state
* Verify that all high-value business logic flows, including authentication, session management and access control are thread safe and resistant to time-of-check and time-of-use race conditions

#### 1.12 Secure File Upload Architectural Requirements
* Verify that user-uploaded files are stored outside of the web root
* Verify that user-uploaded files - if required to be displayed or downloaded from the application - are served by either octet stream downloads, or from an unrelated domain, such as a cloud file storage bucket. Implement a suitable content security policy to reduce the risk from XSS vectors or other attacks from
the uploaded file

#### 1.14 Configuration Architectural Requirements
* Verify the segregation of components of differing trust levels through welldefined security controls, firewall rules, API gateways, reverse proxies, cloudbased security groups, or similar mechanisms
* Verify that if deploying binaries to untrusted devices makes use of binary signatures, trusted connections, and verified endpoints
* Verify that the build pipeline warns of out-of-date or insecure components and takes appropriate actions
* Verify that the build pipeline contains a build step to automatically build and verify the secure deployment of the application, particularly if the application infrastructure is software defined, such as cloud environment build scripts
* Verify that application deployments adequately sandbox, containerize and/or isolate at the network level to delay and deter attackers from attacking other
applications, especially when they are performing sensitive or dangerous actions such as deserialization
* Verify the application does not use unsupported, insecure, or deprecated clientside technologies such as NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets

#### 2.10 Service Authentication Requirements
* Verify that integration secrets do not rely on unchanging passwords, such as API keys or shared privileged accounts.
* Verify that if passwords are required, the credentials are not a default account.
* Verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access.
* Verify passwords, integrations with databases and third-party systems, seeds and internal secrets, and API keys are managed securely and not included in the source code or stored within source code repositories. Such storage SHOULD resist offline attacks. The use of a secure software key store (L1), hardware
trusted platform module (TPM), or a hardware security module (L3) is recommended for password storage.

#### 3.1 Fundamental Session Management Requirements

* Verify the application never reveals session tokens in URL parameters or error messages.

#### 3.2 Session Binding Requirements

* Verify the application generates a new session token on user authentication.
* Verify that session tokens possess at least 64 bits of entropy.
* Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (see section 3.4) or HTML 5 session storage.
* Verify that session token are generated using approved cryptographic algorithms.

#### 3.3 Session Logout and Timeout Requirements
* Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties
* If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period
* Verify that the application terminates all other active sessions after a successful password change, and that this is effective across the application, federated login (if present), and any relying parties.
* Verify that users are able to view and log out of any or all currently active sessions and device
* Verify that users are able to view and log out of any or all currently active sessions and devices.

#### 3.5 Token Based Session Management
* Verify the application does not treat OAuth and refresh tokens — on their own — as the presence of the subscriber and allows users to terminate trust relationships with linked applications.
* Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations.
* Verify that stateless session tokens use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.

#### 3.6 Re-authentication from a Federation or Assertion
* Verify that relying parties specify the maximum authentication time to CSPs and that CSPs re-authenticate the subscriber if they haven't used a
session within that period.
* Verify that CSPs inform relying parties of the last authentication event, to allow RPs to determine if they need to re-authenticate the user.

#### 3.7 Defenses Against Session Management Exploits
* Verify the application ensures a valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.

#### 5.1 Input Validation Requirements
* Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (GET, POST, cookies, headers, or environment variables).
* Verify that frameworks protect against mass parameter assignment attacks, or that the application has countermeasures to protect against unsafe parameter assignment, such as marking fields private or similar.
* Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (whitelisting).
* Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern (e.g. credit card numbers or telephone, or validating that two related fields are reasonable, such as checking that suburb and zip/postcode match).
* Verify that URL redirects and forwards only allow whitelisted destinations, or show a warning when redirecting to potentially untrusted content.

#### 5.2 Sanitization and Sandboxing Requirements
* Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library or framework feature.
* Verify that unstructured data is sanitized to enforce safety measures such as allowed characters and length.
* Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection.
* Verify that the application avoids the use of eval() or other dynamic code execution features. Where there is no alternative, any user input being included
must be sanitized or sandboxed before being executed.
* Verify that the application protects against template injection attacks by ensuring that any user input being included is sanitized or sandboxed.
* Verify that the application protects against SSRF attacks, by validating or sanitizing untrusted data or HTTP file metadata, such as filenames and URL input fields, use whitelisting of protocols, domains, paths and ports.
* Verify that the application sanitizes, disables, or sandboxes user-supplied SVG scriptable content, especially as they relate to XSS resulting from inline scripts, and foreignObject.
* Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as Markdown, CSS or
XSL stylesheets, BBCode, or similar.

#### 5.3 Output encoding and Injection Prevention Requirements
* Verify that output encoding is relevant for the interpreter and context required. For example, use encoders specifically for HTML values, HTML attributes,
JavaScript, URL Parameters, HTTP headers, SMTP, and others as the context requires, especially from untrusted inputs (e.g. names with Unicode or apostrophes, such as ねこ or O'Hara).
* Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and safely handled.
* Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM based XSS.
* Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected
from database injection attacks.
* Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection.
* Verify that the application projects against JavaScript or JSON injection attacks, including for eval attacks, remote JavaScript includes, CSP bypasses, DOM XSS, and JavaScript expression evaluation.
* Verify that the application protects against LDAP Injection vulnerabilities, or that specific security controls to prevent LDAP Injection have been implemented.
* Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command
line output encoding.
* Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks.
* Verify that the application protects against XPath injection or XML injection attacks.

#### 5.4 Memory, String, and Unmanaged Code Requirements
* Verify that the application uses memory-safe string, safer memory copy and
pointer arithmetic to detect or prevent stack, buffer, or heap overflows. ✓ ✓ 120
* Verify that format strings do not take potentially hostile input, and are constant. ✓ ✓ 134
* Verify that sign, range, and input validation techniques are used to prevent
integer overflows.

#### 5.5 Deserialization Prevention Requirements
* Verify that serialized objects use integrity checks or are encrypted to prevent hostile object creation or data tampering.
* Verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that unsafe features such as resolving external entities are disabled to prevent XXE.
* Verify that deserialization of untrusted data is avoided or is protected in both custom code and third-party libraries (such as JSON, XML and YAML parsers).
* Verify that when parsing JSON in browsers or JavaScript-based backends, JSON.parse is used to parse the JSON document. Do not use eval() to parse JSON.

#### 6.1 Data Classification
* Verify that regulated private data is stored encrypted while at rest, such as personally identifiable information (PII), sensitive personal information, or data assessed likely to be subject to EU's GDPR.
* Verify that regulated health data is stored encrypted while at rest, such as medical records, medical device details, or de-anonymized research records.
* Verify that regulated financial data is stored encrypted while at rest, such as financial accounts, defaults or credit history, tax records, pay history,
beneficiaries, or de-anonymized market or research records.

#### 6.2 Algorithms
* Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.
* Verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography.
* Verify that encryption initialization vector, cipher configuration, and block modes are configured securely using the latest advice.
* Verify that random number, encryption or hashing algorithms, key lengths, rounds, ciphers or modes, can be reconfigured, upgraded, or swapped at any
time, to protect against cryptographic breaks.
* Verify that known insecure block modes (i.e. ECB, etc.), padding modes (i.e. PKCS#1 v1.5, etc.), ciphers with small block sizes (i.e. Triple-DES, Blowfish, etc.), and weak hashing algorithms (i.e. MD5, SHA1, etc.) are not used unless required for backwards compatibility.
* Verify that nonces, initialization vectors, and other single use numbers must not be used more than once with a given encryption key. The method of generation must be appropriate for the algorithm being used. 6.2.7 Verify that encrypted data is authenticated via signatures, authenticated cipher modes, or HMAC to ensure that ciphertext is not altered by an unauthorized party.
* Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information.

#### 6.3 Random Values
* Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's approved
cryptographically secure random number generator when these random values are intended to be not guessable by an attacker. ✓ ✓ 338
* Verify that random GUIDs are created using the GUID v4 algorithm, and a cryptographically-secure pseudo-random number generator (CSPRNG). GUIDs created using other pseudo-random number generators may be predictable.
* Verify that random numbers are created with proper entropy even when the application is under heavy load, or that the application degrades gracefully in such circumstances.

#### 6.4 Secret Management
* Verify that a secrets management solution such as a key vault is used to securely create, store, control access to and destroy secrets.
* Verify that key material is not exposed to the application but instead uses an isolated security module like a vault for cryptographic operations.

#### 7.1 Log Content Requirements
* Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an irreversible, hashed form.
* Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy.
* Verify that the application logs security relevant events including successful and failed authentication events, access control failures, deserialization failures and input validation failures.
* Verify that each log event includes necessary information that would allow for a detailed investigation of the timeline when an event happens.

#### 7.2 Log Processing Requirements
* Verify that all authentication decisions are logged, without storing sensitive session identifiers or passwords. This should include requests with relevant
metadata needed for security investigations.
* Verify that all access control decisions can be logged and all failed decisions are logged. This should include requests with relevant metadata needed for security investigations.

#### 7.3 Log Protection Requirements
* Verify that the application appropriately encodes user-supplied data to prevent log injection.
* Verify that all events are protected from injection when viewed in log viewing software.
* Verify that security logs are protected from unauthorized access and modification.
* Verify that time sources are synchronized to the correct time and time zone.  Strongly consider logging only in UTC if systems are global to assist with post-incident forensic analysis.

#### 7.4 Error Handling
* Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate.
* Verify that exception handling (or a functional equivalent) is used across the codebase to account for expected and unexpected error conditions.
* Verify that a "last resort" error handler is defined which will catch all unhandled exceptions.

#### 8.1 General Data Protection
* Verify the application protects sensitive data from being cached in server components such as load balancers and application caches.
* Verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or purged/invalidated after the
authorized user accesses the sensitive data.
* Verify the application minimizes the number of parameters in a request, such as hidden fields, Ajax variables, cookies and header values.
* Verify the application can detect and alert on abnormal numbers of requests, such as by IP, user, total per hour or day, or whatever makes sense for the application.

#### 8.2 Client-side Data Protection
* Verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers [![PARTIALLY TRUE](../images/partial.png?raw=true)](https://pathcheck.atlassian.net/browse/PLACES-272)
* Verify that data stored in client side storage (such as HTML5 local storage, session storage, IndexedDB, regular cookies or Flash cookies) does not contain sensitive data or PII.
* Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated.

#### 8.3 Sensitive Private Data
__Note that some elements of this section have not been included, as they are privacy related and covered in elsewhere.__

* Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data.
* Verify that sensitive information contained in memory is overwritten as soon as it is no longer required to mitigate memory dumping attacks, using zeroes or random data.
* Verify that sensitive or private information that is required to be encrypted, is encrypted using approved algorithms that provide both confidentiality and integrity.

#### 9.1 Communications Security Requirements

* Verify that secured TLS is used for all client connectivity, and does not fall back to insecure or unencrypted protocols
* Verify using online or up to date TLS testing tools that only strong algorithms, ciphers, and protocols are enabled, with the strongest algorithms and ciphers set as preferred.
* Verify that old versions of SSL and TLS protocols, algorithms, ciphers, and configuration are disabled, such as SSLv2, SSLv3, or TLS 1.0 and TLS 1.1. The latest version of TLS should be the preferred cipher suite.

#### 10.1 Code Integrity Controls
* Verify that a code analysis tool is in use that can detect potentially malicious code, such as time functions, unsafe file operations and network connections.

#### 10.2 Malicious Code Search
* Verify that the application source code and third party libraries do not contain unauthorized phone home or data collection capabilities. Where such functionality exists, obtain the user's permission for it to operate before collecting any data
* Verify that the application does not ask for unnecessary or excessive permissions to privacy related features or sensors, such as contacts, cameras, microphones, or location.
* Verify that the application source code and third party libraries do not contain back doors, such as hard-coded or additional undocumented accounts or keys,
code obfuscation, undocumented binary blobs, rootkits, or anti-debugging, insecure debugging features, or otherwise out of date, insecure, or hidden functionality that could be used maliciously if discovered.
* Verify that the application source code and third party libraries does not contain time bombs by searching for date and time related functions.
* Verify that the application source code and third party libraries does not contain malicious code, such as salami attacks, logic bypasses, or logic bombs.
* Verify that the application source code and third party libraries do not contain Easter eggs or any other potentially unwanted functionality.

#### 11.1 Business Logic Security Requirements
* Verify the application will only process business logic flows for the same user in sequential step order and without skipping steps.
* Verify the application will only process business logic flows with all steps being processed in realistic human time, i.e. transactions are not submitted too quickly.
* Verify the application has appropriate limits for specific business actions or transactions which are correctly enforced on a per user basis.
* Verify the application has sufficient anti-automation controls to detect and protect against data exfiltration, excessive business logic requests, excessive file uploads or denial of service attacks.
* Verify the application has business logic limits or validation to protect against likely business risks or threats, identified using threat modelling or similar methodologies.
* Verify the application does not suffer from "time of check to time of use" (TOCTOU) issues or other race conditions for sensitive operations.
* Verify the application monitors for unusual events or activity from a business logic perspective. For example, attempts to perform actions out of order or
actions which a normal user would never attempt.
* Verify the application has configurable alerting when automated attacks or unusual activity is detected.

#### 12.1 File Upload Requirements
* Verify that the application will not accept large files that could fill up storage or cause a denial of service attack.
* Verify that compressed files are checked for "zip bombs" - small input files that will decompress into huge files thus exhausting file storage limits.
* Verify that a file size quota and maximum number of files per user is enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files.

#### 12.2 File Integrity Requirements
* Verify that files obtained from untrusted sources are validated to be of expected type based on the file's content.

#### 12.3 File execution Requirements
* Verify that user-submitted filename metadata is not used directly with system or framework file and URL API to protect against path traversal.
* Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating or removal of local files (LFI).
* Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure or execution of remote files (RFI), which may also lead to SSRF.
* Verify that the application protects against reflective file download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter, the response Content-Type header should be set to text/plain, and the Content-Disposition header should have a fixed filename.
* Verify that untrusted file metadata is not used directly with system API or libraries, to protect against OS command injection.
* Verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution networks, JavaScript libraries, node npm libraries, or server-side DLLs.

#### 12.4 File Storage Requirements
* Verify that files obtained from untrusted sources are stored outside the web root, with limited permissions, preferably with strong validation.
* Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent upload of known malicious content.

#### 12.5 File Download Requirements
* Verify that the web tier is configured to serve only files with specific file extensions to prevent unintentional information and source code leakage. For
example, backup files (e.g. .bak), temporary working files (e.g. .swp), compressed files (.zip, .tar.gz, etc) and other extensions commonly used by editors should be blocked unless required.  __note this should form guidance to HAs, rather than implemented configuration__
* Verify that direct requests to uploaded files will never be executed as HTML/JavaScript content.

#### 13.1 Generic Web Service Security Verification Requirements
* Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior that could be used in SSRF and RFI attacks.
* Verify that access to administration and management functions is limited to authorized administrators.
* Verify API URLs do not expose sensitive information, such as the API key, session tokens etc.
* Verify that authorization decisions are made at both the URI, enforced by programmatic or declarative security at the controller or router, and at the
resource level, enforced by model-based permissions.
* Verify that requests containing unexpected or missing content types are rejected with appropriate headers (HTTP response status 406 Unacceptable or 415
Unsupported Media Type).

#### 13.2 RESTful Web Service Verification Requirements
* Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT on protected API or
resources.
* Verify that JSON schema validation is in place and verified before accepting input.
* Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: triple or double submit cookie pattern (see references), CSRF nonces, or ORIGIN request header checks.
* Verify that REST services have anti-automation controls to protect against excessive calls, especially if the API is unauthenticated.
* Verify that REST services explicitly check the incoming Content-Type to be the expected one, such as application/xml or application/JSON.
* Verify that the message headers and payload are trustworthy and not modified in transit. Requiring strong encryption for transport (TLS only) may be sufficient in many cases as it provides both confidentiality and integrity protection. Per-message digital signatures can provide additional assurance on top of the transport protections for high-security applications but bring with them additional complexity and risks to weigh against the benefits.

#### 13.4 GraphQL and other Web Service Data Layer Security Requirements
* Verify that query whitelisting or a combination of depth limiting and amount limiting should be used to prevent GraphQL or data layer expression denial of
service (DoS) as a result of expensive, nested queries. For more advanced scenarios, query cost analysis should be used.
* Verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of the GraphQL layer.

#### 14.2 Dependency
* Verify that all components are up to date, preferably using a dependency checker during build or compile time.
* Verify that all unneeded features, documentation, samples, configurations are removed, such as sample applications, platform documentation, and default or
example users.
* Verify that if application assets, such as JavaScript libraries, CSS stylesheets or web fonts, are hosted externally on a content delivery network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset.
* Verify that third party components come from pre-defined, trusted and continually maintained repositories.
* Verify that an inventory catalog is maintained of all third party libraries in use.
* Verify that the attack surface is reduced by sandboxing or encapsulating third party libraries to expose only the required behaviour into the application.

#### 14.3 Unintended Security Disclosure Requirements
* Verify that web or application server and framework error messages are configured to deliver user actionable, customized responses to eliminate any
unintended security disclosures
* Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and
unintended security disclosures [![PARTIALLY TRUE](../images/partial.png?raw=true)](https://pathcheck.atlassian.net/browse/PLACES-272)
* Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components
* Verify that every HTTP response contains a content type header specifying a safe character set (e.g., UTF-8, ISO 8859-1)
* Verify that all API responses contain Content-Disposition: attachment;filename="api.json" (or other appropriate filename for the content type).
* Verify that a content security policy (CSPv2) is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection vulnerabilities.
* Verify that all responses contain X-Content-Type-Options: nosniff. [![PARTIALLY TRUE](../images/partial.png?raw=true)](https://pathcheck.atlassian.net/browse/PLACES-272)
* Verify that HTTP Strict Transport Security headers are included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800;includeSubdomains [![PARTIALLY TRUE](../images/partial.png?raw=true)](https://pathcheck.atlassian.net/browse/PLACES-272)
* Verify that a suitable "Referrer-Policy" header is included, such as "no-referrer" or "same-origin" [![PARTIALLY TRUE](../images/partial.png?raw=true)](https://pathcheck.atlassian.net/browse/PLACES-272)
* Verify that a suitable X-Frame-Options or Content-Security-Policy: frame-ancestors header is in use for sites where content should not be embedded in a
third-party site [![PARTIALLY TRUE](../images/partial.png?raw=true)](https://pathcheck.atlassian.net/browse/PLACES-272)
