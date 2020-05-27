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
ToDo
