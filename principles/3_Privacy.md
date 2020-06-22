# Privacy

Where a test result is recorded against a principle, the icon links to a test or issue report.

## Data Minimization

* The minimum amount of data possible shall be collected, for the purposes for which it is gathered. Data that is not used in the disclosure to healthcare authorities should not be collected unless it is essential to the purposes of the application  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* Users can choose how much data to share from symptom surveys [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)

## Consent

* A member of the public (MoP) shall be explicitly asked for consent to data being collected or transmitted. Consent should not be implied by usage, or mixed with any other consent requests  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* A MoP shall provide informed consent, that is they must be able to understand what they are consenting to and the purposes for which each category of data is gathered  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* Information about privacy shall be communicated in as simple language as possible while maintaining clarity. Specifically, legal or technical language should be avoided.  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* Consent to collect each category of data (e.g. location, proximity) shall be separate  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* No communication initiated by 3rd parties shall be provided to a MoP, through the app, without their consent  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* No data shall be shared with 3rd parties, except healthcare authorities using the agreed mechanisms
* The user of SafePaths shall be able to disable location tracking temporarily  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* Consent to disclose data to a HA shall be separate, at the time of disclosure, and contain a reference to the HA privacy policy  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* SafePlaces shall support a technical process for users to sign-off on post-redacted data  [![FAIL](../images/fail.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)

## Transparency & Accountability

* The privacy policy shall include the steps taken by the data collector to ensure the confidentiality, integrity, and quality of the data   [![PARTIALLY TRUE](../images/partial.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* The privacy policy shall identify clearly both the person who controls the data that is collected and how the data is stored and disclosed  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* No single person shall be able to both modify the source code and release the application to the public
* All source code, models and technical documentation shall be publicly available, including all dependencies
* An assessment of any residual privacy risks shall be made public in the form of a risk assessment

# Anonymization

* Location, proximity, health, race/ethnicity, gender, and any data that allows the identification of a person, shall be considered sensitive unless it is sufficiently aggregated  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* Paths followed by individuals between waypoints shall not be stored or published [![PARTIALLY TRUE](../images/partial.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* No identifiers of nearby devices shall be recorded that can be used to identify a MoP
* Healthcare authorities should have the ability to effectively redact data  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* Un-redacted data shall not be persisted by a Healthcare authority in the Safe Places web application or it’s supporting components
* Location or proximity data of less than N number of diagnosed people shall not able to be published, where N can be configured based on local legislation  [![FAIL](../images/fail.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* Precautions shall be taken to ensure that shared aggregate data may not be re-identified downstream, by ensuring that no data items are passed from SafePaths to SafePlaces that are not required (see Data Minimization)  [![PASS](../images/pass.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)
* Users should have the ability to effectively redact data themselves  [![FAIL](../images/fail.png?raw=true)](../dynamic_testing/SPL_PrivacyTesting/E2E_Privacy_Test_001.md)

# Retention & Retraction

* Retention periods shall be 14 days in the mobile application
* Retention periods shall be identified in the privacy policy
* Users shall be able to transmit a request to healthcare authorities to retract the data
* Healthcare authorities have the technical ability retract data they have published
* Retention periods for both unaggregated, and aggregated data stored in SafePlaces shall be configurable and enforced technically
* When new datasets are published from SafePlaces, older data that has passed it's retention period will be removed from the new published dataset.
* It is noted that although data will be aggregated, obfuscated, and only published for a limited amount of time, it may not be possible to guarantee that no copies of that data exist after the retention period has passed

# Other Technical Measures

* Data shall be as accurate as possible
* To protect the system against false-positive-claim attacks, the solution will establish an authorisation process between the contact tracer and the diagnosed user
* Privacy shall be as inclusive as possible, and this includes making the application work just as well for people with different abilities, wherever technically possible, and based on [W3C/WAI](https://www.w3.org/WAI/) standards
* Measures shall be taken to avoid algorithms leading to unfair outcomes for people based on immutable characteristics of people (e.g. race, gender, age) or socio-economic class This includes proxy variables such as location, which may infer these items
* The potential risk that information about people may be exposed or misused as a result of a contact tracing system must be proportional to the public health benefits of that system for combating the epidemic. The analysis of proportionality should take into account the efficacy of the contact tracing app at reducing the incidence of new cases and factors including but not limited to scope and purpose of the contact tracing app, type(s) of data collected, collection processes, sharing, retention, and deletion of data
