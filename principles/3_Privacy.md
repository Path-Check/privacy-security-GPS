# Privacy

## Data Minimization

* The minimum amount of data possible shall be collected, for the purposes for which it is gathered. Data that is not used in the disclosure to healthcare authorities should not be collected unless it is essential to the purposes of the application
* Users can choose how much data to share from symptom surveys

## Consent
* A member of the public (MoP) shall consent to data being collected or transmitted explicitly, that is it should not be implied by usage, or mixed with another consent
* A MoP shall provide informed consent, that is they must be able to understand what they are consenting to and the purposes for which each category of data is gathered
* Information about privacy shall be communicated in plain English, not legal, or technical language
* Consent to collect data shall be separate from consent to disclose data, and include retention periods
* Consent to collect each category of data (e.g. location, proximity) shall be separate
* No communication initiated by 3rd parties shall be provided to a MoP, through the app, without their consent
* No data shall be shared with 3rd parties, except healthcare authorities using the agreed mechanisms
* The user of SafePaths shall be able to disable location tracking temporarily
* Consent to disclose data to a HA shall be separate, at the time of disclosure, and contain a reference to the HA privacy policy

## Transparency & Accountability

* The privacy policy shall include the steps taken by the data collector to ensure the confidentiality, integrity, and quality of the data
* The data controller, that is, who controls what data is collected and how it is stored and disclosed shall be identified clearly
* No single person shall be able to modify the source code and release the application to the public
* All source code, models and technical documentation shall be publicly available, including all dependencies
* An assessment of any residual privacy risks shall be made public in the form of a risk assessment

# Anonymization

* Location, proximity, health, race/ethnicity, gender, and any data that allows the identification of a person, shall be considered sensitive unless it is sufficiently aggregated
* Paths between waypoints shall not be stored or published
* No identifiers of nearby devices shall be recorded that can be used to identify a MoP
* Healthcare authorities should have the ability to effectively redact data
* Un-redacted data shall not be persisted by a Healthcare authority in the Safe Places web application or it’s supporting components
* Location or proximity data of less than N number of diagnosed people shall not able to be published, where N can be configured based on local legislation
* Precautions shall be taken to ensure that shared aggregate data may not be re-identified downstream, by ensuring that no data items are passed from SafePaths to SafePlaces that are not required (see DM2)
* Users should have the ability to effectively redact data themselves

# Retention & Retraction

* Retention periods shall be 14 days in the mobile application
* Retention periods shall be in the privacy policy
* Users shall be able to transmit a request to healthcare authorities to retract the data
* Healthcare authorities have the technical ability retract data they have published
* SafePlaces shall support a technical process for users to sign-off on post-redacted data.
* Retention periods in SafePlaces shall be configurable and enforced technically

# Other Technical Measures
* Data shall be as accurate as possible
* Privacy shall be as inclusive as possible, and this includes making the application work just as well for people with different abilities, wherever technically possible, and based on W3C/WAI standards
* Measures shall be taken to avoid algorithms leading to unfair outcomes for people based on immutable characteristics of people (e.g. race, gender, age) or socio-economic class This includes proxy variables such as location, which may infer these items
* The potential risk that information about people may be exposed or misused as a result of a contact tracing system must be proportional to the public health benefits of that system for combating the epidemic. The analysis of proportionality should take into account the efficacy of the contact tracing app at reducing the incidence of new cases and factors including but not limited to scope and purpose of the contact tracing app, type(s) of data collected, collection processes, sharing, retention, and deletion of data
