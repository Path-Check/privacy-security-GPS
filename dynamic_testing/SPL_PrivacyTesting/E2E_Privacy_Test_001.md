# Safe Places Privacy Test

## Data Minimization

* The minimum amount of data possible shall be collected, for the purposes for which it is gathered. Data that is not used in the disclosure to healthcare authorities should not be collected unless it is essential to the purposes of the application

__The data that enteres and leaves the SafePlaces system has been checked, and no data that might breach this principle was found__

* Users can choose how much data to share from symptom surveys

__Symptom surveys not in scope for this release__

## Consent

* A member of the public (MoP) shall be explicitly asked for consent to data being collected or transmitted. Consent should not be implied by usage, or mixed with any other consent requests

__Consent is sought upon application install, and upon the disclosure of data.  It is explicit and not implied.__

* A MoP shall provide informed consent, that is they must be able to understand what they are consenting to and the purposes for which each category of data is gathered

__It is clear what they are consenting to__

* Information about privacy shall be communicated in as simple language as possible while maintaining clarity. Specifically, legal or technical language should be avoided.

__The app screens use simple, non-legal language__

* Consent to collect data shall be separate from consent to disclose data, and include retention periods

__The consent on app install does not specifically say that data will only be kept for 14 days - raised [SAF-720](https://pathcheck.atlassian.net/browse/SAF-720).  Otherwise the consent is separate from disclose and collection.  Disclosure refers to to the HA privacy policy for their retention period.__

* Consent to collect each category of data (e.g. location, proximity) shall be separate

__Only location data is gathered, and the consent is explicitly for that__

* No communication initiated by 3rd parties shall be provided to a MoP, through the app, without their consent

__No mechanism has been identified that would allow this__

* The user of SafePaths shall be able to disable location tracking temporarily

__This is only possible by disabling location tracking on the device__

* Consent to disclose data to a HA shall be separate, at the time of disclosure, and contain a reference to the HA privacy policy

__This is confirmed as separate, and technical support for a link to the HA privacy policy is in place__

* SafePlaces shall support a technical process for users to sign-off on post-redacted data

__This is not in place, there is a technical prompts for a process that needs to be put in place by healthcare authorities.  A better strategic solution would be for the redacted data to be retrieved by the device (it still has the access code) and review a copy.__

## Transparency & Accountability

* The privacy policy shall include the steps taken by the data collector to ensure the confidentiality, integrity, and quality of the data
__The new PCI privacy policy does not cover this in a lot of detail, but work has started on a Data Protection Impact Assessment that will cover this__
* The privacy policy shall identify clearly both the person who controls the data that is collected and how the data is stored and disclosed
__The new PCI privacy policy does so__
* No single person shall be able to both modify the source code and release the application to the public
* All source code, models and technical documentation shall be publicly available, including all dependencies
* An assessment of any residual privacy risks shall be made public in the form of a risk assessment
__Work has started on a Data Protection Impact Assessment that will cover this__

# Anonymization

* Location, proximity, health, race/ethnicity, gender, and any data that allows the identification of a person, shall be considered sensitive unless it is sufficiently aggregated
__Pass, only location data is currently stored from this list.  It is protected in it's unaggregated form, until aggregated as a public feed.  [This request](https://pathcheck.atlassian.net/browse/PLACES-42) is open to improve the enforcement of the aggregation process__
* Paths followed by individuals between waypoints shall not be stored or published
__This information is inherent to data of individuals location data over time, but importantly, it is not maintained on publishing, as it is aggregated with other data.__
* No identifiers of nearby devices shall be recorded that can be used to identify a MoP
__TODO: Need to get into the encrypted DB to check__
* Healthcare authorities should have the ability to effectively redact data
__This is confirmed through user interface testing__
* Un-redacted data shall not be persisted by a Healthcare authority in the Safe Places web application or it’s supporting components
__TODO:  Storage test__
* Location or proximity data of less than N number of diagnosed people shall not able to be published, where N can be configured based on local legislation
__Failed, see [This request](https://pathcheck.atlassian.net/browse/PLACES-42) to improve the enforcement of the aggregation process__
* Precautions shall be taken to ensure that shared aggregate data may not be re-identified downstream, by ensuring that no data items are passed from SafePaths to SafePlaces that are not required (see Data Minimization)
__The output published file includes hashes, but not publicly readable data, and not data except aggregated points and space in time.__
* Users should have the ability to effectively redact data themselves
__Failed this is not yet in place__
