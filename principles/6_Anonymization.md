# Anonymization

* Location, proximity, health, race/ethnicity, gender, and any data that allows the identification of a person, shall be considered sensitive unless it is sufficiently aggregated.
* Paths between waypoints shall not be stored or published
* No identifiers of nearby devices shall be recorded that can be used to identify a MoP
* Healthcare authorities should have the ability to effectively redact data
* Un-redacted data shall not be persisted by a Healthcare authority in the Safe Places web application or it’s supporting components
* Location or proximity data of less than N number of diagnosed people shall not able to be published, where N can be configured based on local legislation
* Precautions shall be taken to ensure that shared aggregate data may not be re-identified downstream, by ensuring that no data items are passed from SafePaths to SafePlaces that are not required (see DM2)
* Users should have the ability to effectively redact data themselves
