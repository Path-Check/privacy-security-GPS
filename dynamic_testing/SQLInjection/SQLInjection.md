# OWASP principles in scope
Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (whitelisting).

# Endpoints in scope
* Safeplaces facing /login API endpoint, and endpoint to get a new access-code
* Public endpoint API for uploading location data

# Purpose of test
This test was to provide some assurance that these key endpoints are not vulnerable to SQL injection.  

The end-points were selected as they are accessible to someone reverse engineering the mobile application, and a contact tracer working inside a healthcare authority, and represent the only data entry point to the Safe Places system in the current release.  

The existence of a vulnerabilty may mean that bad data can be injected, existing data can be compromised, or the system can be otherwise subverted at the application code level.

The actual payloads for the attacks were based on a list of known SQL attacks from fuzzdb.

The tests require pytest, and can be run by adding "test_" to the start of the test method name in test_fuzzing.py.  For example, changing "happy_path" to "test_happy_path", then running pytest in this folder, will execute a happy path test.

# Test results
No issues were found:

* The login endpoint was tested to ensure that with any SQL injection example an error response is returned, not a login token
* The consent endpoint was tested to ensure that if any attack was sent as an access code in a payload, a failure was returned.
* The upload endpoint was tested to ensure that attacked data was not accepted or propogated into the solution when placing the attack string in latitude, longitude, time, access code or key name fields.  The trace screen was regularly checked to see if new data had been uploaded, propogated from the attacks.

# Further testing
This covers some SQL injection attackes on some priority interfaces, but could be extended to cover other endpoints and attack strings.
