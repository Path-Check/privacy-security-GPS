# OWASP principles in scope
Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (whitelisting).

# Endpoints in scope

* Safeplaces facing /login endpoint, and endpoint to get a new access-code
* Public endpoint for uploading location data

# Purpose of test
This test was to provide some assurance that these key endpoints are not vulnerable to JSON injection.  Based on a list of known attacks from fuzzdb.

The tests require pytest, and can be run by adding "test_" to the start of the methods name in test_fuzzing.py.  For example, changing "happy_path" to "test_happy_path", then running pytest in this folder, will execute a happy path test.

# Test results
* The login endpoint was tested to ensure that with any JSON Fuzz example an error response is returned, not a login token
* The access-code endpoint was tested to ensure that if any fuzz example was sent, an access code was still provided (as the POST payload is not used).  This test failed as 4xx errors were seen.  [See jira.}(https://pathcheck.atlassian.net/browse/PLACES-423?atlOrigin=eyJpIjoiNDNjYmIyMTEwN2Q1NDBlNjg3YWFmZTU4YmM0NjExYWUiLCJwIjoiaiJ9)
* The upload endpoint was tested to ensure that fuzz data was not propogated into the solution.  In some instances the data was accepted (2xx response), and I checked in the UI that out of all the posted fuzz examples, only one actually ended up inside the database (and accessible through the UI), and this was simply empty, rather than holding corrupt data
