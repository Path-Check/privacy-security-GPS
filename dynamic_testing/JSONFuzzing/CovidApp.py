#!/usr/bin/python3
import http.client
import json
import time

class CovidApp():
    token = ""
    spl_url = "zeus.safeplaces.extremesolution.com"
    pe_url= "hermes.safeplaces.extremesolution.com"
    code = 0;


    def validate_results(self, response):
        print("duration" + str(response['duration']))
        assert response['duration'] < 5, "Over time.  HTTP status: " + str(response['status'])
        print("status" + str(response['status']))
        assert response['status'] in range (200, 299), "Bad HTTP status: " + str(response['status'])
        return response

    def validate_results_expect_error(self, response):
        print("duration" + str(response['duration']))
        assert response['duration'] < 70
        print("status" + str(response['status']))
        assert response['status'] in (401, 504, 500, 501, 400), "Bad HTTP status: " + str(response['status'])
        print("OK response: " + str(response['status']))
        return response

    def authenticated_post(self, endpoint, payload):
        conn = http.client.HTTPSConnection(self.spl_url)
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'Authorization': "Bearer " + self.token,
        }

        start_time = time.time()
        print("Calling " + endpoint + " payload:" + str(payload) + " headers: " + str(headers))
        conn.request("POST", endpoint, payload, headers)
        result = {}
        result['response'] = conn.getresponse()
        result['status'] = result['response'].status
        result['duration'] = time.time() - start_time
        return self.validate_results(result)

    def authenticated_post_with_payload(self, endpoint, payload):
        conn = http.client.HTTPSConnection(self.spl_url)
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'Authorization': "Bearer " + self.token,
        }

        start_time = time.time()
        print("Calling " + endpoint + " payload:" + str(payload) + " headers: " + str(headers))
        conn.request("POST", endpoint, payload, headers)
        result = {}
        result['response'] = conn.getresponse()
        result['status'] = result['response'].status
        result['duration'] = time.time() - start_time
        return self.validate_results(result)

    def public_unauthenticated_post(self, endpoint, payload):
        conn = http.client.HTTPSConnection(self.pe_url)
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
        }
        start_time = time.time()
        print("Calling " + endpoint + " payload:" + str(payload) + " headers: " + str(headers))
        conn.request("POST", endpoint, payload, headers)
        result = {}
        result['response'] = conn.getresponse()
        result['status'] = result['response'].status
        result['duration'] = time.time() - start_time
        return self.validate_results(result)

    def public_unauthenticated_post_any_result(self, endpoint, payload):
        conn = http.client.HTTPSConnection(self.pe_url)
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
        }
        start_time = time.time()
        print("Calling " + endpoint + " payload:" + str(payload) + " headers: " + str(headers))
        conn.request("POST", endpoint, payload, headers)
        result = {}
        result['response'] = conn.getresponse()
        result['status'] = result['response'].status
        result['duration'] = time.time() - start_time
        return self.validate_results(result)

    def spl_login_post(self, endpoint, payload):
        conn = http.client.HTTPSConnection(self.spl_url)
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
        }
        start_time = time.time()
        print("Calling " + endpoint + " payload:" + str(payload) + " headers: " + str(headers))
        conn.request("POST", endpoint, payload, headers)
        result = {}
        result['response'] = conn.getresponse()
        result['status'] = result['response'].status
        result['duration'] = time.time() - start_time
        return self.validate_results(result)

    def spl_login_post_expect_error(self, endpoint, payload):
        print("Calling: " + str(self.spl_url) + str(endpoint))
        conn = http.client.HTTPSConnection(self.spl_url)
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
        }
        start_time = time.time()
        conn.request("POST", endpoint, payload, headers)
        result = {}
        result['response'] = conn.getresponse()
        result['status'] = result['response'].status
        result['duration'] = time.time() - start_time
        return self.validate_results_expect_error(result)

    def login_as_contact_tracer(self, user, pw):
        payload = json.loads("{\"username\": \"" + user + "\", \"password\":\"" + pw + "\"}")
        result = self.spl_login_post("/login", json.dumps(payload))
        self.token = json.loads(result['response'].read())['token']

    def get_an_access_code(self):
        result = self.authenticated_post("/access-code", "")
        self.code = json.loads(result['response'].read())['accessCode']
        return self.code

    def get_access_code_with_payload(self, payload):
        result = self.authenticated_post_with_payload("/access-code", payload)
        self.code = json.loads(result['response'].read())['accessCode']

    def user_consent(self, code):
        payload = {}
        payload['accessCode'] = self.code
        payload['consent'] = True
        self.public_unauthenticated_post("/consent", json.dumps(payload) )

    def upload_data(self, code, json_data):
        payload = {}
        payload['accessCode'] = self.code
        payload['concernPoints'] = json_data
        result = self.public_unauthenticated_post("/upload", json.dumps(payload))
        response = result['response'].read()
        print("Response: " + response)
        return response

    def upload_data_any_result(self, code, json_data):
        payload = {}
        payload['accessCode'] = self.code
        payload['concernPoints'] = json_data
        result = self.public_unauthenticated_post_any_result("/upload", json.dumps(payload))
        response = result['response'].read()
        print("Response: " + response)
        return response
