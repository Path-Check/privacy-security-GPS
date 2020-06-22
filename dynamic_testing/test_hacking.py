#!/usr/bin/python3
import http.client
import unittest
import json
import time

class CovidPath(unittest.TestCase):
    token = ""
    conn = http.client.HTTPSConnection("zeus.safeplaces.extremesolution.com")

    #def __init__(self):

        #jsonPayload = ...load it...https://github.com/fuzzdb-project/fuzzdb

    #Happy Path
    #response is a tuple of status code, and time to respond

    # TODO: Need a URL that returns all URLs
    # return safeplaces-backend/oas3.yaml
    # Write a test that locks the attack surface - is the OAS3 spec automatically generated

    #Test javascript injections / nodejs applications

    #Test large files - with valid data

    #Test - Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern
    #(e.g. credit card numbers or telephone, or validating that two related fields are reasonable, such as checking that suburb and zip/postcode match).

    def test_happy_path(self):
        self.login_as_contact_tracer("spladmin", "theforce")
        code = self.get_an_access_code()
        self.is_code_valid(code)
        self.user_consent(code)
        self.upload_data(code, json)

    def authenticated_post(endpoint, payload):
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'Authorization': "Bearer " + self.token,
        }

        start_time = time.time()
        self.conn.request("POST", endpoint, payload, headers)
        result = {}
        result['response'] = self.conn.getresponse()
        result['status'] = self.conn.getresponse().status
        result['duration'] = time.time() - start_time
        return validate_results(result)

    def unauthenticated_post(endpoint, payload):
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
        }
        start_time = time.time()
        self.conn.request("POST", endpoint, payload, headers)
        result = {}
        result['response'] = self.conn.getresponse()
        result['status'] = self.conn.getresponse().status
        result['duration'] = time.time() - start_time
        return validate_results(result)

    def validate_results(self, response):
        assert response['duration'] < 200
        assert response['status'] in range (200, 299)
        return response

    def login_as_contact_tracer(self, user, pw):
        payload = "{\"username\": +user, \"password\":" + pw + "}"
        result = self.unauthenticated_post("/login", payload)
        self.token = json.loads(result['response'].decode("utf-8"))['token']

    def get_an_access_code(self):
        headers = {
            'content-type': "application/json",
            'Authorization': "Bearer " + self.token,
            'cache-control': "no-cache"
        }

        self.conn.request("POST", "/access-code", "", headers)
        res = self.conn.getresponse()
        data = res.read()
        print(data)
