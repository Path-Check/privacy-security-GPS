import unittest
import traceback
import json
from CovidApp import CovidApp

class CovidPathTests(unittest.TestCase):
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



    def jsonfuzz_login(self):
        app = CovidApp()
        with open("JSON_Fuzzing.txt") as file_in:
            lines = []
            for payload in file_in:
                print(payload)
                result = app.spl_login_post_expect_error("/login", payload)
                try:
                    token = json.loads(result['response'].read())['token']
                    print(token)
                except:
                    pass

    def jsonfuzz_get_access_code(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")
        with open("JSON_Fuzzing.txt") as file_in:
            lines = []
            for payload in file_in:
                print(payload)
                result = app.get_access_code_with_payload(payload)
                try:
                    code = json.loads(result['response'].read())['token']
                    print(code)
                except:
                    pass

    def jsonfuzz_upload(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")
        with open("JSON_Fuzzing.txt") as file_in:
            lines = []
            for payload in file_in:
                print(payload)
                code = app.get_an_access_code()
                app.user_consent(code)
                try:
                    result =  app.upload_data(code, payload)
                except Exception as e:
                    #print(result['response'].read())
                    tb = traceback.format_exc()
                    print(tb)


    def happy_path(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")
        code = app.get_an_access_code()
        app.user_consent(code)

        with open('privkit31A-synthetic-REDACTED.json', 'r') as myfile:
            data = myfile.read()
            obj = json.loads(data)

        app.upload_data(code, obj)
