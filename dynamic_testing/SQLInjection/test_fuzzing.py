import unittest
import traceback
import json
import random
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


    def sqlfuzz_upload_random(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")

        #load base data
        with open('privkit31A-synthetic-REDACTED.json', 'r') as myfile:
            data = myfile.read()
            obj = json.loads(data)

        #load fuzz patterns
        with open("xplatform.txt") as file_in:
            lines = []
            for fuzz in file_in:
                code = app.get_an_access_code()
                app.user_consent(code)
                try:
                    # insert the SQL injection at a random location in the payload
                    n = random.randint(1,len(obj))
                    left = str(obj[:n])
                    right = str(obj[n:])
                    new_payload = left + fuzz + right
                    result =  app.upload_data_expect_error(code, new_payload)
                except Exception as e:
                    tb = traceback.format_exc()
                    print(tb)
                    try:
                        print(result['response'].read())
                    except:
                        pass


    def sqlfuzz_upload_time(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")

        #load base data
        with open('privkit31A-synthetic-REDACTED.json', 'r') as myfile:
            data = myfile.read()
            obj = json.loads(data)

        #load fuzz patterns
        with open("xplatform.txt") as file_in:
            lines = []
            for fuzz in file_in:
                code = app.get_an_access_code()
                app.user_consent(code)
                try:
                    # insert the SQL injection at a random location in the payload
                    new_payload = json.dumps(obj).replace('1583069740422', fuzz)
                    result =  app.upload_data_expect_error(code, new_payload)
                except Exception as e:
                    tb = traceback.format_exc()
                    print(tb)
                    try:
                        print(result['response'].read())
                    except:
                        pass


    def sqlfuzz_upload_lat(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")

        #load base data
        with open('privkit31A-synthetic-REDACTED.json', 'r') as myfile:
            data = myfile.read()
            obj = json.loads(data)

        #load fuzz patterns
        with open("xplatform.txt") as file_in:
            lines = []
            for fuzz in file_in:
                code = app.get_an_access_code()
                app.user_consent(code)
                try:
                    # insert the SQL injection at a random location in the payload
                    new_payload = json.dumps(obj).replace('51.53839304439309', fuzz)
                    result =  app.upload_data_expect_error(code, new_payload)
                except Exception as e:
                    tb = traceback.format_exc()
                    print(tb)
                    try:
                        print(result['response'].read())
                    except:
                        pass

    def sqlfuzz_upload_colname(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")

        #load base data
        with open('privkit31A-synthetic-REDACTED.json', 'r') as myfile:
            data = myfile.read()
            obj = json.loads(data)

        #load fuzz patterns
        with open("xplatform.txt") as file_in:
            lines = []
            for fuzz in file_in:
                code = app.get_an_access_code()
                app.user_consent(code)
                try:
                    # insert the SQL injection at a random location in the payload
                    new_payload = json.dumps(obj).replace('time', fuzz)
                    result =  app.upload_data_expect_error(code, new_payload)
                except Exception as e:
                    tb = traceback.format_exc()
                    print(tb)
                    try:
                        print(result['response'].read())
                    except:
                        pass


    def sqlfuzz_upload_lon(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")

        #load base data
        with open('privkit31A-synthetic-REDACTED.json', 'r') as myfile:
            data = myfile.read()
            obj = json.loads(data)

        #load fuzz patterns
        with open("xplatform.txt") as file_in:
            lines = []
            for fuzz in file_in:
                code = app.get_an_access_code()
                app.user_consent(code)
                try:
                    # insert the SQL injection at a random location in the payload
                    new_payload = json.dumps(obj).replace('-0.11477509793272855', fuzz)
                    result =  app.upload_data_expect_error(code, new_payload)
                except Exception as e:
                    tb = traceback.format_exc()
                    print(tb)
                    try:
                        print(result['response'].read())
                    except:
                        pass

    def test_sqlfuzz_access_code(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")

        #load base data
        with open('privkit31A-synthetic-REDACTED.json', 'r') as myfile:
            data = myfile.read()
            obj = json.loads(data)

        #load fuzz patterns
        with open("xplatform.txt") as file_in:
            for fuzz in file_in:
                code = app.get_an_access_code()
                app.user_consent_expect_error(fuzz)

    def happy_path(self):
        app = CovidApp()
        app.login_as_contact_tracer("spladmin", "password")
        code = app.get_an_access_code()
        app.user_consent(code)

        with open('privkit31A-synthetic-REDACTED.json', 'r') as myfile:
            data = myfile.read()
            obj = json.loads(data)

        app.upload_data(code, obj)
