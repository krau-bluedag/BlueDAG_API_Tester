import tkinter as tk
from tkinter import ttk, scrolledtext, font
import requests
import base64
import json
import urllib3
import logging
import threading
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

api_endpoints = {
    "GET": {
        "/v1/evaluation/list": None,
        "/v1/evaluation/<ID>": None,
        "/v1/evaluation/describe": None,
        "/v1/finding/list": None,
        "/v1/evaluation/<EID>/finding/list": None,
        "/v1/finding/describe": None,
        "/v1/masterfinding/list": None,
        "/v1/user/list": None
    },
    "DELETE": {
        "/v1/evaluation/<ID>": None,
        "/v1/finding/<ID>": None
    },
    "POST": {
       "/v1/evaluation": json.dumps({
            "Name": "T2 Evaluation",
            "Description": "Description here.",
            "Type": "building2",
            "Standards": [24],
            "ChecklistGroup": 44,
            "InspectionType": 2,
            "Jurisdiction": [10047],
            "Address": {
                "Address": "2999 Gold Canal Dr",
                "Address2": "",
                "Apartment": "",
                "City": "Rancho Cordova",
                "State": "CA",
                "Zip": 95670,
                "ZipFour": 0,
                "Note": "",
                "Latitude": 38.0,
                "Longitude": -121.0
            },
            "Bounds": {
                "MaximumLatitude": 38.1,
                "MaximumLongitude": -121.1,
                "MinimumLatitude": 37.9,
                "MinimumLongitude": -120.9
            },
            "Stories": 2,
            "Buildings": 1,
            "BuildYear": None
        }, indent=2),
        "/v1/finding": json.dumps({
            "evaluationId": "<EID>",
            "title": "Finding Title",
            "description": "Finding Description",
            "severity": "high",
            "status": "open"
        }, indent=2),
        "/v1/evaluation/<EID>/finding": json.dumps({
            "evaluationId": "<EID>",
            "title": "Finding Title",
            "description": "Finding Description",
            "severity": "high",
            "status": "open"
        }, indent=2)
    },
    "PATCH": {
        "/v1/evaluation/<ID>": json.dumps({
            "name": "Updated Evaluation Name",
            "description": "Updated description",
            "properties": {
                "endDate": "2024-09-26"
            }
        }, indent=2),
        "/v1/finding/<ID>": json.dumps({
            "name": "Updated Evaluation Name",
            "description": "Updated description",
            "properties": {
                "endDate": "2024-09-26"
            }
        }, indent=2),
    }
}

# Globals
API_LOCATION = ""
CLIENT_ID = ""
BASIC_AUTH = ""
results = {}
evaluation_describe = {}
inspection_type_id = None
finding_describe = {}
endpoints_tested = 0
endpoints_tested_fails = 0

def get_auth_token():
    api_location = API_LOCATION.rstrip('/')
    url = f"{api_location}/services/oauth2/token"
    auth_string = base64.b64encode(f"{CLIENT_ID}:{BASIC_AUTH}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_string}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    logging.debug(f"url: " + url)
    logging.debug(f"Auth: " + json.dumps(headers, indent=2))

    response = requests.post(url, headers=headers, verify=False)
    response.raise_for_status()
    data = response.json()['data']
    return data['token'], data.get('expiresIn')

def make_api_call(verb, endpoint, payload, token):
    global endpoints_tested, endpoints_tested_fails

    # Right trim trailing slash from API_LOCATION
    api_location = API_LOCATION.rstrip('/')
    # Left trim leading slash from endpoint
    endpoint = endpoint.lstrip('/')

    url = f"{api_location}/{endpoint}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # logging.debug(f"Making API call: {verb} {url}")
    # logging.debug(f"Headers: {headers}")
    # logging.debug(f"Payload: {payload}")

    endpoints_tested += 1

    response = requests.request(verb, url, headers=headers, data=payload, verify=False)
    logging.debug(f"Response status code: {response.status_code}")
    response.raise_for_status()

    response = response.json()

    if not 'success' in response or not response['success']:
        endpoints_tested_fails += 1 

    return response

class APICallerApp:
    def __init__(self, master):
        self.master = master
        master.title("BlueDAG API Tester")
        master.geometry("700x700")
        # master.resizable(True, True)  # Allow window resizing
        # master.grid_propagate(False)  # Prevent automatic resizing

        self.base_font_size = 10
        self.current_font_size = self.base_font_size
        self.default_font = font.nametofont("TkDefaultFont")
        self.text_font = font.Font(family="TkFixedFont", size=self.current_font_size)

        self.token = None
        self.auth_timer = None

        self.payload_label = None
        self.payload_text = None
        self.create_widgets()

        # Bind zoom events
        master.bind("<Control-plus>", self.zoom_in)
        master.bind("<Control-minus>", self.zoom_out)
        master.bind("<Control-MouseWheel>", self.zoom_mouse)

        self.is_authenticated = False

    def schedule_reauth(self, expires_in):
        if hasattr(self, 'auth_timer_id'):
            self.master.after_cancel(self.auth_timer_id)

        # Schedule re-authentication 10 seconds before expiration
        reauth_time = max((expires_in - 10) * 1000, 1000)  # Convert to milliseconds
        self.auth_timer_id = self.master.after(reauth_time, self.authenticate)

    def authenticate(self):
        def auth_thread():
            try:
                global API_LOCATION, CLIENT_ID, BASIC_AUTH
                API_LOCATION = self.api_location_combo.get()
                CLIENT_ID = self.client_id_entry.get()
                BASIC_AUTH = self.basic_auth_entry.get()

                self.token, expires_in = get_auth_token()

                self.master.after(0, lambda: self.auth_success(expires_in))
            except Exception as e:
                self.master.after(0, lambda: self.auth_failure(str(e)))

        threading.Thread(target=auth_thread).start()

    def auth_success(self, expires_in):
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, f"Authentication successful! Token expires in {expires_in} seconds.")

        # Hide the authenticate button
        self.auth_button.grid_remove()

        # Disable authentication fields
        self.api_location_entry.config(state='disabled')
        self.api_location_combo.config(state='disabled')
        self.client_id_entry.config(state='disabled')
        self.basic_auth_entry.config(state='disabled')
        self.auth_button.config(state='disabled')

        # Schedule re-authentication
        if expires_in:
            self.schedule_reauth(expires_in)

        self.is_authenticated = True

    def auth_failure(self, error_message):
        logging.error(f"Authentication error: {error_message}")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, f"Authentication Error: {error_message}")

    def submit(self):
        if not self.token:
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, "Please authenticate first.")
            return

        try:
            verb = self.verb_combo.get()
            endpoint = self.endpoint_combo.get()

            payload = self.payload_text.get("1.0", tk.END).strip()
            # logging.debug(f"Verb: {verb}")
            # logging.debug(f"Endpoint: {endpoint}")
            # logging.debug(f"Payload: {payload}")

            result = make_api_call(verb, endpoint, payload, self.token)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, json.dumps(result, indent=2))
        except Exception as e:
            logging.error(f"Error occurred: {str(e)}", exc_info=True)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Error: {str(e)}")

    def zoom_in(self, event=None):
        self.change_zoom(1)

    def zoom_out(self, event=None):
        self.change_zoom(-1)

    def zoom_mouse(self, event):
        if event.delta > 0:
            self.change_zoom(1)
        else:
            self.change_zoom(-1)

    def change_zoom(self, delta):
        self.current_font_size = max(6, min(self.current_font_size + delta, 24))
        scale_factor = self.current_font_size / self.base_font_size

        # Update fonts
        self.default_font.configure(size=int(self.base_font_size * scale_factor))
        self.text_font.configure(size=self.current_font_size)

        # Update text widget fonts
        self.payload_text.configure(font=self.text_font)
        self.output_text.configure(font=self.text_font)

        # Resize window
        current_width = self.master.winfo_width()
        current_height = self.master.winfo_height()
        new_width = int(600 * scale_factor)
        new_height = int(500 * scale_factor)
        self.master.geometry(f"{new_width}x{new_height}")

        # Update layout
        self.master.update_idletasks()

    def create_widgets(self):
        # API Configuration
        ttk.Label(self.master, text="API Location:", font=self.default_font).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.api_location_entry = ttk.Entry(self.master, font=self.default_font)
        self.api_location_entry.grid(row=0, column=1, sticky="we", padx=5, pady=5)
        self.api_location_combo = ttk.Combobox(self.master, values=['https://api.dev.bluedag.com', 'https://api.staging.bluedag.com', 'https://api.bluedag.com'], font=self.default_font)
        self.api_location_combo.grid(row=0, column=1, sticky="we", padx=5, pady=5)

        ttk.Label(self.master, text="Client ID:", font=self.default_font).grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.client_id_entry = ttk.Entry(self.master, font=self.default_font)
        self.client_id_entry.grid(row=1, column=1, sticky="we", padx=5, pady=5)

        ttk.Label(self.master, text="Basic Auth:", font=self.default_font).grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.basic_auth_entry = ttk.Entry(self.master, font=self.default_font)
        self.basic_auth_entry.grid(row=2, column=1, sticky="we", padx=5, pady=5)

        # Authenticate Button
        self.auth_button = ttk.Button(self.master, text="Authenticate", command=self.authenticate)
        self.auth_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Horizontal Line
        self.separator = ttk.Separator(self.master, orient='horizontal')
        self.separator.grid(row=4, column=0, columnspan=2, sticky="we", pady=10)

        # Add Auto Test button
        self.auto_test_button = ttk.Button(self.master, text="Auto Test", command=self.auto_test)
        self.auto_test_button.grid(row=5, column=0, columnspan=2, pady=10)

        # Horizontal Line
        self.separator = ttk.Separator(self.master, orient='horizontal')
        self.separator.grid(row=6, column=0, columnspan=2, sticky="we", pady=10)

        # Rest of the form
        ttk.Label(self.master, text="HTTP Verb:", font=self.default_font).grid(row=7, column=0, sticky="w", padx=5, pady=5)
        self.verb_combo = ttk.Combobox(self.master, values=['GET', 'POST', 'PATCH', 'DELETE'], font=self.default_font, state="readonly")
        self.verb_combo.set('GET')
        self.verb_combo.grid(row=7, column=1, sticky="we", padx=5, pady=5)
        self.verb_combo.bind("<<ComboboxSelected>>", self.on_verb_change)

        ttk.Label(self.master, text="Endpoint Path:", font=self.default_font).grid(row=8, column=0, sticky="w", padx=5, pady=5)
        self.endpoint_entry = ttk.Entry(self.master, font=self.default_font)
        self.endpoint_entry.grid(row=8, column=1, sticky="we", padx=5, pady=5)
        self.endpoint_combo = ttk.Combobox(self.master, values=[], font=self.default_font)
        self.endpoint_combo.grid(row=8, column=1, sticky="we", padx=5, pady=5)
        self.endpoint_combo.bind("<<ComboboxSelected>>", self.on_endpoint_change)

        self.payload_label = ttk.Label(self.master, text="Payload (JSON):", font=self.default_font)
        self.payload_label.grid(row=9, column=0, sticky="w", padx=5, pady=5)
        self.payload_text = scrolledtext.ScrolledText(self.master, height=8, font=self.text_font)
        self.payload_text.grid(row=9, column=1, sticky="we", padx=5, pady=5)

        self.submit_button = ttk.Button(self.master, text="Submit", command=self.submit)
        self.submit_button.grid(row=10, column=0, columnspan=2, pady=10)

        self.output_text = scrolledtext.ScrolledText(self.master, height=15, font=("Courier", 10))
        self.output_text.grid(row=11, column=0, columnspan=2, sticky="we", padx=5, pady=5)
        self.output_text.config(font=("Courier", 10))

        self.master.columnconfigure(1, weight=1)
        self.master.rowconfigure(11, weight=1) # Make the row with the output text expandable

        self.on_verb_change(None)

    def on_verb_change(self, event):
        selected_verb = self.verb_combo.get()
        if selected_verb in ['GET', 'DELETE']:
            self.toggle_payload_visibility(False)
        else:
            self.toggle_payload_visibility(True)

        self.update_endpoint_options()

    def clear_payload(self):
        self.payload_text.delete("1.0", tk.END)

    def toggle_payload_visibility(self, show):
        if self.payload_label and self.payload_text:
            if show:
                self.payload_label.grid(row=9, column=0, sticky="w", padx=5, pady=5)
                self.payload_text.grid(row=9, column=1, sticky="we", padx=5, pady=5)
            else:
                self.payload_label.grid_remove()
                self.payload_text.grid_remove()

    def update_endpoint_options(self):
        selected_verb = self.verb_combo.get()
        endpoints = list(api_endpoints.get(selected_verb, {}).keys())
        self.endpoint_combo['values'] = endpoints
        if endpoints:
            self.endpoint_combo.set(endpoints[0])
            self.update_payload_text(selected_verb, endpoints[0])
        else:
            self.endpoint_combo.set('')
            self.clear_payload()

    def update_payload_text(self, verb, endpoint):
        payload_text = api_endpoints[verb][endpoint]
        if payload_text:
            self.payload_text.delete("1.0", tk.END)
            self.payload_text.insert(tk.END, payload_text)
        else:
            self.clear_payload()

    def on_endpoint_change(self, event):
        selected_verb = self.verb_combo.get()
        selected_endpoint = self.endpoint_combo.get()
        self.update_payload_text(selected_verb, selected_endpoint)

    # def update_output(self, text):
    #     self.output_text.insert(tk.END, text)
    #     self.output_text.see(tk.END)  # Scrolls to the end of the text
    #     self.master.update_idletasks()
    def update_output(self, message, success=None):
        output = f"{message:<70}"
        
        self.output_text.insert(tk.END, output)
        
        if success is not None:
            status = "Success" if success else "Failed"
            
            if success:
                self.output_text.tag_config("success", foreground="green")
                self.output_text.insert(tk.END, f"{status:>7}", "success")
            else:
                self.output_text.tag_config("failed", foreground="red")
                self.output_text.insert(tk.END, f"{status:>7}", "failed")

        self.output_text.insert(tk.END, "\n")
        self.output_text.see(tk.END)
        self.master.update_idletasks()

    def update_output_threadsafe(self, text):
        self.master.after(0, self.update_output, text)

    def _run_auto_test(self):
        try:
            global results, endpoints_tested, endpoints_tested_fails

            # Disable test and submit buttons durring auto test
            self.submit_button.config(state='disabled')
            self.auto_test_button.config(state='disabled')

            self.output_text.delete("1.0", tk.END)
            self.update_output("Begin Auto testing")

            # Clear auto test results
            results = {}
            endpoints_tested = 0
            endpoints_tested_fails = 0

            # Test GET api endpoints
            self.update_output("\nGET\n")
            self.test_get()
            self.test_describe()

            self.update_output("\nPOST\n")
            evaluation_id = self.test_post_evaluation("building2")
            finding_id = self.test_post_finding(evaluation_id)

            #building3

            #tas

            self.update_output("\nPATCH\n")
            self.test_patch_evaluation(evaluation_id, "building2")
            self.update_output("\n")
            self.test_patch_finding(finding_id, "building2")

            self.update_output("\nDELETE\n")
            self.test_delete_finding(finding_id)
            self.test_delete_evaluation(evaluation_id)

            # Summary
            self.update_output("\nResults:")
            self.update_output(f"Endpoints tested: {str(endpoints_tested)} , successes: {str(endpoints_tested - endpoints_tested_fails)} , failures: {str(endpoints_tested_fails)}")

        except Exception as e:
            self.update_output(f"An error occurred: {str(e)}")

        finally:
            # Re-neable auto test and submit buttons
            self.submit_button.config(state='normal')
            self.auto_test_button.config(state='normal')

    def auto_test(self):
        if not self.is_authenticated:
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, "Need to Authenticate First")
        else:
            # Disable buttons
            self.submit_button.config(state='disabled')
            self.auto_test_button.config(state='disabled')

            # Clear output
            self.output_text.delete("1.0", tk.END)

            # Start auto test in a separate thread
            threading.Thread(target=self._run_auto_test, daemon=True).start()  

    def test_get(self):
        global results

        endpoints = {
            "evaluation": "/v1/evaluation/list",
            "finding": "/v1/finding/list",
            "masterfinding": "/v1/masterfinding/list",
            "user": "/v1/user/list"
        }

        for key, endpoint in endpoints.items():
            result = make_api_call("GET", endpoint, None, self.token)

            success = False
            first_id = None

            if result.get("success") == True:
                if key == "user":
                    success = True
                elif result.get("data") and isinstance(result["data"], list) and len(result["data"]) > 0:
                    first_id = result["data"][0].get("ID")
                    if first_id is not None:
                        success = True

            results[endpoint] = {
                "success": success,
                "first_id": first_id
            }

        for key, result in results.items():
            #self.update_output(f"'{key}' ... {'Success' if result['success'] else 'Failed'}\n")
            self.update_output(f"'{key}'", result['success'])

        # Test Evaluation ID GET endpoint
        success = False
        if '/v1/evaluation/list' in results and results['/v1/evaluation/list']['first_id'] is not None:
            first_id = results['/v1/evaluation/list']['first_id']
            result = make_api_call("GET", f"/v1/evaluation/{first_id}", None, self.token)
            if result.get("success") == True:
                success = True

        results["/v1/evaluation/<ID>"] = {"success": success}
        #self.update_output(f"'/v1/evaluation/<ID>' ... {'Success' if success else 'Failed'}\n")
        self.update_output(f"'/v1/evaluation/<ID>'", success)

        # Test Finding ID GET endpoint
        success = False
        if '/v1/finding/list' in results and results['/v1/finding/list']['first_id'] is not None:
            first_id = results['/v1/finding/list']['first_id']
            result = make_api_call("GET", f"/v1/finding/{first_id}", None, self.token)
            if result.get("success") == True:
                success = True

        results["/v1/finding/<ID>"] = {"success": success}
        #self.update_output(f"'/v1/finding/<ID>' ... {'Success' if success else 'Failed'}\n")
        self.update_output(f"'/v1/finding/<ID>'", success)

        return results

    def test_describe(self):
        # Evaluation
        endpoint = '/v1/evaluation/describe'
        response_data = make_api_call("GET", endpoint, None, self.token)

        # Initialize the evaluation_describe dictionary
        global evaluation_describe
        evaluation_describe = {}
        global inspection_type_id
        inspection_type_id = None

        # Check if the request was successful
        if response_data['success']:
            for key, details in response_data['data'].items():
                # Skip this item if it's a system field
                if details.get('system', False):
                    continue

                evaluation_describe[key] = {}

                # Set the value based on the field type
                if details['type'] == 'text':
                    evaluation_describe[key]['value'] = key
                elif details['type'] == 'integer':
                    if 'null' in details:
                        evaluation_describe[key]['value'] = None
                    else:
                        evaluation_describe[key]['value'] = 1
                elif details['type'] in ['select', 'multiselect']:
                    evaluation_describe[key]['array'] = True
                    if 'options' in details and len(details['options']) > 0:
                        evaluation_describe[key]['value'] = details['options'][0]['value']
                    else:
                        evaluation_describe[key]['value'] = None

                    # Check for InspectionType and find the option with isTas: true
                    if key == 'InspectionType':
                        for option in details['options']:
                            if option.get('isTas', False):
                                inspection_type_id = option['value']
                                break

                # Handle permittedWhen
                if 'permittedWhen' in details:
                    for condition_key, condition_values in details['permittedWhen'].items():
                        for value in condition_values:
                            evaluation_describe[key][value] = True

                # Add required field if it's required for create
                if 'required' in details and 'create' in details['required']:
                    evaluation_describe[key]['required'] = True

        #self.update_output(f"'{endpoint}' ... {'Success' if response_data['success'] else 'Failed'}\n")
        self.update_output(f"'{endpoint}'", True if response_data['success'] else False)
        logging.debug(json.dumps(evaluation_describe, indent=2))

        # Finding
        endpoint = '/v1/finding/describe'
        response_data = make_api_call("GET", endpoint, None, self.token)

        global finding_describe
        finding_describe = {}

        # Check if the request was successful
        if response_data['success']:
            for key, details in response_data['data'].items():
                # Skip this item if it's a system field
                if details.get('system', False):
                    continue

                finding_describe[key] = {}

                # Set the value based on the field type
                if details['type'] == 'text':
                    finding_describe[key]['value'] = key
                elif details['type'] == 'integer':
                    if 'null' in details:
                        finding_describe[key]['value'] = None
                    else:
                        finding_describe[key]['value'] = 1
                elif details['type'] in ['select', 'multiselect']:
                    finding_describe[key]['array'] = True
                    if 'options' in details and len(details['options']) > 0:
                        finding_describe[key]['value'] = details['options'][0]['value']
                    else:
                        finding_describe[key]['value'] = None

                # Handle permittedWhen
                if 'permittedWhen' in details:
                    for condition_key, condition_values in details['permittedWhen'].items():
                        for value in condition_values:
                            finding_describe[key][value] = True

                # Add required field if it's required for create
                if 'required' in details and 'create' in details['required']:
                    finding_describe[key]['required'] = True

        #self.update_output(f"'{endpoint}' ... {'Success' if response_data['success'] else 'Failed'}\n")
        self.update_output(f"'{endpoint}'", True if response_data['success'] else False)
        logging.debug(json.dumps(finding_describe, indent=2))

    def test_post_evaluation(self, type):
        global evaluation_describe

        if not evaluation_describe:
            self.update_output("/v1/evaluation ... Unable to test")
            return None

        types = ["building3", "building2", "row2"]

        payload = {}
        logging.debug("[655] "+json.dumps(evaluation_describe, indent=2))
        for key, details in evaluation_describe.items():
            # Check if details has any of the fields in types
            if any(t in details for t in types):
                # If it does, check if it has the specific type field
                if type not in details:
                    continue 

            if 'required' in details and 'value' in details:
                if key == 'Standards':
                    payload[key] = [details['value'], 24] # add the 2010 ADAS so Finding has better chance of matching a MFID
                elif 'array' in details:
                    payload[key] = [details['value']]
                else:
                    payload[key] = details['value']

        payload['Address'] = {
            "Address": "2999 Gold Canal Dr",
            "Address2": "",
            "Apartment": "",
            "City": "Rancho Cordova",
            "State": "CA",
            "Zip": 95670,
            "ZipFour": 0,
            "Note": "",
            "Latitude": 38.0,
            "Longitude": -121.0
        }
        payload["Bounds"] = {
            "MaximumLatitude": 38.1,
            "MaximumLongitude": -121.1,
            "MinimumLatitude": 37.9,
            "MinimumLongitude": -120.9
        }
        response_data = None
        try:
            logging.debug("[690] "+json.dumps(payload, indent=2))
            response_data = make_api_call("POST", '/v1/evaluation', json.dumps(payload, indent=2), self.token)
            #self.update_output(f"'/v1/evaluation' ... {'Success' if response_data['success'] else 'Failed'}\n")
            logging.debug("[692] "+json.dumps(response_data, indent=2))
            self.update_output(f"'/v1/evaluation'", response_data['success'])
        except requests.exceptions.HTTPError as e:
            #self.update_output(f"'/v1/evaluation' ... Failed\n")
            logging.debug("[696] "+json.dumps(response_data, indent=2))
            self.update_output(f"'/v1/evaluation'", False)

        # Prepopulate endpoint dropdown with your new post payload
        api_endpoints['POST']['/v1/evaluation'] = json.dumps(payload, indent=2)

        eval_id = response_data['data'] if 'data' in response_data else 0

        return eval_id

    def test_post_finding(self, evaluation_id):
        global finding_describe

        #POST /v1/finding
        #POST /v1/evaluation/<EID>/finding
        if not finding_describe:
            self.update_output("/v1/finding ... Unable to test")
            return None

        payload = {}
        for key, details in finding_describe.items():
            if 'required' in details and 'value' in details:
                if 'array' in details:
                    payload[key] = [details['value']]
                else:
                    payload[key] = details['value']

        payload['EvaluationID'] = evaluation_id
        payload['MasterFindingID'] = results['/v1/masterfinding/list']['first_id']
        payload['Latitude'] = 32
        payload['Longitude'] = -121

        try:
            response_data = make_api_call("POST", '/v1/finding', json.dumps(payload, indent=2), self.token)
            #self.update_output(f"'/v1/finding' ... {'Success' if response_data['success'] else 'Failed'}\n")
            #self.update_output(f"'/v1/evaluation/<EID>/finding' ... {'Success' if response_data['success'] else 'Failed'}\n")
            self.update_output(f"'/v1/finding'", response_data['success'])
            self.update_output(f"'/v1/evaluation/<EID>/finding'", response_data['success'])
        except requests.exceptions.HTTPError as e:
            # self.update_output(f"'/v1/finding' ... Failed\n")
            # self.update_output(f"'/v1/evaluation/<EID>/finding ... Failed\n")
            self.update_output(f"'/v1/finding'", False)
            self.update_output(f"'/v1/evaluation/<EID>/finding", False)

        api_endpoints['POST']['/v1/finding'] = json.dumps(payload, indent=2)

        finding_id = response_data['data'] if 'data' in response_data else 0

        return finding_id

    def test_patch_evaluation(self, evaluation_id, type, tas=False):
        global evaluation_describe
        logging.debug(json.dumps(evaluation_describe, indent=2))

        if not evaluation_describe:
            self.update_output("/v1/evaluation/<ID> ... Unable to test")
            return None

        types = ["building3", "building2", "row2"]
        #todo: need to handle tas as well

        for key, details in evaluation_describe.items():
            payload = {}

            if key in ['Type']:
                continue

            if not 'value' in details:
                logging.debug(f"Skipping field {key}")
                continue

            if 'isTas' in details:
                continue

            # Check if details has any of the fields in types
            if any(t in details for t in types):
                # If it does, check if it has the specific type field
                if type not in details:
                    logging.debug(f"Type issue, so skipping '{key}'")
                    continue

            if 'array' in details:
                payload[key] = [details['value']]
            else:
                payload[key] = details['value']

            try:
                response_data = make_api_call("PATCH", f'/v1/evaluation/{evaluation_id}', json.dumps(payload, indent=2), self.token)
                #self.update_output(f"'/v1/evaluation/<ID>' update '{key}' ... {'Success' if response_data['success'] else 'Failed'}\n")
                self.update_output(f"'/v1/evaluation/<ID>' update '{key}'", response_data['success'])
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    self.update_output(f"Rate limit exceeded. Waiting before retrying...")
                    time.sleep(3)  # Wait for X seconds before retrying
                    continue
                else:
                    #self.update_output(f"'/v1/evaluation/<ID>' update '{key}' ... Failed\n")
                    self.update_output(f"'/v1/evaluation/<ID>' update '{key}'", False)
                    continue

            # Add a small delay between requests to avoid hitting rate limits
            time.sleep(1)  # Wait for 1 second between requests

    def test_patch_finding(self, finding_id, eval_type):
        global finding_describe

        if not finding_describe:
            self.update_output("/v1/finding/<ID> ... Unable to test")
            return None

        types = ["building3", "building2", "row2"]

        for key, details in finding_describe.items():
            logging.debug(f"(findings) testing '{key}'")
            payload = {}

            if key in ['EvaluationID', 'MasterFindingID']:
                continue

            if not 'value' in details:
                logging.debug(f"Skipping field {key}")
                continue

            # Check if details has any of the fields in types
            if any(t in details for t in types):
                # If it does, check if it has the specific type field
                if eval_type not in details:
                    logging.debug(f"Type issue, so skipping '{key}'")
                    continue

            if 'array' in details:
                payload[key] = [details['value']]
            else:
                payload[key] = details['value']

            try:
                response_data = make_api_call("PATCH", f'/v1/finding/{finding_id}', json.dumps(payload, indent=2), self.token)
                #self.update_output(f"'/v1/finding/<ID>' update '{key}' ... {'Success' if response_data['success'] else 'Failed'}\n")
                self.update_output(f"'/v1/finding/<ID>' update '{key}'", response_data['success'])
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    self.update_output(f"Rate limit exceeded. Waiting before retrying...")
                    time.sleep(3)
                    continue
                else:
                    #self.update_output(f"'/v1/finding/<ID>' update '{key}' ... Failed\n")
                    self.update_output(f"'/v1/finding/<ID>' update '{key}'", False)
                    continue

            # Add a small delay between requests to avoid hitting rate limits
            time.sleep(1)  # Wait for 1 second between requests

    def test_delete_evaluation(self, evaluation_id):
        if not evaluation_id:
            self.update_output(f"DELETE '/v1/evaluation/<ID>' ... No ID provided")
            return

        response_data = make_api_call("DELETE", f'/v1/evaluation/{evaluation_id}', None, self.token)
        #self.update_output(f"'/v1/evaluation/<ID>' ... {'Success' if response_data['success'] else 'Failed'}\n")
        self.update_output(f"'/v1/evaluation/<ID>'", response_data['success'])

    def test_delete_finding(self, finding_id):
        if not finding_id:
            self.update_output(f"DELETE '/v1/finding/<ID>' ... No ID provided")
            return

        response_data = make_api_call("DELETE", f'/v1/finding/{finding_id}', None, self.token)
        #self.update_output(f"'/v1/finding/<ID>' ... {'Success' if response_data['success'] else 'Failed'}\n")
        self.update_output(f"'/v1/finding/<ID>'", response_data['success'])
      


root = tk.Tk()
app = APICallerApp(root)
root.mainloop()