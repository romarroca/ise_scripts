import requests
import json
import base64
import csv

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def create_dacl_payload(name, acl_entries):
    dacl_string = '\n'.join(acl_entries)
    payload = {
        "DownloadableAcl": {
            "name": f"{name}_DACL",
            "description": "Added via ERS",
            "dacl": dacl_string,
            "daclType": "IPV4"
        }
    }
    return json.dumps(payload)

def create_authz_payload(name, vlan):
    payload = {
        "AuthorizationProfile": {
            "name": f"{name}_AUTHZ",
            "description": "added via ERS",
            "accessType": "ACCESS_ACCEPT",
            "vlan": {
                "nameID": vlan,
                "tagID": 1
            },
            "daclName": f"{name}_DACL",
        }
    }
    return json.dumps(payload)

def send_request(url, payload):
    print(f"\nHere is the JSON payload:\n{payload}")
    response = requests.post(url, headers=headers, data=payload, verify=False)
    if response.status_code == 201:
        print(f"Successfully created resource.")
    else:
        print(f"Failed to create resource. Status Code: {response.status_code}. Message: {response.text}")
        proceed = input("Do you want to continue? (yes/no): ")
        if proceed.lower() != 'yes':
            exit()

def create_airespace_authz_payload(name, vlan, airespace_acl):
    payload = {
        "AuthorizationProfile": {
            "name": f"{name}_AIRESPACE_AUTHZ",
            "description": "Added via ERS",
            "accessType": "ACCESS_ACCEPT",
            "vlan": {
                "nameID": vlan,
                "tagID": 1
            },
            "airespaceACL": airespace_acl
        }
    }
    return json.dumps(payload)

def read_airespace_csv_and_send_requests():
    with open('resources/airespace_acls.csv', 'r') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            name, vlan, airespace_acl = row

            authz_payload = create_airespace_authz_payload(name, vlan, airespace_acl)
            send_request(f'https://{ise_ip}/ers/config/authorizationprofile', authz_payload)


def read_csv_and_send_requests():
    acl_list = []
    current_name = ''
    current_vlan = ''
    
    with open('resources/dacls.csv', 'r') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            name, vlan, acl = row
            if name:
                if acl_list:
                    dacl_payload = create_dacl_payload(current_name, acl_list)
                    send_request(f'https://{ise_ip}/ers/config/downloadableacl', dacl_payload)
                    
                    authz_payload = create_authz_payload(current_name, current_vlan)
                    send_request(f'https://{ise_ip}/ers/config/authorizationprofile', authz_payload)
                    
                current_name = name
                current_vlan = vlan
                acl_list = [acl]
            else:
                acl_list.append(acl)

        if acl_list:
            dacl_payload = create_dacl_payload(current_name, acl_list)
            send_request(f'https://{ise_ip}/ers/config/downloadableacl', dacl_payload)
            
            authz_payload = create_authz_payload(current_name, current_vlan)
            send_request(f'https://{ise_ip}/ers/config/authorizationprofile', authz_payload)

def main():
    global ise_ip, headers
    ise_ip = "192.168.8.7"
    username = "ise_api"
    password = "P@ssw0rd"

    base64_credentials = base64.b64encode(f"{username}:{password}".encode('utf-8')).decode('utf-8')

    headers = {
        'Authorization': f'Basic {base64_credentials}',
        'Content-Type': 'application/json'
    }

    print("""
          This function will push profiles that uses DACLs and VLANs.
          Please define all the profiles in the resources/dacls.csv file and follow the
          format.
          """)
    begin_script = input("Do you want to continue? (yes/no): ")
    if begin_script.lower() == 'yes':
        read_csv_and_send_requests()
    else:
        print(f"Exit initial profile push")

    print("""
          This function will push profiles that uses airespaces ACLs and VLANs.
          Please define all the profiles in the resources/airespace_acls.csv file and follow the
          format.
          """)
    
    begin_script2 = input("Do you want to continue? (yes/no): ")
    if begin_script2.lower() == 'yes':
        read_airespace_csv_and_send_requests() 
    else:
        input("Thank you! Please review everything and peace out! Press any key to exit. ")

    input("Thank you! Please review everything and peace out! Press any key to exit. ")

if __name__ == "__main__":
    main()
