# -*- coding: utf-8 -*-
"""
Created on Wed Oct 17 15:30:04 2018

@author: jhweaver
"""

import random
import hashlib
import base64
import requests
import json
import urllib3
import getpass
import pprint

# Disable warning re: server certificate checking turned off
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def vsaLogin():
    while True:
        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")
        
        vsa = "https:/redacted.com/api/v1.0/auth"
        random_integer = random.randint(5000, 50000)
        CoveredSHA256HashTemp_object = hashlib.sha256()
        CoveredSHA256HashTemp_object.update(('%s%s' % (password, username)).encode('utf-8'))
        CoveredSHA256HashTemp = CoveredSHA256HashTemp_object.hexdigest()
        CoveredSHA256Hash_object = hashlib.sha256()
        CoveredSHA256Hash_object.update(('%s%d' % (CoveredSHA256HashTemp, random_integer)).encode('utf-8'))
        CoveredSHA256Hash = CoveredSHA256Hash_object.hexdigest()
        CoveredSHA1HashTemp_object = hashlib.sha1()
        CoveredSHA1HashTemp_object.update(('%s%s' % (password, username)).encode('utf-8'))
        CoveredSHA1HashTemp = CoveredSHA1HashTemp_object.hexdigest()
        CoveredSHA1Hash_object = hashlib.sha1()
        CoveredSHA1Hash_object.update(('%s%d' % (CoveredSHA1HashTemp, random_integer)).encode('utf-8'))
        CoveredSHA1Hash = CoveredSHA1Hash_object.hexdigest()
        auth = "user=%s, pass2=%s, pass1=%s, rpass2=%s, rpass1=%s, rand2=%d, twofapass=:undefined" % (username, CoveredSHA256Hash, CoveredSHA1Hash, CoveredSHA1Hash, CoveredSHA256Hash, random_integer)
        encode = base64.urlsafe_b64encode(('%s' % auth).encode('UTF-8')).decode('ascii')
        headers = { 'Authorization' : 'Basic %s' %  encode }
        r = requests.get(vsa, headers=headers, verify=False)
    
        data = r.text
    
        parsed_data = json.loads(data)
        if parsed_data['ResponseCode'] == 0:
            print("\nSuccessfully logged in.\n")
            vsa_token = parsed_data['Result']['Token']
            return vsa_token
        else:
            print("Unauthorized")
            
            
def get_agent_id(session_token):
    '''
    Returns agent ID based off of machine name
    '''
       
    groupORmachine = input("Search for 1. group or 2. individual machine? ")
    
    if groupORmachine == '1':
        machines = {}
        groupName = input("Please enter the group name: ")
        call = "/assetmgmt/agents?$filter=substringof('" + groupName + "', MachineGroup)"

        r = requests.get(vsa_url + call, headers=auth_headers, verify=False)
        data = r.text
        parsed_data = json.loads(data)
        for item in parsed_data['Result']:
            if groupName in item.get('MachineGroup'):
                machines[item.get('ComputerName')] = [item.get('AgentId')]
#                if result['MachineGroup'] == groupName:
#                    machines.append(result['ComputerName'])

        print(machines)
    
    if groupORmachine == '2':
        compName = input("Please enter the machine name: ")
        call = "/assetmgmt/agents?$filter=ComputerName eq '" + compName  + "'"
        r = requests.get(vsa_url + call, headers=auth_headers, verify=False)
        data = r.text
        parsed_data = json.loads(data)
#        print(parsed_data)
        for item in parsed_data['Result']:
            if item['ComputerName'] == compName:
                return item['AgentId']
        
            
def disk_space(session_token):
    '''
    returns disk space for machines
    '''
    
    agent_id = get_agent_id(session_token)
    call = '/assetmgmt/audit/' + agent_id + '/hardware/diskvolumes'
    
    r = requests.get(vsa_url + call, headers=auth_headers, verify=False)
    data = r.text
    parsed_data = json.loads(data)
#        print(parsed_data)
#        for item in all_agents.items():
    for item in parsed_data['Result']:
        if item['Drive'] == 'C':
            print(round(int(item['FreeMBytes']) / 1024, 2), "GB free.")
#        for agents in all_agents['Result'][:5]:
#                    list_agents.append((agents['AgentName']))
#        return list_agents
            
def asset_info(session_token):
    '''
    returns asset information based off of service tag
    '''

    asset_ids = []
    skip_num = 0
    while True:
        skip_num_string = str(skip_num)
        call = "/assetmgmt/assets?$skip=%s" % skip_num_string
        r = requests.get(vsa_url + call, headers=auth_headers, verify=False)
        data = r.text
        parsed_data = json.loads(data)
        for item in parsed_data['Result']:
            asset_ids.append(item['AssetId'])
#        print(skip_num_string)
#        print(parsed_data)
        if parsed_data['Result'] == []:
            break
        skip_num += 100
        
    calls = 0
    for asset_id in asset_ids[:3]:
        call = "/assetmgmt/assets/" + asset_id
        r = requests.get(vsa_url + call, headers=auth_headers, verify=False)
        data = r.text
        parsed_data = json.loads(data)
#        for item in parsed_data['Result']:
#            for 
        pprint.pprint(parsed_data)
    print(calls)

#    print(asset_ids)
#    print(len(asset_ids))


def audit_info(session_token):
    '''
    returns asset information based off of service tag
    '''

    service_tag = input('Please input the service tag: ')
    call = "/assetmgmt/audit?$filter=SystemSerialNumber eq '" + service_tag + "'"
    

    r = requests.get(vsa_url + call, headers=auth_headers, verify=False)
    data = r.text
    parsed_data = json.loads(data)
    pprint.pprint(parsed_data)
#    for item in parsed_data['Results']:
#        if service_tag == item['SystemSerialNumber']:
#            print(item)
#        else:
#            pass

#    for item in parsed_data['Result']:
##        print(skip_num_string)
##        print(parsed_data)
#    if parsed_data['Result'] == []:
#        break


session_token = vsaLogin()
auth_headers = {'Authorization': "Bearer " + session_token}
vsa_url = "https://vsar9.intinc.com/api/v1.0/"

while True:
    print("**********************************************")
    print("Menu:")
    print("1: ")
    print("2: Disk Space")
    print("3: Get Asset Information")
    print("4: Get Audit Information")
    print("9: Exit")
    
    choice = input("What would you like to do ? ")
    print("**********************************************")

    if choice == '1':
        pass
    elif choice == '2':
        disk_space(session_token)
    elif choice == '3':
        asset_info(session_token)
    elif choice == '4':
        audit_info(session_token)
    elif choice == '9':
        break
    else:
        print("Invalid input - try again.")
        
