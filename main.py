from __future__ import print_function
import json
import requests
import configparser
import os
import re

requests.packages.urllib3.disable_warnings()  # Added to avoid warnings in output if proxy


def return_error(message):
    print("\nERROR: " + message)
    exit(1)


def get_parser_from_sections_file(file_name):
    file_parser = configparser.ConfigParser()
    try:  # Checks if the file has the proper format
        file_parser.read(file_name)
    except (ValueError, configparser.MissingSectionHeaderError, configparser.DuplicateOptionError,
            configparser.DuplicateOptionError):
        return_error("Unable to read file " + file_name)
    return file_parser


def read_value_from_sections_file(file_parser, section, option):
    value = {}
    value['Exists'] = False
    if file_parser.has_option(section, option):  # Checks if section and option exist in file
        value['Value'] = file_parser.get(section, option)
        if not value['Value'] == '':  # Checks if NOT blank (so properly updated)
            value['Exists'] = True
    return value


def read_value_from_sections_file_and_exit_if_not_found(file_name, file_parser, section, option):
    value = read_value_from_sections_file(file_parser, section, option)
    if not value['Exists']:
        return_error("Section \"" + section + "\" and option \"" + option + "\" not found in file " + file_name)
    return value['Value']


def load_api_config(iniFilePath):
    if not os.path.exists(iniFilePath):
        return_error("Config file " + iniFilePath + " does not exist")
    iniFileParser = get_parser_from_sections_file(iniFilePath)
    api_config = {}
    api_config['BaseURL'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser, 'URL',
                                                                                'URL')
    api_config['AccessKey'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser,
                                                                                  'AUTHENTICATION', 'ACCESS_KEY_ID')
    api_config['SecretKey'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser,
                                                                                  'AUTHENTICATION', 'SECRET_KEY')
    api_config['tenantId'] =  read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser, 'AZURESP','tenantId')
    api_config['clientId'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser, 'AZURESP',
                                                                                'clientId')
    api_config['servicePrincipalId'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser, 'AZURESP',
                                                                                'servicePrincipalId')

    return api_config


def handle_api_response(apiResponse):
    status = apiResponse.status_code
    if (status != 200):
        return_error("API call failed with HTTP response " + str(status))


def run_api_call_with_payload(action, url, headers_value, payload):
    apiResponse = requests.request(action, url, headers=headers_value, data=json.dumps(payload),
                                   verify=False)  # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse


def run_api_call_without_payload(action, url, headers_value):
    apiResponse = requests.request(action, url, headers=headers_value,
                                   verify=False)  # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse


def login(api_config):
    action = "POST"
    url = api_config['BaseURL'] + "/login"
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        'username': api_config['AccessKey'],
        'password': api_config['SecretKey'],
    }
    apiResponse = run_api_call_with_payload(action, url, headers, payload)
    authentication_response = apiResponse.json()
    token = authentication_response['token']
    return token


### APIs to interact  with  Account Groups ###

def get_account_groups(api_config):
    action = "GET"
    url = api_config['BaseURL'] + "/cloud/group"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload(action, url, headers)
    accountGroups = json.loads(apiResponse.text)
    return accountGroups


def update_account_group(api_config, accountGroupName, accountGroupId, accountIds, description):
    action = "PUT"
    url = api_config['BaseURL'] + "/cloud/group/" + accountGroupId
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    payload = {
        'accountIds': accountIds,
        'name': accountGroupName,
        'description': description
    }
    run_api_call_with_payload(action, url, headers, payload)


def create_account_group(api_config, accountGroupName, accountIds, description):
    action = "POST"
    url = api_config['BaseURL'] + "/cloud/group/"
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    payload = {
        'accountIds': accountIds,
        'name': accountGroupName,
        'description': description
    }
    run_api_call_with_payload(action, url, headers, payload)


def delete_account_group(api_config, accountGroupId):
    action = "DELETE"
    url = api_config['BaseURL'] + "/cloud/group/" + accountGroupId
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    run_api_call_with_payload(action, url, headers)

def get_child_parent_azure (api_config, tenantId, parentId,clienId,servicePrincipalId):
    action = "POST"
    url = api_config['BaseURL'] + "/cloud-accounts-manager/v1/cloudAccounts/azureAccounts/"+parentId+"/children"
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    payload = {
        "clientId": clienId,
        "cloudAccount":
            {
                "accountId": tenantId,
                "accountType": "tenant"
            },
        "environmentType": "azure",
        "key": "",
        "monitorFlowLogs": bool ("true"),
        "rootSyncEnabled": bool("true"),
        "servicePrincipalId": servicePrincipalId,
        "tenantId": tenantId
    }

    apiResponse = run_api_call_with_payload (action, url, headers,payload)
    accounts = json.loads(apiResponse.text)
    return accounts




### APIs to interact  with Cloud Accounts and Organization Accounts ###


def get_cloud_accounts(api_config):
    action = "GET"
    url = api_config['BaseURL'] + "/cloud/"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload(action, url, headers)
    accounts = json.loads(apiResponse.text)
    return accounts


def get_org_cloud_account_from_cloud_account(api_config, cloudAccountId):
    action = "GET"
    url = api_config['BaseURL'] + "/cloud/azure/" + cloudAccountId + "/project"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload(action, url, headers)
    accounts = json.loads(apiResponse.text)
    return accounts


### Processing Functions  Cloud Accounts###
def get_cloudAccountName (cloudAccountList, accountId):
    account = ""
    for cloudAccount in cloudAccountList:
        if cloudAccount["accountId"].split (":")[0] == accountId:
            return cloudAccount["name"]

def get_cloud_MgmtGrps_not_having_acountGrp(cloudAccountList, accountGroupsList):
    cloudAccountsMatching = []
    for cloudAccount in cloudAccountList:
        accountGroupName = "AcctGrp " + cloudAccount['name'].split (" - ")[0]
        accountGroupExist = if_accountGroupName_exist_in_accountGroupList(accountGroupName, accountGroupsList)
        if not accountGroupExist:
            cloudAccountsMatching.append(cloudAccount)
    return cloudAccountsMatching


def organize_cloud_accounts_based_azure_mgmtGr(api_config,tenantId,clientId,servicePrincipalId, azureMgmtGrList):
    Graph = [(tenantId,tenantId)]
    for azureMgmtGr in azureMgmtGrList:
        parentId = azureMgmtGr['accountId'].split (":")[0]
        accounts = get_child_parent_azure(api_config,tenantId,parentId,clientId,servicePrincipalId)
        for account in accounts:
            Graph.append ((account['id'],parentId))
    return dict(Graph)






### Processing Functions  Account Groups###

def if_accountGroupName_exist_in_accountGroupList(accountGroupName, accountGroupsList):
    accountGroupExists = False
    for accountGroup in accountGroupsList:
        if (accountGroup['name'].lower() == accountGroupName.lower()):
            accountGroupExists = True
            break
    return accountGroupExists


def get_accountGroupData_from_accountGroupList_by_name_equals(accountGroupName, accountGroupsList):
    accountGroupExists = False
    for accountGroup in accountGroupsList:
        if (accountGroup['name'].lower() == accountGroupName.lower()):
            accountGroupExists = True
            break
    if not accountGroupExists:
        return_error("Account Group \"" + accountGroupName + "\" does not exist")
    return accountGroup


def delete_item_from_list_if_exists(item, list):
    if item in list:
        list.remove(item)
    return list


def add_item_in_list_if_not_exists(item, list):
    if item not in list:
        list.append(item)
    return list


def delete_account_from_account_group(api_config, account, accountGroup):
    accountIds = delete_item_from_list_if_exists(account['accountId'], accountGroup['accountIds'])
    print("Deleting account \"" + account['name'] + "\" from Account Group \"" + accountGroup['name'] + "\"")
    update_account_group(api_config, accountGroup['name'], accountGroup['id'], accountIds, accountGroup['description'])


def add_account_in_account_group(api_config, account, accountGroup):
    if account['id'] not in accountGroup['accountIds']:
        accountIds = add_item_in_list_if_not_exists(account['id'], accountGroup['accountIds'])
        print("Adding account \"" + account['name'] + "\" to Account Group \"" + accountGroup['name'] + "\"")
        update_account_group(api_config, accountGroup['name'], accountGroup['id'], accountIds, accountGroup['description'])

def add_accountId_in_account_group(api_config, accountId, accountGroup):
    if accountId not in accountGroup['accountIds']:
        accountIds = accountGroup['accountIds']
        accountIds.append (accountId)
        print("Adding account ID \"" + accountId + "\" to Account Group \"" + accountGroup['name'] + "\"")
        update_account_group(api_config, accountGroup['name'], accountGroup['id'], accountIds, accountGroup['description'])



def assign_subscriptions_to_account_groups(api_config,azureAllOrgAccountList,accountGroupsList,graph,tenantId):
    path = {}
    for subscription  in  azureAllOrgAccountList:
        node0 = subscription['accountId'].split (":")[0]
        path [node0] = []
        child = bool ("true")
        node = node0
        while child:
            node = graph [node]
            accountGroupName = "acctGrp " + get_cloudAccountName(azureAllOrgAccountList, node).split (" - ")[0]
            if node != tenantId :
                path[node0] = path[node0] +[node]
                accountGrp= get_accountGroupData_from_accountGroupList_by_name_equals(accountGroupName, accountGroupsList)
                add_accountId_in_account_group(api_config, subscription['accountId'], accountGrp)
            else:
                accountGrp= get_accountGroupData_from_accountGroupList_by_name_equals(accountGroupName, accountGroupsList)
                add_accountId_in_account_group(api_config, subscription['accountId'], accountGrp)
                child = bool("false")
                break





def main():
    # ----------- Load API configuration from .ini file -----------

    api_config = load_api_config("API_config.ini")

    # ----------- First API call for authentication -----------

    token = login(api_config)
    api_config['Token'] = token


    # ----------- Naming Convention -----------

    tenantId = api_config ["tenantId"]
    clientId = api_config ["clientId"]
    servicePrincipalId = api_config ["servicePrincipalId"]


    # ----------- Get Account Groups and Cloud Accounts -----------

    accountGroupsList = get_account_groups(api_config)
    azureAllOrgAccountList = get_org_cloud_account_from_cloud_account(api_config, tenantId)



    # ----------- Get org Accounts based on Cloud Accounts and cloud type-----------

    azureMgmtGrList = []
    azureSubscriptions =[]

    # ----------- Split subscriptions and azure management groups-----------
    for account in azureAllOrgAccountList:
        if account ["accountType"] in ("management_group","tenant"):
            azureMgmtGrList.append(account)
        elif account ["accountType"] == "account":
            azureSubscriptions.append (account)

    # ----------- Create account groups for every azure management group-----------

    newAzureMgmtGrp = get_cloud_MgmtGrps_not_having_acountGrp(azureMgmtGrList, accountGroupsList)
    for account in newAzureMgmtGrp:
        create_account_group(api_config, "acctGrp "+ account['name'].split (" - ")[0], [], "This account group is create by a script for the management group "+account['name'].split(" - ")[0])
    accountGroupsList = get_account_groups(api_config)

    # ----------- represent azure subscriptions in graph-----------
    graph = organize_cloud_accounts_based_azure_mgmtGr(api_config, tenantId,clientId, servicePrincipalId, azureMgmtGrList)

    # ----------- represent azure subscriptions in graph-----------

    # ----------- assign subscriptions to Account Groups-----------

    assign_subscriptions_to_account_groups(api_config,azureAllOrgAccountList,accountGroupsList,graph,tenantId)








if __name__ == "__main__":
    main()
