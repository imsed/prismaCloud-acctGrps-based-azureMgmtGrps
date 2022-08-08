# IMPORTANT: update "API_config.ini" file before running the script. The following fields are currently empty and need to be updated:
```
URL --> introduce your API URL (e.g. "https://api2.eu.prismacloud.io")
ACCESS_KEY_ID --> introduce your Prisma Cloud ACCESS KEY ID
SECRET_KEY --> introduce your Prisma Cloud SECRET KEY
tenantId --> azure tenant id
clientId --> the service principal id
servicePrincipalId --> the service principal Enterprise Application Object ID
```
## Prerequisites:
- The script is tested on Python 3.10
- Install requests package
    
## Functioning description:

- The script contains couple of functions that helps automat account groups creation and manipulation. The main use case is to create account groups based on azure management groups and auto map subscription to account groups


## Applicable use cases:

The purpose of the script is to have dynamic adding of accounts to account groups based on azure management groups. This is to make sure that all onboarded accounts are mapped to proper account groups automatically without manual intervention. The script can be run on a regular basis (e.g. daily) to constantly update the accounts.

