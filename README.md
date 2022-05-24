# Prisma SD-WAN EDL (Preview)
The purpose of this script is get a URL EDL and import the prefixes into a Security Group Prefix  

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.6

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt
 - Add your EDL URL and Security Prefix name to the cloudgenix_settings.py

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 - ./edl.py can be used to get a URL EDL and impor the prefixes into a Security Group Prefix
 
 
### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
