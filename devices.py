"""
List SDWAN device model types and their associated counts.

Example: python2 devices.py sdwandemo.cisco.com demo demo

PARAMETERS:
    vmanage_hostname : Ip address of the vmanage or the dns name of the vmanage without port number
    username : Username to login the vmanage
    password : Password to login the vmanage

Note: All the three arguments are manadatory.  

REST API class pulled from:
https://sdwan-docs.cisco.com/Product_Documentation/Command_Reference/
vManage_REST_APIs/vManage_REST_APIs_Overview/Using_the_vManage_REST_APIs
"""
import requests
import sys
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class rest_api_lib:
    def __init__(self, vmanage_ip, username, password):
        self.vmanage_ip = vmanage_ip
        self.session = {}
        self.login(self.vmanage_ip, username, password)

    def login(self, vmanage_ip, username, password):
        """Login to vmanage"""
        base_url_str = 'https://%s/'%vmanage_ip
        login_action = '/j_security_check'
        #Format data for loginForm
        login_data = {'j_username' : username, 'j_password' : password}
        #Url for posting login data
        login_url = base_url_str + login_action
        url = base_url_str + login_url
        sess = requests.session()
        #If the vmanage has a certificate signed by a trusted authority change verify to True
        login_response = sess.post(url=login_url, data=login_data, verify=False)
        if '<html>' in login_response.content:
            print "Login Failed"
            sys.exit(0)
        self.session[vmanage_ip] = sess

    def get_request(self, mount_point):
        """GET request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        #print url
        response = self.session[self.vmanage_ip].get(url, verify=False)
        data = response.content
        return data

    def post_request(self, mount_point, payload, headers={'Content-Type': 'application/json'}):
        """POST request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        response = self.session[self.vmanage_ip].post(url=url, data=payload, headers=headers, verify=False)
        data = response.content
        
def main(args):
    if not len(args) == 3:
        print __doc__
        return
    vmanage_ip, username, password = args[0], args[1], args[2]
    obj = rest_api_lib(vmanage_ip, username, password)
    response = obj.get_request('device')
    # loads() takes a json string and turns it into a python object
    parse_data(json.loads(response))

def parse_data(obj):
    #create a dictionary of key value pairs, keys are device model, values are the counts
    device_models = {}
    #loop through json object
    #use a json viewer like http://jsonviewer.stack.hu to better visualize this
    for device in obj['data']:
        dm = device['device-model']
        #if device model is not already in the dictionary, add it
        if dm not in device_models:
            device_models[dm] = 0
        #increment the count by 1
        device_models[dm] += 1
    
    for key, value in device_models.items():
        print "{:<25}{:<15}".format(key, value)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))