#!/usr/bin/python
#
# (c) 2015, Joseph Callen <jcallen () csc.com>
# Portions Copyright (c) 2015 VMware, Inc. All rights reserved.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.


DOCUMENTATION = '''
module: vcenter_vrops_config
Short_description: Configuration for vROPs
description:
    Configuration for vROPs
requirements:
    - ansible 2.x
    - requests
Tested on:
    - vcenter 6.0
    - esx 6
    - ansible 2.1.2
    - vRealize-Operations-Manager-Appliance-6.4.0.4635874
options:
    hostname:
        description:
            - The hostname or IP address of the vSphere vCenter API server
        required: True
    username:
        description:
            - The username of the vSphere vCenter with Admin rights
        required: True
        aliases: ['user', 'admin']
    password:
        description:
            - The password of the vSphere vCenter user
        required: True
        aliases: ['pass', 'pwd']


    state:
        description:
            - Desired state of the disk group
        choices: ['present', 'absent']
        required: True
'''

EXAMPLE = '''
- name: vROPs Configure
  vcenter_vrops_config:
    administrator: 'admin'
    password: 'pass123!'
    vrops_ip_addess: '128.123.123.3'
    state: 'present'
  tags:
    - vrops_config
'''


try:
    import time
    import requests
    import inspect
    import logging
    IMPORTS = True
except ImportError:
    IMPORTS = False

## Logging
LOG = logging.getLogger(__name__)
handler = logging.FileHandler('/var/log/chaperone/vcenter_vrops_config.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
LOG.addHandler(handler)
LOG.setLevel(logging.DEBUG)

def log(message=None):
    func = inspect.currentframe().f_back.f_code
    msg="Method: {} Line Number: {} Message: {}".format(func.co_name, func.co_firstlineno, message)
    LOG.debug(msg)

## vrops api paths, cannot find casa api docs... google don't even know?
_set_admin_path      = 'security/adminpassword/initial'
_set_admin_role_path = 'deployment/slice/role'
_token_path          = 'auth/token/acquire'

class VropsRestClient(object):
    """"""
    def __init__(self, username, password, server):
        super(VropsRestClient, self).__init__()
        self._username       = username
        self._password       = password
        self._server         = server
        self._base_url       = 'https://{}'.format(self._server)
        self._base_user_url  = 'https://{}/suite-api/api/{}'
        self._base_admin_url = 'https://{}/casa/{}'

        log("---- VropsRestClient ----")
        log("username: {}".format(self._username))
        log("password: {}".format(self._password))
        log("server: {}".format(self._server))
        log("base url: {}".format(self._base_url))

    def _do_request(self, **params):
        """
        :param url_type: optional: False
          choices: admin, user, None
        :param request_type: optional: False
          choices: get, put, post, delete
        :param path: optional: True
          choices: specify casa (admin) or suite-api (user) path
        :param
        """
        resp        = None
        content     = None
        status_code = None
        api_path    = None
        _url        = self._base_url

        not_optional_params = ['url_type', 'request_type']
        param_keys = [p for p in params.iterkeys()]
        params_present = [nop for nop in not_optional_params if nop not in param_keys]

        if params_present:
            msg = "Requests requires param: {}".format(params_present)
            log(msg)

        if 'path' in param_keys:
            api_path = params['path']
        if params['url_type'] == 'admin':
            _url = self._base_admin_url.format(self._server, api_path)
        if params['url_type'] == 'user':
            _url = self._base_user_url.format(self._server, api_path)

        rheader = { 'Content-Type': 'application/json', 'Accept': 'application/json' }

        if 'request_body' in param_keys:
            log("REQ: {} URL: {} BODY: {}".format(params['request_type'], _url, True))
            json_body = json.dumps(params['request_body'])

        log("REQ: {} URL: {}".format(params['request_type'], _url))

        try:

            if params['request_type'] == 'get':
                log("Get Request...")
                resp = requests.get(_url, verify=False)

            if params['request_type'] == 'post' and params['request_body']:
                resp = requests.post(_url, headers=rheader, data=json_body, verify=False)

            if params['request_type'] == 'put' and params['request_body']:
                resp = requests.put(_url, headers=rheader, data=json_body, verify=False)

            if params['request_type'] == 'delete':
                resp = requests.delete(_url, headers=rheader, verify=False)

        except requests.exceptions.ConnectionError as conn_error:
            msg = "Failed Request GET with Connection Error: {}".format(str(conn_error))
            log(msg)
        except requests.RequestException as e:
            msg = "Failed Request GET with Error: {}".format(str(e))
            log(msg)

        if resp.status_code not in params['status_codes']:
            msg = "Response Status Cod Not in "
            log(msg)
            return status_code, content

        try:
            content = resp.json()
        except Exception as e:
            pass

        status_code = resp.status_code
        log("REQ: {} URL: {} CODE: {}".format(params['request_type'], _url, status_code))

        return status_code, content

    def get_token(self):
        token_path   = _token_path
        token_auth   = { 'username': self._username, 'password': self._password }
        token_params = {'path': token_path, 'url_type': 'user',
                        'request_type': 'post', 'status_codes': [200],
                        'request_body': token_auth}

        status, content = self._do_request(**token_params)

        if status != 200:
            return None

        return content['token']

    def set_admin_password(self):
        state  = False
        path   = _set_admin_path
        body   = { "password": self._password }
        params = {'path': path, 'url_type': 'admin', 'request_type': 'put',
                  'status_codes': [200, 500], 'request_body': body}

        status, content = self._do_request(**params)

        if status == 500:
            state = (content['error_message_key'] == 'security.initial_password_already_set')
        elif status == 200:
            state = True

        return state

    def set_admin_role(self):
        state = False
        path  = _set_admin_role_path

        body  = [{ "slice_address": self._server,
                   "admin_slice": self._server,
                   "is_ha_enabled": 'true',
                   "user_id": self._username,
                   "password": self._password,
                   "slice_roles": ["ADMIN","DATA","UI"] }]

        params = {'path': path, 'url_type': 'admin',
                  'request_type': 'post', 'status_codes': [202],
                  'request_body': body}

        status, content = self._do_request(**params)

        if status == 202:
            state = True

        return state

    def api_test(self):
        url = self._base_url
        log("REQ: GET URL: {}".format(url))

        try:
            resp = requests.get(url=url, verify=False)
        except requests.exceptions.ConnectionError as ce:
            log("Failed request ConnectionError: {}".format(ce))
            return False
        except requests.RequestException as re:
            log("Failed request RequestException: {}".format(re))
            return False
        except Exception as e:
            log("Failed request general exception: {}".format(e))
            return False

        log("REQ: GET URL: {} Status: {}".format(url, resp.status_code))
        return resp.status_code

class VropsConfig(object):
    """
    """
    def __init__(self, module):
        """
        """
        super(VropsConfig, self).__init__()
        self.module       = module
        self.admin        = module.params['administrator']
        self.admin_pass   = module.params['password']
        self._server      = module.params['vrops_ip_addess']
        self.vrops_client = VropsRestClient(self.admin, self.admin_pass, self._server)

        log("--- VropsConfig ---")
        log("admin: {}".format(self.admin))
        log("admin_pass: {}".format(self.admin_pass))
        log("server: {}".format(self._server))


    def _fail(self, msg=None):
        """Fail from AnsibleModule
        :param msg: defaults to None
        """
        if not msg: msg = "General Error occured"
        log(msg)
        self.module.fail_json(msg=msg)

    def state_exit_unchanged(self):
        """Returns changed result and msg"""
        changed = False
        result = None
        msg = "EXIT UNCHANGED"
        return changed, result, msg

    def state_delete(self):
        """Returns changed result msg"""
        changed = False
        result = None
        msg = "STATE DELETE"

        return changed, result, msg

    def api_test(self):
        url = "https://{}".format(self._server)
        log("REQ: GET URL: {}".format(url))

        try:
            resp = requests.get(url=url, verify=False)
        except requests.exceptions.ConnectionError as ce:
            log("Failed request ConnectionError: {}".format(ce))
            return False
        except requests.RequestException as re:
            log("Failed request RequestException: {}".format(re))
            return False
        except Exception as e:
            log("Failed request general exception: {}".format(e))
            return False

        log("REQ: GET URL: {} Status: {}".format(url, resp.status_code))
        return resp.status_code

    def state_create(self):
        """Returns changed result and msg"""
        changed = False
        result = None
        msg = "STATE CREATE"

        api_test = self.api_test()
        
        return changed, result, msg

    def run_state(self):
        """Exit AnsibleModule after running state"""
        log(" --- --- --- --- --- ")
        changed = False
        result = None
        msg = None

        desired_state = self.module.params['state']
        current_state = self.check_state()
        module_state = (desired_state == current_state)

        if module_state:
            changed, result, msg = self.state_exit_unchanged()

        if desired_state == 'absent' and current_state == 'present':
            changed, result, msg = self.state_delete()

        if desired_state == 'present' and current_state == 'absent':
            changed, result, msg = self.state_create()

        self.module.exit_json(changed=changed, result=result, msg=msg)

    def check_state(self):
        state = 'absent'
        return state


def main():
    argument_spec = dict(administrator=dict(required=True, type='str'),
                         password=dict(required=True, type='str'),
                         vrops_ip_addess=dict(required=True, type='str'),
                         state=dict(default='present', choices=['present', 'absent']),)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=False)

    if not IMPORTS:
        module.fail_json(msg="Failed to import modules")

    log("--- Module Params ---")
    for k, v in module.params.iteritems():
        log("Param: {} Values: {}".format(k, v))

    vrops = VropsConfig(module)
    vrops.run_state()


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
