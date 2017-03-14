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
    msg="{} Line: {} Msg: {}".format(func.co_name, func.co_firstlineno, message)
    LOG.debug(msg)

## vrops api paths, cannot find casa api docs... google don't even know?
_security         = 'security/%s'
_deployment       = 'deployment/%s'
_sysadmin         = 'sysadmin/%s'
_cluster          = 'cluster/%s'
cluster           = 'cluster'
_node             = 'node/%s'
node              = 'node'
_slice            = 'slice/%s'
slice_            = 'slice'
_role             = 'role/%s'
role              = 'role'

ntp               = 'ntp'
_ntp              = '%s/%s'
_status           = 'status'
_ntp_status       = _ntp % (ntp, _status)

adminpassword     = 'adminpassword'
admin_pass_init   = 'initial'
admin_pass        = '%s/%s'

_headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' }
_set_admin_role_body = [{ "slice_address": "", "admin_slice": "",
                          "is_ha_enabled": True, "user_id": "", "password": "",
                          "slice_roles": ["ADMIN","DATA","UI"] }]

class VropsRestClient(object):
    """"""
    def __init__(self, username, password, server):
        super(VropsRestClient, self).__init__()
        self._username       = username
        self._password       = password
        self._server         = server
        self._base_url       = 'https://%s' % self._server
        self._base_user_url  = 'https://%s/suite-api/api/%s'
        self._base_admin_url = 'https://%s/casa/%s'
        self.auth            = (self._username, self._password)

    def do_request(self, request_type, status_codes, params):
        """Returns status code of rest call and json content
        returns None, None on failure
        :param request_type: get, put, post, delete
        :param status_codes: list of accepted status codes
        :param params: dict of requests.<request_type> accepted parameters
        """
        resp  = None
        content = None
        status_code = None

        log("REQ: %s URL: %s" % (request_type, params['url']))

        try:
            if request_type == 'get':
                resp = requests.get(**params)
            if request_type == 'put':
                resp = requests.put(**params)
            if request_type == 'post':
                resp = requests.post(**params)
            if request_type == 'delete':
                resp = requests.delete(**params)
            status_code = resp.status_code
        except (requests.exceptions.ConnectionError, requests.RequestException) as conn_error:
            log("Failed Request GET Error: %s "% str(conn_error))
            return resp, content
        except (status_code not in status_codes):
            log("Status Code: %s not in status codes: %s " % (status_code, status_codes))
            return resp, content
        except Exception as e:
            log("General Failure: %s " % str(e))
            return resp, content

        log("REQ: %s URL: %s STATUS: %s" % (request_type, params['url'], status_code))

        try:
            content = resp.json()
        except Exception as e:
            pass

        return resp.status_code, content

    def api_url(self, url_tpye=None, path=None):
        url = self._base_url
        if url_tpye == 'admin' and path:
            url = self._base_admin_url % (self._server, path)
        if url_tpye == 'user' and path:
            url = self._base_user_url % (self._server, path)
        return url

    def api_state(self):
        state  = False
        _url   = self.api_url()
        params = {'url': _url, 'verify': False}

        state, content = self.do_request('get', [200], params)

        log("API State: %s " % state)
        return state

    def ntp_state(self, ntp_server):
        state = False
        path  = _sysadmin % _cluster % ntp
        url   = self.api_url('admin', path)

        params = {'url': url, 'auth': self.auth,
                  'headers': _headers, 'verify': False}

        state, content = self.do_request('get', [200], params)

        if not state:
            return state

        ### todo compare lists
        if ntp_server in content['time_server']:
            state = True

        log("ntp state: %s " % state)
        return state

    def set_ntp(self, ntp_servers):
        state = False

        return state


    def admin_role_state(self):
        state    = False
        _url     = self._base_admin_url % (self._server, _get_admin_role_path)

        params   = {'url': _url, 'auth': self.auth,
                    'verify': False, 'headers': _headers}

        status_code, content = self.do_request('get', [200], params)

        if status_code == 200:
            state = content['configurationRunning']

        log("Admin Role State: %s " % state)

        return state

    def body_to_json(self, body):
        json_body = None

        try:
            json_body = json.dumps(body)
        except Exception as e:
            log("Failed to convert to json: %s " % str(e))
            return json_body

        return json_body

    def set_admin_init_password(self):
        state    = False
        path     = _security % admin_pass % (adminpassword, admin_pass_init)
        _url     = self.api_url('admin', path)
        body     = { "password": self._password }
        _body    = self.body_to_json(body)

        params   = {'url': _url, 'verify': False,
                    'data': _body, 'headers': _headers}

        state, content = self.do_request('put', [200, 500], params)

        if state == 500:
            state = (content['error_message_key'] != 'security.initial_password_already_set')
            log("Admin Initial password not set... already been set")

        log("set admin pass state: %s " % state)
        return state

    def admin_role_body(self, _admin_role_body):
        for body in _admin_role_body:
            body.update({'slice_address': self._server})
            body.update({'admin_slice': self._server})
            body.update({'user_id': self._username})
            body.update({'password': self._password})
        return _admin_role_body

    def set_admin_role(self):
        state  = False
        path   = _deployment % _slice % role
        _url   = self.api_url('admin', path)
        body   = self.admin_role_body(_set_admin_role_body)
        _body  = self.body_to_json(body)

        params = {'url': _url, 'verify': False, 'auth': self.auth,
                  'data': _body, 'headers': _headers}

        state, content = self.do_request('post', params)

    def admin_role(self):
        set_role = False

        if not self.admin_role_state():
            set_role = self.set_admin_role()

        return set_role

    def cluster_state(self):
        state    = False
        _url     = self._base_admin_url % (self._server, _cluster_deployment)
        params   = {'url': _url, 'verify': False, 'auth': self.auth, 'headers': _headers}

        status_code, content = self.do_request('get', params)

        if status_code == 200:
            state = (content['cluster_name'] == self._server)

        return state

    def configure_cluster(self):
        state    = False
        _url     = self._base_admin_url % (self._server, _cluster_deployment)
        body     = { 'cluster_name': self._server }
        _body    = self.body_to_json(body)

        params   = {'url': _url, 'verify': False, 'auth': self.auth,
                    'headers': _headers, 'data': _body}

        status_code, content = self.do_request('put', params)
        log("configure cluster content: %s " % content)
        return state

    def configure_cluster_name(self):
        state = False
        if not self.cluster_state():
            state = self.configure_cluster()
        return state



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
        self._ntp_server  = '10.159.18.10'
        self.vrops_client = VropsRestClient(self.admin, self.admin_pass, self._server)

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

    def state_create(self):
        """Returns changed result and msg"""
        changed = False
        result = None
        msg = "STATE CREATE"

        log("Getting API State... ")
        api_state = self.vrops_client.api_state()

        if not api_state:
            msg = "API should be ready but is not"
            log(msg)
            self._fail(msg)

        log("Setting Admin Init Pass... ")
        admin_password_state = self.vrops_client.set_admin_init_password()

        log("Getting NTP State....")
        ntp_state = self.vrops_client.ntp_state(self._ntp_server)

        if not ntp_state:
            log("Setting NTP...")
            configure_ntp = self.vrops_client.set_ntp(self._ntp_server)

        log("Setting Admin Role... ")
        #admin_role = self.vrops_client.admin_role()

        log("Setting Cluster Name... ")
        #cluster_name  = self.vrops_client.configure_cluster_name()

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

    vrops = VropsConfig(module)
    vrops.run_state()


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
