#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2015 VMware, Inc. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
# to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions
# of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.


DOCUMENTATION = '''
module: vio_check_heat_stack
Short_description: Checks if heat stack is present
description:
    Module will check if a heat stack is present for a specified tenant. Module specifically
    developed for the ansible-role-vio
requirements:
    - keystoneclient.v2_0
    - requests
    - urlparse
Tested on:
    - vio 2.5
    - ansible 2.1.2
options:
    auth_url:
        description:
            - keystone authentication for the openstack api endpoint
        required: True
    username:
        description:
            - user with rights to specified project
        required: True
    password:
        description:
            - password for specified user
        required: True
    tenant_name:
        description:
            - tenant name with authorization for specified project
        required: True
'''

EXAMPLE = '''
- name: Check Heat stack present
  vio_check_heat_stack:
    auth_url: "https://{{ vio_loadbalancer_vip }}:5000/v2.0"
    username: "{{ projectuser }}"
    password: "{{ projectpass }}"
    tenant_name: "{{ vio_val_project_name }}"
    heat_stack_name: "{{ vio_val_heat_name }}"
  register: stack_present
  tags:
    - validate_openstack
'''

try:
    from keystoneclient.v2_0 import client as ks_client
    from urlparse import urlparse
    import requests
    import inspect
    import logging
    HAS_CLIENTS = True
except ImportError:
    HAS_CLIENTS = False

LOG = logging.getLogger(__name__)
handler = logging.FileHandler('/var/log/chaperone/os_check_heat.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
LOG.addHandler(handler)
LOG.setLevel(logging.DEBUG)

def log(message=None):
    func = inspect.currentframe().f_back.f_code
    msg="{} Line: {} Msg: {}".format(func.co_name, func.co_firstlineno, message)
    LOG.debug(msg)


class OpenstackHeat(object):
    """"""
    def __init__(self, module):
        super(OpenstackHeat, self).__init__()
        self.module = module
        self.auth_url = module.params['auth_url']
        self.user_name = module.params['username']
        self.user_pass = module.params['password']
        self.auth_tenant = module.params['tenant_name']
        self.stack_name = module.params['heat_stack_name']
        self.ks = self.ks_auth()
        self.ks_token = self.ks.auth_token
        self.ks_project_id = self.ks.tenant_id
        self.endpoint = urlparse(self.auth_url).netloc.split(':')[0]
        self.heat_url = 'https://{}:8004/v1/{}/stacks'.format(self.endpoint, self.ks_project_id)

    def ks_auth(self):
        log("GETTING Keystone client...")
        ksclient = None

        try:
            ksclient = ks_client.Client(username=self.user_name, password=self.user_pass,
                                        tenant_name=self.auth_tenant, auth_url=self.auth_url,
                                        insecure=True)
        except Exception as e:
            msg="Failed to get keystone client authentication: {}".format(e)
            log(msg)
            self.module.fail_json(msg=msg)

        return ksclient

    def heat_get(self, url, token, status_code):
        log("GET REQUEST URL--> {}".format(url))
        log("GET REQUEST TOKEN--> {}".format(token))

        rheaders = {'X-Auth-Token': "%s" % token}
        resp = requests.get(url, headers=rheaders, verify=False)

        if resp.status_code != status_code:
            msg="FAILED GET REQUEST STATUS CODE--> {}".format(resp.status_code)
            log(msg)
            self.module.fail_json(msg=msg)

        content = resp.json()
        return content

    def get_stack_status(self):
        log("GETTING STACK State...")
        state = False

        stacks = self.heat_get(self.heat_url, self.ks_token, 200)
        stack_present = [s for s in stacks['stacks'] if s['stack_name'] == self.stack_name]

        if stack_present:
            state = True

        log("STACK--> {} PRESENT--> {}".format(self.stack_name, state))
        return state

    def process_state(self):
        present = self.get_stack_status()
        self.module.exit_json(changed=False, present=present)

def main():

    argument_spec = dict(
        auth_url=dict(required=True, type='str'),
        username=dict(required=True, type='str'),
        password=dict(required=True, type='str', no_log=True),
        tenant_name=dict(required=True, type='str'),
        heat_stack_name=dict(required=True, type='str'),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

    if not HAS_CLIENTS:
        module.fail_json(msg='python-keystone is required for this module')

    h = OpenstackHeat(module)
    h.process_state()


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
