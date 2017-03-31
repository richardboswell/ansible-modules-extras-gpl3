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
    import time
    HAS_CLIENTS = True
except ImportError:
    HAS_CLIENTS = False

LOG = logging.getLogger(__name__)
handler = logging.FileHandler('/var/log/chaperone/os_heat_status.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
LOG.addHandler(handler)
LOG.setLevel(logging.DEBUG)

def log(message=None):
    func = inspect.currentframe().f_back.f_code
    msg="Method: {} Line Number: {} Message: {}".format(func.co_name, func.co_firstlineno, message)
    LOG.debug(msg)

def keystone_auth(module):
    ksclient = None
    try:
        ksclient = ks_client.Client(username=module.params['username'],
                                    password=module.params['password'],
                                    tenant_name=module.params['project_name'],
                                    auth_url=module.params['auth_url'],
                                    insecure=True)
    except Exception as e:
        module.fail_json(msg="Failed to get keystone client authentication: {}".format(e))
    return ksclient

def stack_get(module, heaturl, token, status_code):
    log("REQUEST GET - URL - {}".format(heaturl))
    log("REQUEST GET - TOKEN - {}".format(token))

    rheaders = {'X-Auth-Token': "%s" % token}
    resp = requests.get(heaturl, headers=rheaders, verify=False)

    log("REQUEST GET - STATUS_CODE - {}".format(resp.status_code))

    if resp.status_code != status_code:
        module.fail_json(msg="Failed to get stack status: {}".format(resp.status_code))

    content = resp.json()
    return content

def stack_delete(module, heaturl, token, status_code):
    log("REQUEST DELETE - URL - {}".format(heaturl))
    log("REQUEST DELETE - TOKEN - {}".format(token))

    rheaders = {'X-Auth-Token': "%s" % token}
    resp = requests.delete(heaturl, headers=rheaders, verify=False)

    if resp.status_code != status_code:
        module.fail_json(msg="Failed to get stack status: {}".format(resp.status_code))

    log("REQUEST DELETE - STATUS_CODE - {}".format(resp.status_code))
    return resp.status_code


def project_stacks(module, token, endpoint, project_id):
    url = 'https://{}:8004/v1/{}/stacks'.format(endpoint, project_id)
    content = stack_get(module, url, token, 200)
    return content['stacks']

def stack_status(module, token, endpoint, project_id, stack_data):
    stack_name = stack_data['stack_name']
    stack_id = stack_data['id']
    url = 'https://{}:8004/v1/{}/stacks/{}/{}'.format(endpoint, project_id, stack_name, stack_id)
    content = stack_get(module, url, token, 200)
    return content['stack']['stack_status']

def log_stack_data(stack):
    stack_data = {}
    stack_data.update({'name': stack['stack_name']})
    stack_data.update({'data': stack})
    log("STACK NAME: {}".format(stack['stack_name']))
    log("STACK DATA: {}".format(stack_data))
    return stack_data

def wait_for_stack(module, token, endpoint, project_id):
    stack_info = []
    url = 'https://{}:8004/v1/{}/stacks'.format(endpoint, project_id)
    del_url = '{}/{}/{}'

    stacks = project_stacks(module, token, endpoint, project_id)

    if not stacks:
        return stack_info

    for stack in stacks:
        stack_delete_url = del_url.format(url, stack['stack_name'], stack['id'])
        wait_count = 0

        while wait_count < 21:
            project_stack_status = project_stacks(module, token, endpoint, project_id)

            if not project_stack_status:
                break

            status = stack_status(module, token, endpoint, project_id, stack)
            msg="STACK: {} STATUS: {}".format(stack['stack_name'], status)
            log(msg)

            if status == "CREATE_COMPLETE" or status == "CREATE_FAILED":
                stack_data = log_stack_data(stack)
                delete_status = stack_delete(module, stack_delete_url, token, 204)
                log("Delete STATUS - STACK - {} Delete RESP - {}".format(stack['stack_name'], delete_status))
                stack_info.append(stack_data)

            elif status == "DELETE_IN_PROGRESS":
                log("Deleting State --> {}".format(status))
                stack_data = log_stack_data(stack)
                stack_info.append(stack_data)

                wait_count += 1
                time.sleep(45)

            elif status == "DELETE_FAILED":

                delete_status = stack_delete(module, stack_delete_url, token, 204)

                if not (delete_status == 204):
                    msg = "Failed to Delete Stack: {} with STATUS - {}".format(stack['stack_name'], delete_status)
                    log(msg)
                    module.fail_json(msg=msg)
                elif delete_status == 204:
                    log("Deleted Stack - {}".format(stack['stack_name']))
                    break

            else:
                wait_count += 1
                time.sleep(20)

            if wait_count == 21:
                log("WAITED 7 minutes for stack exiting ... . . ")
                break
    return stack_info


def main():

    argument_spec = dict(
        auth_url=dict(required=True, type='str'),
        username=dict(required=True, type='str'),
        password=dict(required=True, type='str', no_log=True),
        project_name=dict(required=True, type='str'),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

    if not HAS_CLIENTS:
        module.fail_json(msg='python-requests is required for this module')

    changed = False

    ks = keystone_auth(module)
    token = ks.auth_token
    project_id = ks.tenant_id
    vioendpoint = urlparse(module.params['auth_url']).netloc.split(':')[0]

    project_stack_info = wait_for_stack(module, token, vioendpoint, project_id)

    if project_stack_info:
        changed=True

    module.exit_json(changed=changed, stack_data_info=project_stack_info)


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
