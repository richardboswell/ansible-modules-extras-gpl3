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
module: os_create_project
short_description: Creates openstack project
description:
    Creates openstack project
requirements:
    - keystoneclient.v2_0
    - ansible 2.x
options:
    auth_url:
        description:
            - keystone authentication for the openstack api endpoint
        required: True
    username:
        description:
            - user with rights to create project
        required: True
    password:
        description:
            - password for specified user
        required: True
    tenant_name:
        description:
            - tenant name with authorization to create project
        ex: 'admin'
        required: True
    new_project_name:
        description:
            - name of the project to create
        required: True
    state:
        description:
            - If should be present or absent
        choices: ['present', 'absent']
        required: True
'''

EXAMPLES = '''
- name: Create Demo Project
  os_create_project:
    auth_url: 'https://{{ vio_loadbalancer_vip }}:5000/v2.0'
    username: "{{ authuser }}"
    password: "{{ authpass }}"
    tenant_name: 'admin'
    new_project_name: "{{ vio_val_project_name }}"
    state: "{{ desired_state }}"
  register: os_new_project
  tags:
    - validate_openstack

'''


try:
    from keystoneauth1.identity import v3
    from keystoneauth1 import session
    from keystoneclient.v3 import client
    import inspect
    import logging
    HAS_CLIENTS = True
except ImportError:
    HAS_CLIENTS = False

LOG = logging.getLogger(__name__)
handler = logging.FileHandler('/var/log/chaperone/os_projects.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
LOG.addHandler(handler)
LOG.setLevel(logging.DEBUG)

def log(message=None):
    func = inspect.currentframe().f_back.f_code
    msg="Method: {} Line Number: {} Message: {}".format(func.co_name, func.co_firstlineno, message)
    LOG.debug(msg)


class OpenstackProject(object):

    def __init__(self, module):
        super(OpenstackProject, self).__init__()
        self.module = module
        self.auth_url = module.params['auth_url']
        self.auth_user = module.params['auth_user']
        self.auth_pass = module.params['auth_password']
        self.auth_project = module.params['auth_project']
        self.auth_project_domain = module.params['auth_project_domain']
        self.auth_user_domain = module.params['auth_user_domain']
        self.project_name = module.params['new_project_name']
        self.project_enabled = module.params['enabled']
        self.project_desc = module.params['project_description']
        self.project_domain_id = \
            module.params['project_domain_id'] if module.params['project_domain_id'] else 'default'
        self.project_description = \
            module.params['project_description'] if module.params['project_description'] else 'New Project'
        self.ks = self.keystone_auth()
        self.project_id = None

    def _keystone_auth(self):
        log("GETTING KEYSTONE CLIENT....")
        ksclient = None
        try:
            ksclient = ks_client.Client(username=self.user_name, password=self.user_pass,
                                        tenant_name=self.auth_tenant, auth_url=self.auth_url,
                                        insecure=True)
        except Exception as e:
            msg="Failed to get keystone client: {}".format(e)
            log(msg)
            self.module.fail_json(msg=msg)
        return ksclient

    def keystone_auth(self):
        log("GETTING KEYSTONE CLIENT....")
        ks = None
        try:
            auth = v3.Password(auth_url=self.auth_url,
                               username=self.auth_user,
                               password=self.auth_pass,
                               project_name=self.auth_project,
                               project_domain_id=self.auth_project_domain,
                               user_domain_id=self.auth_user_domain)
            sess = session.Session(auth=auth, verify=False)
            ks = client.Client(session=sess)
        except Exception as e:
            msg = "Failed to get client: %s " % str(e)
            log(msg)
            self.module.fail_json(msg=msg)
        log("ks client: %s " % ks)
        return ks

    def run_state(self):
        changed       = False
        result        = None

        current_state = self.check_project_state()
        desired_state = self.module.params['state']
        module_state  = (self.current_state == desired_state)

        if module_state:
            msg = "EXIT UNCHANGED"
            self.state_exit_unchanged(changed=False, msg=msg,
                                      project_name=self.project_name,
                                      project_id=self.project_id)

        if current_state == 'absent' and desired_state == 'present':
            changed, result = self.state_create_project(self.project_name,
                                                        self.project_enabled,
                                                        self.project_domain_id,
                                                        self.project_description)
        if current_state == 'present' and desired_state == 'absent':
            changed, result = self.state_delete_project()

        self.module.exit_json(changed=changed, result=result)

    def state_delete_project():
        pass


    def state_create_project(self, _name, _enabled, _domain_id, _description):
        changed = False
        project = None

        try:
            project = self.ks.projects.create(name=_name,
                                              domain_id=_domain_id,
                                              description=_description,
                                              enabled=_enabled)
            changed = True
        except Exception as e:
            msg = "Failed to create project: %s " % str(e)
            log(msg)
            self.module.fail_json(msg=msg)

        return changed, project


    def check_project_state(self):
        project = None
        try:
            project = [p for p in self.ks.projects.list() if p.name == self.project_name][0]
        except IndexError:
            return 'absent'
        self.project_id = project.id

        return 'present'



def main():
    argument_spec = dict(
        auth_url=dict(required=True, type='str'),
        auth_user=dict(required=True, type='str'),
        auth_password=dict(required=True, type='str', no_log=True),
        auth_project=dict(required=True, type='str'),
        auth_project_domain=dict(required=True, type='str'),
        auth_user_domain=dict(required=True, type='str'),
        new_project_name=dict(required=True, type='str'),
        enabled=dict(required=True, type='bool'),
        project_domain_id=dict(required=False, type='str'),
        project_description=dict(required=False, type='str'),
        state=dict(default='present', choices=['present', 'absent'], type='str'),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

    if not HAS_CLIENTS:
        module.fail_json(msg='python-keystone is required for this module')

    os = OpenstackProject(module)
    os.run_state()


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
