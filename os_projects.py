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
        self.auth_pass = module.params['auth_pass']
        self.auth_project = module.params['auth_project']
        self.auth_project_domain = module.params['auth_project_domain']
        self.auth_user_domain = module.params['auth_user_domain']
        self.project_name = module.params['new_project_name']
        self.current_state = None
        self.ks = self.keystone_auth()

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
            auth = identity.Password(auth_url=self.auth_url,
                                     username=self.auth_user,
                                     password=self.auth_pass,
                                     project_name=self.auth_project,
                                     project_domain_id=self.auth_project_domain,
                                     user_domain_id=self.auth_user_domain)
            sess = session.Session(auth=auth,
                                   verify=False)
            ks = client.Client(session=sess)
        except Exception as e:
            msg = "Failed to get client: %s " % str(e)
            log(msg)
            self.module.fail_json(msg=msg)
        log("ks client: %s " % ks)
        return ks

    def check_project_state(self):
        log("Checking State...")
        state = 'absent'
        projects = [p.name for p in self.ks.tenants.list()]
        if self.project_name in projects:
            state = 'present'
        log("Current State--> {}".format(state))
        return state

    def process_state(self):
        log("Processing State...")
        self.current_state = self.check_project_state()

        project_states = {
            'absent': {
                'present': self.state_delete_project,
                'absent': self.state_exit_unchanged,
            },
            'present': {
                'present': self.state_exit_unchanged,
                'absent': self.state_create_project,
            }
        }

        project_states[self.module.params['state']][self.current_state]()


    def state_create_project(self):
        log("Create Project...")
        new_project = None
        changed = False
        try:
            new_project = self.ks.tenants.create(self.project_name)
            changed = True
        except Exception as e:
            msg="Failed to create Project Exception: {}".format(e)
            log(msg)
            self.module.fail_json(msg=msg)
        if not new_project:
            self.module.fail_json(msg="Failed to create Project")
        log("NEW PROJECT--> {}".format(new_project))
        self.module.exit_json(changed=changed, project_name=new_project.name, project_id=new_project.id)

    def state_delete_project(self):
        log("Deleting Project...")
        delete_project = None
        project_name = None
        project_id = None

        project_to_delete = [t for t in self.ks.tenants.list() if t.name == self.project_name]

        if project_to_delete:
            project_name = project_to_delete[0].name
            project_id = project_to_delete[0].id
            delete_project = self.ks.tenants.delete(project_to_delete[0])
        log("Deleted Project--> {}".format(project_name))
        self.module.exit_json(changed=True, project_name=project_name,
                              project_id=project_id, msg="Delete Project")

    def state_exit_unchanged(self):
        log("Exiting Unchanged...")
        if self.module.params['state'] == 'absent' and self.current_state == 'absent':
            self.module.exit_json(changed=False, msg="EXIT UNCHANGED",
                                  project_name=None, project_id=None)

        if self.module.params['state'] == 'present' and self.current_state == 'present':
            project = [p for p in self.ks.tenants.list() if p.name == self.project_name][0]
            self.module.exit_json(changed=False, msg="EXIT UNCHANGED",
                                  project_name=project.name, project_id=project.id)



def main():
    argument_spec = dict(
        auth_url=dict(required=True, type='str'),
        auth_user=dict(required=True, type='str'),
        auth_password=dict(required=True, type='str', no_log=True),
        auth_project=dict(required=True, type='str'),
        auth_project_domain=dict(required=True, type='str'),
        auth_user_domain=dict(required=True, type='str'),
        new_project_name=dict(required=True, type='str'),
        state=dict(default='present', choices=['present', 'absent'], type='str'),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

    if not HAS_CLIENTS:
        module.fail_json(msg='python-keystone is required for this module')

    os = OpenstackProject(module)
    os.process_state()


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
