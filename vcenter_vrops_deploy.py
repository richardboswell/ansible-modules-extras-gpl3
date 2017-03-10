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
module: vcenter_vrops_deploy
Short_description: Deploys (creates), Deletes vROPs ova to vcenter cluster
description:
    Deploys (creates), Deletes vROPs ova to vcenter cluster. Module will wait for vm to
    power on and "pings" the vROPs api before exiting if not failed.
requirements:
    - pyvmomi 6
    - ansible 2.x
Tested on:
    - vcenter 6.0
    - pyvmomi 6
    - esx 6
    - ansible 2.1.2
    - VMware-*.ova
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
    datacenter:
        description:
            - The name of the datacenter.
        required: True
    cluster:
        description:
            - The name of the vCenter cluster
        required: True
    vmname:
        description:
            - The name of the vm in vcenter
        required: True
    ovftool_path:
        description:
            - The path where the ovftool is installed
        ex: /usr/local/bin/ovftool
    path_to_ova:
        description:
            - The path where the ova is located
        required: True
    ova_file:
        description:
            - The name of the ova file
        required: True
    disk_mode:
        description:
            - The disk mode for the deployment of the ova
        default: thin
        required: True
    datastore:
        description:
            - Valid vcenter datastore
        required: True
    network:
        description:
            - Name of the network/portgroup for the appliance
        required: True

    state:
        description:
            - Desired state of the disk group
        choices: ['present', 'absent']
        required: True
'''

EXAMPLE = '''
- name: vROPs ova
  vcenter_vrops_deploy:
    vmname: "{{ vrops_vm_name }}"
    datastore: "{{ vrops_vm_datastore }}"
    disk_mode: "{{ vrops_vm_disk_mode }}"
    network: "{{ vrops_vm_network }}"
    ip_protocol: "{{ vrops_vm_ip_protocol }}"
    gateway: "{{ vrops_vm_network_gatway }}"
    dns_server: "{{ vrops_vm_network_dns }}"
    ip_address: "{{ vrops_vm_network_ip_address }}"
    netmask: "{{ vrops_vm_network_netmask }}"
    deployment_size: "{{ vrops_vm_deployment_size }}"
    enable_ssh: "{{ vrops_vm_enable_ssh }}"
    state: "{{ global_state }}"
  register: vrops_deploy
  tags:
    - deploy_vrops_ova
'''


try:
    import time
    import requests
    import inspect
    import logging
    from pyVmomi import vim, vmodl
    IMPORTS = True
except ImportError:
    IMPORTS = False

## Logging
LOG = logging.getLogger(__name__)
handler = logging.FileHandler('/var/log/chaperone/os_neutron_lbaas.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
LOG.addHandler(handler)
LOG.setLevel(logging.DEBUG)

def log(message=None):
    func = inspect.currentframe().f_back.f_code
    msg="Method: {} Line Number: {} Message: {}".format(func.co_name, func.co_firstlineno, message)
    LOG.debug(msg)

class VropsDeploy(object):
    """docstring for VropsDeploy"""
    def __init__(self, module):
        super(VropsDeploy, self).__init__()
        self.module    = module
        self.si        = connect_to_api(module)
        self.name      = module.params['vmname']
        self.datastore = module.params['datastore']
        self.network   = module.params['network']
        self.vm        = None

    def _fail(self, msg=None):
        if not msg: msg = "General Error occured"
        log(msg)
        self.module.fail_json(msg=msg)

    def run_state(self):
        log("---------------------------")
        changed = False
        current_state = self.check_state()

        self.module.exit_json(changed=changed, msg=msg)

    def state_delete(self):
        pass

    def state_create(self):
        #deploy ova
        #wait for power on
        #wait for api
        pass

    def wait_for_power(self):
        pass

    def wait_for_api(self):
        pass

    def check_datastore(self):
        return True

    def check_network(self):
        return True

    def check_state(self):
        state = 'absent'

        network_state = self.check_network()
        log("Network State: {}".format(network_state))

        if not network_state:
            msg = "Failed to Find Network: {}".format(self._network)
            self._fail(msg)

        datastore_state = self.check_datastore()
        log("Datastore State: {}".format(datastore_state))

        if not datastore_state:
            msg = "Failed to find Datastore: {}".format(self._datastore)
            self._fail(msg)

        self.vm = find_vm_by_name(self.si, self.vmname)

        if self.vm:
            state = 'present'

        log("Current State: {}".format(state))
        return state


def main():
    argument_spec = vmware_argument_spec()

    argument_spec.update(
        dict(
            vmname=dict(required=True, type='str', default='vrop_manager'),
            datastore=dict(required=True, type='str'),
            disk_mode=dict(required=True, type='str', default='thin'),
            network=dict(required=True, type='str', default='VM Network'),
            gateway=dict(required=False, type='str'),
            dns_server=dict(required=False, type='str'),
            ip_address=dict(required=False, type='str'),
            netmask=dict(required=False, type='str'),
            deployment_size=dict(required=True,
                                 default='small',
                                 choices=['small', 'medium', 'large',
                                          'smallrc', 'largerc', 'xsmall']),
            enable_ssh=dict(required=True, type='bool', default=True),
            ip_protocol=dict(required=False, type='str'),
            state=dict(default='present', choices=['present', 'absent']),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=False,
                           required_together=[['network', 'gateway', 'dns_server',
                                              'ip_address', 'netmask', 'ip_protocol']])

    if not IMPORTS:
        module.fail_json(msg="Failed to import modules")

    vrops = VropsDeploy(module)
    vrops.run_state()


from ansible.module_utils.basic import *
from ansible.module_utils.vmware import *

if __name__ == '__main__':
    main()
