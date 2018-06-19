#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks Thunder vlan objects
(c) 2018, Kentaro Ishizuka <kishizuka@a10networks.com>

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: a10_network_vlan
version_added: 1.0
short_description: Manage A10 Networks Thunder/vThunder devices
description:
    - Manage network vlan objects on A10 Networks devices via aXAPI.
author: "Kentaro Ishizuka (@kishizuka4989)"
extends_documentation_fragment: a10
options:
  a10_host:
    description:
      - A10 Thunder/vThunder hostname or IP address for management port
    required: true
  a10_username:
    description:
      - A10 Thunder/vThunder user name
    required: true
  a10_password:
    description:
      - A10 Thunder/vThunder user's password
    required: true
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']
  axapi_version:
    description:
      - A10 Thunder/vThunder aXAPI version (2.1 or 3)
    required: false
    default: ['3']
    choises: ['2.1','3']
  partition:
    description:
      - ADP (partition) name to be modified
    required: false
    default: ['shared']
  device:
    description:
      - aVCS device ID to be modified
    required: false
  write_config:
    description:
      - Write the configuration to the memory or not
    required: false
    default: ['yes']
    choises: ['yes', 'no']
  state:
    description:
      - State for the configuration in the playbook
    required: true
    choises: ['present', 'absent', 'current']

  name:
    description:
      - Name of VLAN (string: 1-63 characters)
    required: false
  user_tag:
    description:
      - Customized tag of VLAN (string: 1-127 characters)
    required: false  
  vlan_num:
    description:
      - Number of VLAN (number)
    required: false (require if the state is 'present' or 'absent')
    choises: 2-4094
  shared_vlan:
    description:
      - Configure VLAN as a shared VLAN (boolean)
    required: false
    default: no
    choises: ['yes','no']
  ve:
    description:
      - Router interface VE number (number)
    required: false
    choises: 2-4094
  tagged_eth_list:
    description: 
      - Tagged ethernet list (List of tagged-ethernet-start and tagged-ethernet-end)
    required: false
  tagged_trunk_list:
    description: 
      - Tagged trunk list (List of tagged-trunk-start and tagged-trunk-end)
    required: false
  untagged_eth_list:
    description: 
      - Untagged ethernet list (List of untagged-ethernet-start and untagged-ethernet-end)
    required: false
  untagged_trunk_list:
    description: 
      - Untagged trunk list (List of untagged-trunk-start and untagged-trunk-end)
    required: false
  untagged_lif:
    description: 
      - Untagged logical tunnel interface (number)
    required: false
    choises: 1-128
'''

RETURN = '''
#
'''

EXAMPLES = '''
# Create a new VLAN 100 with untagged ethernet port 4
- a10_network_vlan:
    a10_host: 192.168.1.1
    a10_username: myadmin
    a10_password: mypassword
    validate_certs: no
    axapi_version: 3
    partition: test
    device: 1
    write_config: yes
    state: present
    name: test_vlan
    user_tag: test_vlan_tag
    vlan_num: 100
    ve: 100
    untagged_eth_list:
      - untagged-ethernet-start: 4
        untagged-ethernet-end: 4
'''


def get_default_argspec():
    rv = dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        axapi_version=dict(type='str', required=False, default='3', choises=['2.1','3']),
        partition=dict(type='str', required=False, default='shared'),
        device=dict(type='str', required=False),
        write_config=dict(type='bool', required=False, default='yes', choises=['yes','no']),
        state=dict(type='str', required=True, choises=['present','absent','current'])
    )
    rv.update(url_argument_spec())
    return rv


def get_argspec():
    rv = get_default_argspec()
    rv.update(
        dict(
            name=dict(type='str', required=False),
            user_tag=dict(type='str', required=False),
            vlan_num=dict(type='str', required=False),
            shared_vlan=dict(type='str', required=False, default='no', choises=['yes','no']),
            ve=dict(type='int', required=False),
            tagged_eth_list=dict(type='list', required=False),
            tagged_trunk_list=dict(type='list', required=False),
            untagged_eth_list=dict(type='list', required=False),
            untagged_trunk_list=dict(type='list', required=False),
            untagged_lif=dict(type='int', required=False)
        )
    )
    return rv

def axapi_open_session(module):
    host = module.params['a10_host']
    username = module.params['a10_username']
    password = module.params['a10_password']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        axapi_auth_url = 'https://{}/axapi/v3/auth/'.format(host)
        rv = axapi_authenticate_v3(module, axapi_auth_url, username, password)
    elif axapi_version == '2.1':
        axapi_auth_url = 'https://{}/services/rest/V2.1/'.format(host)
        rv = axapi_authenticate(module, axapi_auth_url, username, password)

    if axapi_failure(rv):
        module.fail_json(msg="Failed to open aXAPI session")

    module.debug("Succeed open aAPI session")
    return rv


def axapi_close_session(module, signature):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        axapi_logoff_url = 'https://{}/axapi/v3/logoff/'.format(host)
        result = axapi_call_v3(module, axapi_logoff_url, method='POST', body='', signature=signature)
    elif axapi_version == '2.1':
        axapi_logoff_url = signature + '&method=session.close'
        result = axapi_call(module, axapi_logoff_url)
    
    if axapi_failure(result):
        module.fail_json(msg="Failed to close aXAPI session")

    module.debug("Succeed close aAPI session")


def validate(module, signature):
    rc = True
    errors = []

    module.debug("Succeed validation of parameters")
    return rc, errors


def change_partition(module, signature):
    host = module.params['a10_host']
    partition = module.params['partition']
    axapi_version = module.params['axapi_version']
    
    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        result = axapi_call_v3(module, axapi_base_url+'active-partition/'+partition, method='POST', body='', signature=signature)

    if axapi_failure(result):
        axapi_close_session(module, signature)
        module.fail_json(msg="Failed to change partition")

    module.debug("Succeed changing partitions")



def present(module, signature, result):
    module.debug("Succeed to execute present")
    return result


def absent(module, signature, result):
    module.debug("Succeed to execute absent")
    return result


def current(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']
    vlan_num = module.params['vlan_num']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        if vlan_num:
            result["msg"] = axapi_call_v3(module, axapi_base_url+'network/vlan/'+vlan_num, method='GET', body='', signature=signature)
        else:
            result["msg"] = axapi_call_v3(module, axapi_base_url+'network/vlan/', method='GET', body='', signature=signature)
    module.debug("Succeed to execute current")
    return result
    

def run_command(module):
    run_errors = []
    
    result = dict(
        changed=False,
        original_message="",
        msg=""
    )

    partition = module.params['partition']
    device = module.params['device']
    write_config = module.params['write_config']
    state = module.params['state']

    valid = True

    signature = axapi_open_session(module)
    module.debug("Succeed to achieve signature %s" % signature)

    valid, validation_errors = validate(module, signature)
    map(run_errors.append, validation_errors)
    module.debug("Succeed validation")
    
    if not valid:
        result["messages"] = "Parameter validation failure."
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    if partition:
        change_partition(module, signature)

    module.debug("Main routine based on status")
    if state == 'present':
        result = present(module, signature, result)
    elif state == 'absent':
        result = absent(module, signature, result)
    elif state == 'current':
        result = current(module, signature, result)

    axapi_close_session(module, signature)

    return result


# Main routine
def main():
    module = AnsibleModule(
        argument_spec=get_argspec(),
        supports_check_mode=True
    )

    result = run_command(module)

    module.exit_json(changed=result["changed"],msg=result["msg"])


import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call_v3, axapi_call, axapi_authenticate_v3, axapi_authenticate, axapi_failure

if __name__ == '__main__':
    main()
