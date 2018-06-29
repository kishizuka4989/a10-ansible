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
    choises: ['present', 'absent', 'current','statistics','operational']

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

# Global variables
VLAN_MUTUALLY_EXCLUSIVE_SET = [
    ['tagged_eth_list','tagged_trunk_list','untagged_eth_list','untagged_trunk_list','untagged_lif']
]

# Get default argspecs for all modules
def get_default_argspec():
    rv = dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        axapi_version=dict(type='str', required=False, default='3', choises=['2.1','3']),
        partition=dict(type='str', required=False, default='shared'),
        device=dict(type='str', required=False),
        write_config=dict(type='bool', required=False, default='yes', choises=['yes','no']),
        state=dict(type='str', required=True, choises=['present','absent','current','statistics','operational'])
    )
    rv.update(url_argument_spec())
    return rv

# Get module specific argspecs 
def get_argspec():
    rv = get_default_argspec()
    rv.update(
        dict(
            name=dict(type='str', required=False),
            user_tag=dict(type='str', required=False),
            vlan_num=dict(type='int', required=False),
            shared_vlan=dict(type='bool', required=False, default='no', choises=['yes','no']),
            ve=dict(type='int', required=False),
            tagged_eth_list=dict(type='list', required=False),
            tagged_trunk_list=dict(type='list', required=False),
            untagged_eth_list=dict(type='list', required=False),
            untagged_trunk_list=dict(type='list', required=False),
            untagged_lif=dict(type='int', required=False)
        )
    )
    return rv


# Open aXAPI session
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
        module.fail_json(msg="Failed to open aXAPI session: %s" % result['response']['err']['msg'])

    return rv


# Close aXAPI session
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
        module.fail_json(msg="Failed to close aXAPI session: %s" % result['response']['err']['msg'])


# Validate parameters
def validate(module, signature):
    rc = True
    errors = []

    return rc, errors


# Change partition
def change_partition(module, signature):
    host = module.params['a10_host']
    partition = module.params['partition']
    axapi_version = module.params['axapi_version']
    
    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        result = axapi_call_v3(module, axapi_base_url+'active-partition/'+partition, method='POST', body='', signature=signature)

    if axapi_failure(result):
        axapi_close_session(module, signature)
        module.fail_json(msg="Failed to change partition: %s" % result['response']['err']['msg'])


# Change device-context (for aVCS)
def change_device_context(module, signature):
    host = module.params['a10_host']
    device = module.params['device']
    axapi_version = module.params['axapi_version']
    
    if axapi_version == '3':
        # Since device-context does not return any content, axapi_call_v3 is not used here
        json_post = {"device-context": {"device-id": device}}
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        headers = {'content-type': 'application/json', 'Authorization': 'A10 %s' % signature}
        rsp, info = fetch_url(module, axapi_base_url+'device-context', method='POST', data=json.dumps(json_post), headers=headers)
        if not rsp or info['status'] >= 400:
            module.fail_json(msg="failed to connect (status code %s), error was %s" % (info['status'], info.get('msg', 'no error given')))
        rsp.close()


# Check differences between current and playbook's configs
# Return value 'differences" indicates as follows
# 1: Playbook's root element is not in the current config
# 2: Playbook's config is entirely included in the current config
# 3: Playbook's config is partially different from current config
# 4: All playbook's config attributes are not in the current config
# 5: Playbook indicates only the root element in the current config
def diff_config(module, signature, result, status):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']
    vlan_num = module.params['vlan_num']
    name = module.params['name']
    user_tag = module.params['user_tag']
    shared_vlan = module.params['shared_vlan']
    ve = module.params['ve']
    tagged_eth_list = module.params['tagged_eth_list']
    tagged_trunk_list = module.params['tagged_trunk_list']
    untagged_eth_list = module.params['untagged_eth_list']
    untagged_trunk_list = module.params['untagged_trunk_list']
    untagged_lif = module.params['untagged_lif']
    
    # Initialize return value
    differences = 0

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        result_list = axapi_call_v3(module, axapi_base_url+'network', method='GET', body='', signature=signature)
        if axapi_failure(result_list):
            axapi_close_session(module, signature)
            module.fail_json(msg="Failed to obtain current network setup %s." % result_list)
        else:
            if result_list['network'].has_key('vlan-list'):
                result_list = axapi_call_v3(module, axapi_base_url+'network/vlan', method='GET', body='', signature=signature)
                vlan = [vlan['vlan-num'] for vlan in result_list['vlan-list']]
            else:
                result_list = {
                    "vlan": {
                    }
                }
                vlan = []

            if vlan_num in vlan:
                result_list = axapi_call_v3(module, axapi_base_url+'network/vlan/'+str(vlan_num), method='GET', body='', signature=signature)
                if axapi_failure(result_list):
                    axapi_close_session(module, signature)
                    module.fail_json(msg="Failed to obtain vlan information.")
                else:
                    json_post = result_list
                    json_post['vlan'].pop('uuid')
                    json_post['vlan'].pop('a10-url')
                    diff_sw = 0
                    same_sw = 0
                    absent_sw = 0
                    if name:
                        if result_list['vlan'].has_key('name'):
                            if result_list['vlan']['name'] != name:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('name')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['name'] = name
                    if user_tag:
                        if result_list['vlan'].has_key('user-tag'):
                            if result_list['vlan']['user-tag'] != user_tag:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('user-tag')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['user-tag'] = user_tag
                    if int(shared_vlan):
                        if result_list['vlan'].has_key('shared-vlan'):
                            if result_list['vlan']['shared-vlan'] != shared_vlan:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('shared-vlan')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['shared-vlan'] = shared_vlan
                    if ve:
                        if result_list['vlan'].has_key('ve'):
                            if result_list['vlan']['ve'] != ve:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('ve')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['ve'] = ve
                    if tagged_eth_list:
                        if result_list['vlan'].has_key('tagged-eth-list'):
                            if result_list['vlan']['tagged-eth-list'] != tagged_eth_list:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('tagged-eth-list')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['tagged-eth-list'] = tagged_eth_list
                    if tagged_trunk_list:
                        if result_list['vlan'].has_key('tagged-trunk-list'):
                            if result_list['vlan']['tagged-trunk-list'] != tagged_trunk_list:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('tagged-trunk-list')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['tagged-trunk-list'] = tagged_trunk_list
                    if untagged_eth_list:
                        if result_list['vlan'].has_key('untagged-eth-list'):
                            if result_list['vlan']['untagged-eth-list'] != untagged_eth_list:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('untagged-eth-list')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['untagged-eth-list'] = untagged_eth_list
                    if untagged_trunk_list: 
                        if result_list['vlan'].has_key('untagged-trunk-list'):
                            if result_list['vlan']['untagged-trunk-list'] != untagged_trunk_list:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('untagged-trunk-list')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['untagged-trunk-list'] = untagged_trunk_list
                    if untagged_lif:
                        if result_list['vlan'].has_key('untagged-lif'):
                            if result_list['vlan']['untagged-lif'] != untagged_lif:
                                diff_sw = 1
                            else:
                                same_sw = 1
                                if status == 'absent':
                                    json_post['vlan'].pop('untagged-lif')
                        else:
                            absent_sw = 1
                        if status == 'present':
                            json_post['vlan']['untagged-lif'] = untagged_lif

                    if absent_sw and not(diff_sw) and not(same_sw):
                        differences = 4
                    elif diff_sw:
                        differences = 3
                    elif same_sw and not(diff_sw):
                        differences = 2
                    else:
                        differences = 5
            else: #there is no existing vlan whose number is vlan-num
                differences = 1
                if status == 'present':
                    json_post = {
                        "vlan": {
                            "vlan-num": vlan_num
                        }
                    }
                    if name:
                        json_post['vlan']['name'] = name
                    if user_tag:
                        json_post['vlan']['user-tag'] = user_tag
                    if int(shared_vlan):
                        json_post['vlan']['shared-vlan'] = shared_vlan
                    if ve:
                        json_post['vlan']['ve'] = ve
                    if tagged_eth_list:
                        json_post['vlan']['tagged-eth-list'] = tagged_eth_list
                    if tagged_trunk_list:
                        json_post['vlan']['tagged-trunk-list'] = tagged_trunk_list
                    if untagged_eth_list:
                        json_post['vlan']['untagged-eth-list'] = untagged_eth_list
                    if untagged_trunk_list:
                        json_post['vlan']['untagged-trunk-list'] = untagged_trunk_list
                    if untagged_lif:
                        json_post['vlan']['untagged-lif'] = untagged_lif
                elif status == 'absent':
                    json_post = {}
            
    return differences, json_post


# Let the configuration present
def present(module, signature, result):
    differences, json_post = diff_config(module, signature, result, status='present')
    result['msg'] = differences
    result['original_message'] = json_post

    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']
    vlan_num = module.params['vlan_num']

    if axapi_version == '3':
        if differences == 1:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            result_list = axapi_call_v3(module, axapi_base_url+'network/vlan/', method='POST', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to create VLAN: %s." % result_list)
            else:
                result["changed"] = True
        elif differences == 3 or differences == 4:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            result_list = axapi_call_v3(module, axapi_base_url+'network/vlan/'+str(vlan_num), method='POST', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to modify VLAN: %s." % result_list)
            else:
                result["changed"] = True
                    
    return result


# Let the configuration absent
def absent(module, signature, result):
    differences, json_post = diff_config(module, signature, result, status='absent')
    result['msg'] = differences
    result['original_message'] = json_post

    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']
    vlan_num = module.params['vlan_num']

    if axapi_version == '3':
        if differences == 2 or differences == 3:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            result_list = axapi_call_v3(module, axapi_base_url+'network/vlan/'+str(vlan_num), method='PUT', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to delete elemetns of VLAN: %s." % result_list)
            else:
                result["changed"] = True
        elif differences == 5:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            result_list = axapi_call_v3(module, axapi_base_url+'network/vlan/'+str(vlan_num), method='DELETE', body='', signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to delete VLAN: %s." % result_list)
            else:
                result["changed"] = True

    return result


# Return current config
def current(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']
    vlan_num = module.params['vlan_num']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        if vlan_num:
            result["config"] = axapi_call_v3(module, axapi_base_url+'network/vlan/'+vlan_num, method='GET', body='', signature=signature)
        else:
            result["config"] = axapi_call_v3(module, axapi_base_url+'network/vlan/', method='GET', body='', signature=signature)
    return result


# Return current statistics
def statistics(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']
    vlan_num = module.params['vlan_num']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        if vlan_num:
            result["stats"] = axapi_call_v3(module, axapi_base_url+'network/vlan/'+vlan_num+'/stats', method='GET', body='', signature=signature)
        else:
            result["stats"] = axapi_call_v3(module, axapi_base_url+'network/vlan/stats', method='GET', body='', signature=signature)
    return result


# Return current operational data
def operational(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']
    vlan_num = module.params['vlan_num']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        if vlan_num:
            result["oper"] = axapi_call_v3(module, axapi_base_url+'network/vlan/'+vlan_num+'/oper', method='GET', body='', signature=signature)
        else:
            result["oper"] = axapi_call_v3(module, axapi_base_url+'network/vlan/oper', method='GET', body='', signature=signature)
    return result


# Write config to curent startup-config
def write_memory(module, signature):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']
    
    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        result = axapi_call_v3(module, axapi_base_url+'write/memory/', method='POST', body='', signature=signature)

    if axapi_failure(result):
        axapi_close_session(module, signature)
        module.fail_json(msg="Failed to write config: %s" % result['response']['err']['msg'])


# Dry run commands
def dry_run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        msg="Dry run"
    )

    ## Require checking commands

    return result

    
# Run commands
def run_command(module):
    run_errors = []
    
    result = dict(
        changed=False,
        original_message="",
        msg="",
        config="",
        stats="",
        oper=""
    )

    partition = module.params['partition']
    device = module.params['device']
    write_config = module.params['write_config']
    state = module.params['state']

    valid = True

    signature = axapi_open_session(module)

    valid, validation_errors = validate(module, signature)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["msg"] = "Parameter validation failure."
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    if partition:
        change_partition(module, signature)

    if device:
        change_device_context(module, signature)

    if state == 'present':
        result = present(module, signature, result)
    elif state == 'absent':
        result = absent(module, signature, result)
    elif state == 'current':
        result = current(module, signature, result)
    elif state == 'statistics':
        result = statistics(module, signature, result)
    elif state == 'operational':
        result = operational(module, signature, result)

    if write_config:
        write_memory(module, signature)

    axapi_close_session(module, signature)

    return result


# Main routine
def main():
    module = AnsibleModule(
        argument_spec=get_argspec(),
        supports_check_mode=True,
        mutually_exclusive=VLAN_MUTUALLY_EXCLUSIVE_SET
    )

    if module.check_mode:
        result = dry_run_command(module)
    else:
        result = run_command(module)

    module.exit_json(**result)


import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec, fetch_url
from ansible.module_utils.a10 import axapi_call_v3, axapi_call, axapi_authenticate_v3, axapi_authenticate, axapi_failure

if __name__ == '__main__':
    main()
