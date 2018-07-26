#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks Thunder gslb service-ip objects
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

ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: a10_network_vlan
version_added: 0.1
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
    choises: ['present', 'absent', 'current', 'statistics', 'operational']

  vlan_num:
    description:
      - Number of VLAN (number)
    required: true
    choises: 2-4094
  name:
    description:
      - Name of VLAN (string: 1-63 characters)
    required: false
  user_tag:
    description:
      - Customized tag of VLAN (string: 1-127 characters)
    required: false
  shared_vlan:
    description:
      - Configure VLAN as a shared VLAN (boolean)
    required: false
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
    format:
      tagged-ethernet-start:
        description: Port number (number)
        required: true
      tagged-ethernet-end:
        description: Port number (number)
        required: true
  tagged_trunk_list:
    description:
      - Tagged trunk list (List of tagged-trunk-start and tagged-trunk-end)
    required: false
    format:
      tagged-trunk-start:
        description: Port number (number)
        required: true
      tagged-trunk-end:
        description: Port number (number)
        required: true
  untagged_eth_list:
    description:
      - Untagged ethernet list (List of untagged-ethernet-start and untagged-ethernet-end)
    required: false
    format:
      untagged-ethernet-start:
        description: Port number (number)
        required: true
      untagged-ethernet-end:
        description: Port number (number)
        required: true
  untagged_trunk_list:
    description:
      - Untagged trunk list (List of untagged-trunk-start and untagged-trunk-end)
    required: false
    format:
      untagged-trunk-start:
        description: Port number (number)
        required: true
      untagged-trunk-end:
        description: Port number (number)
        required: true
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
FIRST_LEVEL = 'network'
SECOND_LEVEL = 'vlan'
SECOND_LEVEL_LIST = 'vlan-list'

MANDATORY_ATTRIBUTES = {
    'vlan_num': 'vlan-num'
}

COMPONENT_ATTRIBUTES = {
    'name': 'name',
    'user_tag': 'user-tag',
    've': 've',
    'untagged_lif': 'untagged-lif',
}

COMPONENT_ATTRIBUTES_BOOLEAN = {
    'shared_vlan': 'shared-vlan',
}

COMPONENT_ATTRIBUTES_LIST = {
    'tagged_eth_list': 'tagged-eth-list',
    'tagged_trunk_list': 'tagged-trunk-list',
    'untagged_eth_list': 'untagged-eth-list',
    'untagged_trunk_list': 'untagged-trunk-list'
}    

COMPONENT_ATTRIBUTES_LIST_MANDATORIES = {
    'tagged_eth_list': ['tagged-ethernet-start', 'tagged-ethernet-end'],
    'tagged_trunk_list': ['tagged-trunk-start', 'tagged-trunk-end'],
    'untagged_eth_list': ['untagged-ethernet-start', 'untagged-ethernet-end'],
    'untagged_trunk_list': ['untagged-trunk-start', 'untagged-trunk-end']
}

COMPONENT_ATTRIBUTES_ALL = {}
COMPONENT_ATTRIBUTES_ALL.update(COMPONENT_ATTRIBUTES)
COMPONENT_ATTRIBUTES_ALL.update(COMPONENT_ATTRIBUTES_BOOLEAN)
COMPONENT_ATTRIBUTES_ALL.update(COMPONENT_ATTRIBUTES_LIST)
        
MUTUALLY_EXCLUSIVE_ATTRIBUTES_SET = [
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
            vlan_num=dict(type='int', required=True),
            name=dict(type='str', required=False),
            user_tag=dict(type='str', required=False),
            shared_vlan=dict(type='bool', required=False, choises=['yes','no']),
            ve=dict(type='int', required=False),
            tagged_eth_list=dict(type='list', required=False),
            tagged_trunk_list=dict(type='list', required=False),
            untagged_eth_list=dict(type='list', required=False),
            untagged_trunk_list=dict(type='list', required=False),
            untagged_lif=dict(type='str', required=False)
        )
    )
    return rv


# Open aXAPI session (to obtain signature)
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


# Validate parameters (currently no validation)
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


# Change device-context for aVCS
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
    
    # Initialize return values
    differences = 0
    config_before = {}

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL, method='GET', body='', signature=signature)
        if axapi_failure(result_list):
            axapi_close_session(module, signature)
            module.fail_json(msg="Failed to obtain current %s setup %s." % (FIRST_LEVEEL, result_list))
        else:
            component_list = []
            if result_list[FIRST_LEVEL].has_key(SECOND_LEVEL_LIST):
                result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL, method='GET', body='', signature=signature)
                for config_list in result_list[SECOND_LEVEL_LIST]:
                    mandatory_attributes_in_config = []
                    for mandatory_attribute_in_config in MANDATORY_ATTRIBUTES.values():
                        mandatory_attributes_in_config.append(config_list[mandatory_attribute_in_config])
                    component_list.append(mandatory_attributes_in_config)
            else:
                result_list = {
                    SECOND_LEVEL: {
                    }
                }

            config_before = copy.deepcopy(result_list)

            mandatory_attributes_in_playbook = []
            for mandatory_attribute_in_playbook in MANDATORY_ATTRIBUTES.keys():
                if not(module.params[mandatory_attribute_in_playbook] is None):
                    mandatory_attributes_in_playbook.append(module.params[mandatory_attribute_in_playbook])

            if mandatory_attributes_in_playbook in component_list:
                component_path = mandatory_attributes_in_playbook[0]
                mandatory_attributes_in_playbook.pop(0)
                for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
                    component_path = component_path+'+'+mandatory_attribute_in_playbook
                result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+str(component_path), method='GET', body='', signature=signature)
                if axapi_failure(result_list):
                    axapi_close_session(module, signature)
                    module.fail_json(msg="Failed to obtain %s %s %s information." % (FIRST_LEVEL, SECOND_LEVEL, component_path))
                else:
                    config_before = copy.deepcopy(result_list)
                    json_post = copy.deepcopy(result_list)
                    diff_sw = False
                    same_sw = False
                    absent_sw = False

                    for playbook_attribute in COMPONENT_ATTRIBUTES.keys():
                        if not(module.params[playbook_attribute] is None):
                            if result_list[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES[playbook_attribute]):
                                if result_list[SECOND_LEVEL][COMPONENT_ATTRIBUTES[playbook_attribute]] != module.params[playbook_attribute]:
                                    diff_sw = True
                                else:
                                    same_sw = True
                                    if status == 'absent':
                                        json_post[SECOND_LEVEL].pop(COMPONENT_ATTRIBUTES[playbook_attribute])
                            else:
                                absent_sw = True
                                if status == 'present':
                                    for mutually_exclusive_list in MUTUALLY_EXCLUSIVE_ATTRIBUTES_SET:
                                        if playbook_attribute in mutually_exclusive_list:
                                            mutually_exclusive_list.remove(playbook_attribute)
                                            for current_attribute_removed in mutually_exclusive_list:
                                                if json_post[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES_ALL[current_attribute_removed]):
                                                    json_post[SECOND_LEVEL].pop(COMPONENT_ATTRIBUTES_ALL[current_attribute_removed])
                                    json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES[playbook_attribute]] =  module.params[playbook_attribute]

                    for playbook_attribute in COMPONENT_ATTRIBUTES_BOOLEAN.keys():
                        if not(module.params[playbook_attribute] is None):
                            if result_list[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute]):
                                if result_list[SECOND_LEVEL][COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute]] != module.params[playbook_attribute]:
                                    diff_sw = True
                                else:
                                    same_sw = True
                                    if status == 'absent':
                                        json_post[SECOND_LEVEL].pop(COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute])
                            else:
                                absent_sw = True
                                if status == 'present':
                                    for mutually_exclusive_list in MUTUALLY_EXCLUSIVE_ATTRIBUTES_SET:
                                        if playbook_attribute in mutually_exclusive_list:
                                            mutually_exclusive_list.remove(playbook_attribute)
                                            for current_attribute_removed in mutually_exclusive_list:
                                                if json_post[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES_ALL[current_attribute_removed]):
                                                    json_post[SECOND_LEVEL].pop(COMPONENT_ATTRIBUTES_ALL[current_attribute_removed])
                                    json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute]] =  module.params[playbook_attribute]

                    for playbook_attribute in COMPONENT_ATTRIBUTES_LIST.keys():
                        if not(module.params[playbook_attribute] is None):
                            if result_list[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES_LIST[playbook_attribute]):
                                json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]] = []
                                current_lists = copy.deepcopy(result_list[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]])
                                playbook_lists = copy.deepcopy(module.params[playbook_attribute])
                                current_lists_rest = copy.deepcopy(current_lists)
                                playbook_lists_rest = copy.deepcopy(playbook_lists)
                                for playbook_list in playbook_lists:
                                    for current_list in current_lists:
                                        current_list_mandatory_values = []
                                        current_list_options = copy.deepcopy(current_list)
                                        playbook_list_mandatory_values = []
                                        playbook_list_options = copy.deepcopy(playbook_list)
                                        json_post_list = copy.deepcopy(current_list)
                                        if COMPONENT_ATTRIBUTES_LIST_MANDATORIES.has_key(playbook_attribute):
                                            for list_mandatory_key in COMPONENT_ATTRIBUTES_LIST_MANDATORIES[playbook_attribute]:
                                                current_list_mandatory_values.append(current_list[list_mandatory_key])
                                                current_list_options.pop(list_mandatory_key)
                                                playbook_list_mandatory_values.append(playbook_list[list_mandatory_key])
                                                playbook_list_options.pop(list_mandatory_key)
                                        if set(current_list_mandatory_values) == set(playbook_list_mandatory_values):
                                            if playbook_list_options != {}:                                                
                                                playbook_options_included = True
                                                if list(set(playbook_list_options) - set(current_list_options)) != []:
                                                    playbook_options_included = False
                                                for playbook_list_option_key in playbook_list_options.keys():
                                                    if current_list_options.has_key(playbook_list_option_key):
                                                        if playbook_list_options[playbook_list_option_key] != current_list_options[playbook_list_option_key]:
                                                            playbook_options_included = False
                                                if playbook_options_included:
                                                    same_sw = True
                                                else:
                                                    diff_sw = True
                                                    if status == 'present':
                                                        for playbook_list_key in playbook_list.keys():
                                                            json_post_list[playbook_list_key] = playbook_list[playbook_list_key]
                                                if status == 'absent':
                                                    if playbook_list_options != []:
                                                        for playbook_list_key in playbook_list.keys():
                                                            if (json_post_list[playbook_list_key] == playbook_list[playbook_list_key]) and not(playbook_list_key in COMPONENT_ATTRIBUTES_LIST_MANDATORIES[playbook_attribute]):
                                                                json_post_list.pop(playbook_list_key)
                                                json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]].append(json_post_list)
                                            else:
                                                if status == 'absent':
                                                    diff_sw = True
                                                if status == 'present':
                                                    json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]].append(current_list)
                                            current_lists_rest.remove(current_list)
                                            playbook_lists_rest.remove(playbook_list)
                                if current_lists_rest != []:
                                    for current_list in current_lists_rest:
                                        json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]].append(current_list)
                                if playbook_lists_rest != []:
                                    absent_sw = True
                                    if status == 'present':
                                        for playbook_list in playbook_lists_rest:
                                            json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]].append(playbook_list)
                            else:
                                absent_sw = True
                                if status == 'present':
                                    for mutually_exclusive_list in MUTUALLY_EXCLUSIVE_ATTRIBUTES_SET:
                                        if playbook_attribute in mutually_exclusive_list:
                                            mutually_exclusive_list.remove(playbook_attribute)
                                            for current_attribute_removed in mutually_exclusive_list:
                                                if json_post[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES_ALL[current_attribute_removed]):
                                                    json_post[SECOND_LEVEL].pop(COMPONENT_ATTRIBUTES_ALL[current_attribute_removed])
                                    json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]] = module.params[playbook_attribute]

                    if absent_sw and not(diff_sw) and not(same_sw):
                        differences = 4
                    elif not(absent_sw) and not(diff_sw) and not(same_sw):
                        differences = 5
                    elif not(absent_sw) and not(diff_sw) and same_sw:
                        differences = 2
                    else:
                        differences = 3
            else: #there is no existing SECOND_LEVEL component in the current config
                differences = 1
                if status == 'present':
                    json_post = {
                        SECOND_LEVEL: {
                        }
                    }                    
                    for playbook_attribute in MANDATORY_ATTRIBUTES.keys():
                        if not(module.params[playbook_attribute] is None):
                            json_post[SECOND_LEVEL][MANDATORY_ATTRIBUTES[playbook_attribute]] =  module.params[playbook_attribute]
                    for playbook_attribute in COMPONENT_ATTRIBUTES.keys():
                        if not(module.params[playbook_attribute] is None):
                            json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES[playbook_attribute]] =  module.params[playbook_attribute]
                    for playbook_attribute in COMPONENT_ATTRIBUTES_BOOLEAN.keys():
                        if not(module.params[playbook_attribute] is None):
                            json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute]] =  module.params[playbook_attribute]
                    for playbook_attribute in COMPONENT_ATTRIBUTES_LIST.keys():
                        if not(module.params[playbook_attribute] is None):
                            json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]] = module.params[playbook_attribute]
                elif status == 'absent':
                    json_post = {}

    return differences,config_before,json_post


# Let the configuration present
def present(module, signature, result):
    differences, config_before, json_post = diff_config(module, signature, result, status='present')
    result['original_message'] = differences
    if differences == 1:
        result['msg'] = "Playbook's root element is not in the current config."
    elif differences == 2:
        result['msg'] = "Playbook's config is entirely included in the current config."
    elif differences == 3:
        result['msg'] = "Playbook's config is partially different from current config."
    elif differences == 4:
        result['msg'] = "All playbook's config attributes are not in the current config."
    elif differences == 5:
        result['msg'] = "Playbook indicates only the root element in the current config."
    result['post_config'] = json_post

    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        if differences == 1:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/', method='POST', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to create %s %s: %s." % (FIRST_LEVEL, SECOND_LEVEL, result_list))
            else:
                result["changed"] = True
        elif differences == 3 or differences == 4:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES.keys())
            component_path = module.params[mandatory_attributes_in_playbook[0]]
            mandatory_attributes_in_playbook.pop(0)
            for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
                component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
            result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+str(component_path), method='POST', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to modify %s %s: %s." % (FIRST_LEVEL, SECOND_LEVEL, result_list))
            else:
                result["changed"] = True
        else:
            result_list = copy.deepcopy(config_before)
        
        result['diff']['before'] = config_before
        result['diff']['after'] = result_list
                    
    return result


# Let the configuration absent
def absent(module, signature, result):
    differences, config_before, json_post = diff_config(module, signature, result, status='absent')
    result['original_message'] = differences
    if differences == 1:
        result['msg'] = "Playbook's root element is not in the current config."
    elif differences == 2:
        result['msg'] = "Playbook's config is entirely included in the current config."
    elif differences == 3:
        result['msg'] = "Playbook's config is partially different from current config."
    elif differences == 4:
        result['msg'] = "All playbook's config attributes are not in the current config."
    elif differences == 5:
        result['msg'] = "Playbook indicates only the root element in the current config."
    result['post_config'] = json_post

    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        if differences == 2 or differences == 3:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES.keys())
            component_path = module.params[mandatory_attributes_in_playbook[0]]
            mandatory_attributes_in_playbook.pop(0)
            for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
                component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
            result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+str(component_path), method='PUT', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to delete elemetns of %s %s: %s." % (FIRST_LEVEL, SECOND_LEVEL, result_list))
            else:
                if config_before != result_list:
                    result["changed"] = True
                else:
                    result["changed"] = False
        elif differences == 5:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES.keys())
            component_path = module.params[mandatory_attributes_in_playbook[0]]
            mandatory_attributes_in_playbook.pop(0)
            for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
                component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
            result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+str(component_path), method='DELETE', body='', signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to delete %s %s: %s." % (FIRST_LEVEL, SECOND_LEVEL, result_list))
            else:
                result["changed"] = True
        else:
            result_list = copy.deepcopy(config_before)
            
        result['diff']['before'] = config_before
        result['diff']['after'] = result_list
                    
    return result


# Return current config
def current(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES.keys())
        component_path = module.params[mandatory_attributes_in_playbook[0]]
        mandatory_attributes_in_playbook.pop(0)
        for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
            component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
        if component_path:
            result['config'] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+str(component_path), method='GET', body='', signature=signature)
        else:
            result['config'] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/', method='GET', body='', signature=signature)

    return result


# Return current statistics
def statistics(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES.keys())
        component_path = module.params[mandatory_attributes_in_playbook[0]]
        mandatory_attributes_in_playbook.pop(0)
        for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
            component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
        if component_path:
            result["stats"] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+str(component_path)+'/stats', method='GET', body='', signature=signature)
        else:
            result["stats"] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/stats', method='GET', body='', signature=signature)
    return result


# Return current operational data
def operational(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES.keys())
        component_path = module.params[mandatory_attributes_in_playbook[0]]
        mandatory_attributes_in_playbook.pop(0)
        for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
            component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
        if component_path:
            result["oper"] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+str(component_path)+'/oper', method='GET', body='', signature=signature)
        else:
            result["oper"] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/oper', method='GET', body='', signature=signature)
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
        msg="",
        post_config="",
        stats="",
        oper="",
        diff=dict(
            before=dict(),
            after=dict()
        )
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

    if (state == 'present') or (state == 'absent'):
        differences, config_before, json_post = diff_config(module, signature, result, status=state)
        result['original_message'] = differences
        if differences == 1:
            result['msg'] = "Playbook's root element is not in the current config."
        elif differences == 2:
            result['msg'] = "Playbook's config is entirely included in the current config."
        elif differences == 3:
            result['msg'] = "Playbook's config is partially different from current config."
        elif differences == 4:
            result['msg'] = "All playbook's config attributes are not in the current config."
        elif differences == 5:
            result['msg'] = "Playbook indicates only the root element in the current config."
        result['post_config'] = json_post
        result['diff']['before'] = config_before

        if state == 'present':
            if differences == 1 or differences == 3 or differences ==4:
                result['changed'] = True
                result['diff']['after'] = json_post
            else:
                result['changed'] = False
                result['diff']['after'] = config_before
        elif state == 'absent':
            if differences == 2 or differences == 3:
                if config_before != json_post:
                    result['changed'] = True
                else:
                    result['changed'] = False
                result['diff']['after'] = json_post
            elif differences == 5:
                result['changed'] = True
                result['diff']['after'] = ""
            else:
                result['changed'] = False
                result['diff']['after'] = config_before
    else:
        result['changed'] = False
        result = current(module, signature, result)
        result['post_config'] = ""
        result['diff']['before'] = result['config']
        result['diff']['after'] = result['config']

    axapi_close_session(module, signature)

    return result

    
# Run commands
def run_command(module):
    run_errors = []
    
    result = dict(
        changed=False,
        original_message="",
        msg="",
        post_config="",
        stats="",
        oper="",
        diff=dict(
            before=dict(),
            after=dict()
        )
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
        mutually_exclusive=MUTUALLY_EXCLUSIVE_ATTRIBUTES_SET
    )

    if module.check_mode:
        result = dry_run_command(module)
    else:
        result = run_command(module)

    module.exit_json(**result)


import json, copy

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec, fetch_url
from ansible.module_utils.a10 import axapi_call_v3, axapi_call, axapi_authenticate_v3, axapi_authenticate, axapi_failure

if __name__ == '__main__':
    main()
