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
module: a10_glsb_service_ip
version_added: 0.1
short_description: Manage A10 Networks Thunder/vThunder devices
description:
    - Manage gslb service-ip objects on A10 Networks devices via aXAPI.
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

  node_name:
    description:
      - Service-ip name (string: 1-63 characters)
    required: true
  ip_address:
    description:
      - IPv4 address (string: ipv4-address)
    required: true (if there is no ipv6_address)
    mutually exclusive: ipv6_address
  ipv6_address:
    description: 
      - IPv6 address (string: ipv6-address)
    required: true (if there is no ip_address)
    mutually exclusive: ip_address
  port_list:
    description: 
      - Port list (list)
    required: false
    format:
      port-num:
        description: Port number (number)
        required: true
        choises: 0-65534
      port-proto:
        description: Protocl for port (string)
        required: true
        choises: ['tcp','udp']
      action:
        description: Enable/Disable GSLB service port (string)
        required: false
        default: enable
        choises: ['enable','disable']
      health-check:
        description: Health check monitor (string: 1-63 characters)
        required: false
        mutually exclusive: health-check-follow-port and health-check-disable
      health-check-disable:
        description: Disable health check monitor (boolean)
        required: false
        default: no
        choises: ['yes','no']
        mutually exclusive: health-check and health-check-follow-port
      health-check-follow-port:
        description: Specify which port to follow for health status (number)
        required: false
        choise: 1-65534 (port number)
        mutually exclusive: health-check and health-check-disable
      health-check-protocol-disable:
        description: Disable GSLB protocol health monitor (boolean)
        required: false
        default: no
        choises: ['yes','no']
      user-tag:
        description: Customized tag (string: 1-127 characters)
        required: false         
  action:
    description:
      - Enable/disable GSLB server (string)
    required: false
    default: enable
    choises: ['enable','disable']  
  external_ip:
    description:
      - External IPv4 address for NAT (string: ipv4-address)
    required: false
  health_check:
    description:
      - Health check monitor name (string: 1-63 characters)
    required: false
    mutually exclusive: health_check_disable
  health_check_disable:
    description:
      - Diable health check monitor (boolean)
    required: false
    default: no
    choises: ['yes','no']
    mutually exclusive: health_check
  health_check_protocol_disable:
    description: 
      - Disable GSLB protocol health monitor (boolean)
    required: false
    default: 0
    choises: ['yes','no']
  ipv6:
    description: 
      - IPv6 address mapping (string: ipv6-address)
    required: false
  user_tag:
    description: 
      - Customized tag (string: 1-127 characters)
    required: false
'''

RETURN = '''
#
'''

EXAMPLES = '''
# Create a new GSLB service-ip and port 80 and 443
- a10_gslb_service_ip:
    a10_host: 192.168.1.1
    a10_username: myadmin
    a10_password: mypassword
    validate_certs: no
    axapi_version: 3
    partition: test
    device: 1
    write_config: yes
    state: present
    node_name: VIP_HTTP
    ip_address: 100.0.0.21
    port_list:
      - port-num: 80
        port-proto: tcp
      - port-num: 443
        port-proto: tcp
'''

# Global variables
FIRST_LEVEL = 'gslb'
SECOND_LEVEL = 'service-ip'
SECOND_LEVEL_LIST = 'service-ip-list'

MANDATORY_ATTRIBUTES_IN_PLAYBOOK = [
    'node_name'
]
MANDATORY_ATTRIBUTES_IN_CONFIG = [
    'node-name'
]

COMPONENT_ATTRIBUTES = {
    'ip_address': 'ip-address',
    'ipv6_address': 'ipv6-address',
    'action': 'action',
    'external_ip': 'external-ip',
    'health_check': 'health-check',
    'ipv6': 'ipv6',
    'user_tag': 'user-tag'
}

COMPONENT_ATTRIBUTES_BOOLEAN = {
    'health_check_disable': 'health-check-disable',
    'health_check_protocol_disable': 'health-check-protocol-disable'
}

COMPONENT_ATTRIBUTES_LIST = {
    'port_list': 'port-list'
}    

COMPONENT_ATTRIBUTES_LIST_MANDATORIES = {
    'port_list': ['port-num', 'port-proto']
}
        
MUTUALLY_EXCLUSIVE_ATTRIBUTES_SET = [
    ['ip_address','ipv6_address'],
    ['health_check','health_check_disable']
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
            node_name=dict(type='str', required=True),
            ip_address=dict(type='str', required=False),
            ipv6_address=dict(type='str', required=False),
            port_list=dict(type='list', required=False),
            action=dict(type='str', required=False),
            external_ip=dict(type='str', required=False),
            health_check=dict(type='str', required=False),
            health_check_disable=dict(type='bool', required=False, default='no', choises=['yes','no']),
            health_check_protocol_disable=dict(type='bool', required=False, default='no', choises=['yes','no']),
            ipv6=dict(type='str', required=False),
            user_tag=dict(type='str', required=False) 
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
                component_list = []
                for config_list in result_list[SECOND_LEVEL_LIST]:
                    mandatory_attributes_in_config = []
                    for mandatory_attribute_in_config in MANDATORY_ATTRIBUTES_IN_CONFIG:
                        mandatory_attributes_in_config.append(config_list[mandatory_attribute_in_config])
                    component_list.append(mandatory_attributes_in_config)
            else:
                result_list = {
                    SECOND_LEVEL: {
                    }
                }

            config_before = copy.deepcopy(result_list)

            mandatory_attributes_in_playbook = []
            for mandatory_attribute_in_playbook in MANDATORY_ATTRIBUTES_IN_PLAYBOOK:
                if module.params[mandatory_attribute_in_playbook]:
                    mandatory_attributes_in_playbook.append(module.params[mandatory_attribute_in_playbook])

            if mandatory_attributes_in_playbook in component_list:
                component_path = mandatory_attributes_in_playbook[0]
                mandatory_attributes_in_playbook.pop(0)
                for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
                    component_path = component_path+'+'+mandatory_attribute_in_playbook
                result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+component_path, method='GET', body='', signature=signature)
                if axapi_failure(result_list):
                    axapi_close_session(module, signature)
                    module.fail_json(msg="Failed to obtain %s %s %s information." % (FIRST_LEVEL, SECOND_LEVEL, component_path))
                else:
                    config_before = copy.deepcopy(result_list)
                    json_post = copy.deepcopy(result_list)
                    diff_sw = 0
                    same_sw = 0
                    absent_sw = 0

                    for playbook_attribute in COMPONENT_ATTRIBUTES.keys():
                        if module.params[playbook_attribute]:
                            if result_list[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES[playbook_attribute]):
                                if result_list[SECOND_LEVEL][COMPONENT_ATTRIBUTES[playbook_attribute]] != module.params[playbook_attribute]:
                                    diff_sw = 1
                                else:
                                    same_sw = 1
                                    if status == 'absent':
                                        json_post[SECOND_LEVEL].pop(module.params[playbook_attribute])
                            else:
                                absent_sw = 1
                            if status == 'present':
                                json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES[playbook_attribute]] =  module.params[playbook_attribute]

                    for playbook_attribute in COMPONENT_ATTRIBUTES_BOOLEAN.keys():
                        if int(module.params[playbook_attribute]):
                            if result_list[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute]):
                                if result_list[SECOND_LEVEL][COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute]] != module.params[playbook_attribute]:
                                    diff_sw = 1
                                else:
                                    same_sw = 1
                                    if status == 'absent':
                                        json_post[SECOND_LEVEL].pop(module.params[playbook_attribute])
                            else:
                                absent_sw = 1
                            if status == 'present':
                                json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute]] =  module.params[playbook_attribute]
                                        
                    for playbook_attribute in COMPONENT_ATTRIBUTES_LIST.keys():
                        if module.params[playbook_attribute]:
                            if result_list[SECOND_LEVEL].has_key(COMPONENT_ATTRIBUTES_LIST[playbook_attribute]):
                                json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]] = []
                                current_lists = copy.deepcopy(result_list[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]])
                                playbook_lists = copy.deepcopy(module.params[playbook_attribute])
                                for current_list in current_lists:
                                    for playbook_list in playbook_lists:
                                        current_list_mandatory_values = []
                                        current_list_options = current_list
                                        playbook_list_mandatory_values = []
                                        playbook_list_options = playbook_list
                                        for list_mandatory_key in COMPONENT_ATTRIBUTES_LIST_MANDATORIES[playbook_attribute]:
                                            current_list_mandatory_values.append(current_list[list_mandatory_key])
                                            current_list_options.pop(list_mandatory_key)
                                            playbook_list_mandatory_values.append(playbook_list[list_mandatory_key])
                                            playbook_list_options.pop(list_mandatory_key)
                                        if current_list_mandatory_values == playbook_list_mandatory_values:
                                            if list(set(playbook_list_options) - set(current_list_options)) == []:
                                                same_sw = 1
                                                if status == 'absent':
                                                    if playbook_list_options != {}:
                                                        for playbook_list_key in playbook_list.keys():
                                                            if current_list[playbook_list_key] == playbook_list[playbook_list_key]:
                                                                current_list.pop(playbook_list_key)
                                                        json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]].append(current_list)
                                            else:
                                                diff_sw = 1
                                            if status == 'present':
                                                for playbook_list_key in playbook_list.keys():
                                                    current_list[playbook_list_key] = playbook_list[playbook_list_key]
                                                json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]].append(current_list)
                                            current_lists.remove(current_list)
                                            playbook_lists.remove(playbook_list)
                                if current_lists != []:
                                    json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]].append(current_lists)
                                if playbook_lists != []:
                                    absent_sw = 1
                                    if status == 'present':
                                        json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_LIST[playbook_attribute]].append(playbook_lists)

                    if absent_sw and not(diff_sw) and not(same_sw):
                        differences = 4
                    elif diff_sw:
                        differences = 3
                    elif same_sw and not(diff_sw):
                        differences = 2
                    else:
                        differences = 5
            else: #there is no existing SECOND_LEVEL component in the current config
                differences = 1
                if status == 'present':
                    json_post = {
                        SECOND_LEVEL: {
                        }
                    }
                    for playbook_attribute in COMPONENT_ATTRIBUTES.keys():
                        if module.params[playbook_attribute]:
                            json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES[playbook_attribute]] =  module.params[playbook_attribute]
                    for playbook_attribute in COMPONENT_ATTRIBUTES_BOOLEAN.keys():
                        if int(module.params[playbook_attribute]):
                            json_post[SECOND_LEVEL][COMPONENT_ATTRIBUTES_BOOLEAN[playbook_attribute]] =  module.params[playbook_attribute]
                    for playbook_attribute in COMPONENT_ATTRIBUTES_LIST.keys():
                        if module.params[playbook_attribute]:
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
            mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES_IN_PLAYBOOK)
            component_path = module.params[mandatory_attributes_in_playbook[0]]
            mandatory_attributes_in_playbook.pop(0)
            for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
                component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
            result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+component_path, method='POST', body=json.dumps(json_post), signature=signature)
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
            mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES_IN_PLAYBOOK)
            component_path = module.params[mandatory_attributes_in_playbook[0]]
            mandatory_attributes_in_playbook.pop(0)
            for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
                component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
            result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+component_path, method='PUT', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result_list):
                axapi_close_session(module, signature)
                module.fail_json(msg="Failed to delete elemetns of %s %s: %s." % (FIRST_LEVEL, SECOND_LEVEL, result_list))
            else:
                result["changed"] = True
        elif differences == 5:
            axapi_base_url = 'https://{}/axapi/v3/'.format(host)
            mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES_IN_PLAYBOOK)
            component_path = module.params[mandatory_attributes_in_playbook[0]]
            mandatory_attributes_in_playbook.pop(0)
            for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
                component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
            result_list = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+component_path, method='DELETE', body='', signature=signature)
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
        mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES_IN_PLAYBOOK)
        component_path = module.params[mandatory_attributes_in_playbook[0]]
        mandatory_attributes_in_playbook.pop(0)
        for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
            component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
        if component_path:
            result['config'] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+component_path, method='GET', body='', signature=signature)
        else:
            result['config'] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/', method='GET', body='', signature=signature)

    return result


# Return current statistics
def statistics(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES_IN_PLAYBOOK)
        component_path = module.params[mandatory_attributes_in_playbook[0]]
        mandatory_attributes_in_playbook.pop(0)
        for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
            component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
        if component_path:
            result["stats"] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+component_path+'/stats', method='GET', body='', signature=signature)
        else:
            result["stats"] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/stats', method='GET', body='', signature=signature)
    return result


# Return current operational data
def operational(module, signature, result):
    host = module.params['a10_host']
    axapi_version = module.params['axapi_version']

    if axapi_version == '3':
        axapi_base_url = 'https://{}/axapi/v3/'.format(host)
        mandatory_attributes_in_playbook = copy.deepcopy(MANDATORY_ATTRIBUTES_IN_PLAYBOOK)
        component_path = module.params[mandatory_attributes_in_playbook[0]]
        mandatory_attributes_in_playbook.pop(0)
        for mandatory_attribute_in_playbook in mandatory_attributes_in_playbook:
            component_path = component_path+'+'+module.params[mandatory_attribute_in_playbook]
        if component_path:
            result["oper"] = axapi_call_v3(module, axapi_base_url+FIRST_LEVEL+'/'+SECOND_LEVEL+'/'+component_path+'/oper', method='GET', body='', signature=signature)
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

    if state == 'present' or state == 'absent':
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
                result['changed'] = True
                result['diff']['after'] = json_post
            elif differences == 5:
                result['changed'] = True
                result['diff']['after'] = ""
            else:
                result['changed'] = False
                result['diff']['after'] = config_before
    else:
        result['changed'] = False
        result_list = current(module, signature, result)
        result['post_config'] = ""
        result['diff']['before'] = result_list
        result['diff']['after'] = result_list

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
