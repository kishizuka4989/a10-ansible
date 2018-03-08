#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks health monitor objects
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
module: a10_ip_nat_pool_axapi3
version_added: 2.3
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage IP NAT pool objects on A10 Networks devices via aXAPIv3.
author: "Kentaro Ishizuka (@kishizuka4989)"
extends_documentation_fragment: a10
options:
  pool_name:
    description:
      - IP NAT pool name.
    required: true
  start_address:
    description:
      - Start address of NAT range
    required: true
  end_address:
    description:
      - End address of NAT range
    required: true
  netmask:
    description:
      - Netmask for the NAT range.
    required: true
  gateway:
    description:
      - Gateway IP
    required: false
  partition:
    description:
      - Set active-partition
    required: false
    default: null
  operation:
    description:
      - Create, Update or Remove health monitor.
    required: false
    default: create
    choices: ['create', 'update', 'remove']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']

'''

RETURN = '''
#
'''

EXAMPLES = '''
# Create a new NAT Pool
- a10_ip_nat_pool_axapi3:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    pool_name: test
    start_address: 10.0.0.1
    end_address: 10.0.0.5
    netmask: /24
    partition: adp1
    write_config: yes
    operation: create

'''
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call_v3, a10_argument_spec, axapi_authenticate_v3, axapi_failure
from ansible.module_utils.a10 import AXAPI_PORT_PROTOCOLS

# Main routine
def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            partition=dict(type='str', required=False),
            operation=dict(type='str', default='create', choices=['create', 'update', 'delete']),
            pool_name=dict(type='str', required=True),
            start_address=dict(type='str', required=True),
            end_address=dict(type='str', required=True),
            netmask=dict(type='str', required=True),
            gateway=dict(type='str', required=False),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    partition = module.params['partition']
    operation = module.params['operation']
    write_config = module.params['write_config']
    ip_nat_pool_name = module.params['pool_name']
    ip_nat_pool_start_address = module.params['start_address']
    ip_nat_pool_end_address = module.params['end_address']
    ip_nat_pool_netmask = module.params['netmask']
    ip_nat_pool_gateway = module.params['gateway']

    # Initialize JSON to be POST
    json_post = {
        "pool": 
            {
                "pool-name": ip_nat_pool_name,
                "start-address": ip_nat_pool_start_address,
                "end-address": ip_nat_pool_end_address,
                "netmask": ip_nat_pool_netmask
            }
    }

    json_post_create = {
        "pool-list": [
            {
            }
        ]
    }

    if ip_nat_pool_gateway:
        json_post['pool']['gateway'] = ip_nat_pool_gateway

    json_post_create['pool-list'][0] = json_post['pool']
#    module.fail_json(msg="JSON file is %s" % (json_post))
    
    # login A10 device and own signature
    axapi_base_url = 'https://{}/axapi/v3/'.format(host)
    axapi_auth_url = axapi_base_url + 'auth/'
    signature = axapi_authenticate_v3(module, axapi_auth_url, username, password)

    # GET existing partition list and check if the partition indicated in the playbook exists
    if partition:
        partition_list = axapi_call_v3(module, axapi_base_url+'partition/', method='GET', body='', signature=signature)
        if axapi_failure(partition_list):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="There is no partition on the device: %s" % (host))
        else:
            partition_list = [partition_attr['partition-name'] for partition_attr in partition_list['partition-list']]
            if partition in partition_list:
                result = axapi_call_v3(module, axapi_base_url+'active-partition/'+partition, method='POST', body='', signature=signature)
                if axapi_failure(result):
                    axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                    module.fail_json(msg="failed to create the service group: %s" % result['response']['err']['msg'])
            else:
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="The partition does not exist: %s" % (partition))

    # GET existing servers and check if the server already exits
    ip_nat_pool_data = axapi_call_v3(module, axapi_base_url+'ip/nat/pool', method='GET', body='', signature=signature)
    if axapi_failure(ip_nat_pool_data):
        ip_nat_pool_exists = False
    else:
        ip_nat_pool_list = [ip_nat_pool['pool-name'] for ip_nat_pool in ip_nat_pool_data['pool-list']]
        if ip_nat_pool_name in ip_nat_pool_list:
            ip_nat_pool_exists = True
        else:
            ip_nat_pool_exists = False

    # POST configuration
    changed = False
    if operation == 'create':
        if ip_nat_pool_exists is False:
            result = axapi_call_v3(module, axapi_base_url+'ip/nat/pool', method='POST', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to create the NAT Pool: %s" % result['response']['err']['msg'])
            changed = True
        else:
            changed = False
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="NAT pool %s already exists, use 'update' instead" % (ip_nat_pool_name))
        # if we changed things, get the full info regarding result
        if changed:
            result = axapi_call_v3(module, axapi_base_url + 'ip/nat/pool/' + ip_nat_pool_name, method='GET', body='', signature=signature)
        else:
            result = ip_nat_pool_data
    elif operation == 'delete':
        if ip_nat_pool_exists:
            result = axapi_call_v3(module, axapi_base_url + 'ip/nat/pool/' + ip_nat_pool_name, method='DELETE', body='', signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to delete NAT Pool: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="the NAT Pool was not present: %s" % (ip_nat_pool_name))
    elif operation == 'update':
        if ip_nat_pool_exists:
            result = axapi_call_v3(module, axapi_base_url + 'ip/nat/pool/' + ip_nat_pool_name, method='PUT', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to update NAT Pool: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="the NAT Pool was not present: %s" % (ip_nat_pool_name))

    # if the config has changed, save the config unless otherwise requested
    if changed and write_config:
        write_result = axapi_call_v3(module, axapi_base_url+'write/memory/', method='POST', body='', signature=signature)
        if axapi_failure(write_result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out gracefully and exit
    axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
    module.exit_json(changed=changed, content=result)

if __name__ == '__main__':
    main()
