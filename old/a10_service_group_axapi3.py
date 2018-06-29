#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
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
module: a10_service_group_axapi3
version_added: 2.0
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices' service groups with aXAPIv3
description:
    - Manage SLB (Server Load Balancing) service-group objects on A10 Networks devices via aXAPIv3.
author: "Kentaro Ishizuka (@kishizuka4989) based on previous works by Eric Shou (@ericshou) and Mischa Peters (@mischapeters)"
extends_documentation_fragment: a10
options:
  service_group: 
    description:
      - The SLB (Server Load Balancing) service-group name
    required: true
    default: null
    aliases: ['service', 'pool', 'group']
  service_group_protocol:
    description:
      - The SLB service-group protocol of TCP or UDP.
    required: false
    default: tcp
    aliases: ['proto', 'protocol']
    choices: ['tcp', 'udp']
  service_group_lb_method:
    description:
      - The SLB service-group load balancing method, such as round-robin.
        Note that service_group_lb_method and srvice_group_lc_method are mutually exclusive.
    required: false
    default: null
    aliases: ['lb-method']
    choices: ['dst-ip-hash','dst-ip-only-hash','fastest-response','least-request','src-ip-hash','src-ip-only-hash','weighted-rr','round-robin','round-robin-strict']
  service_group_lc_method:
    description:
      - The SLB service-group least connection method, such as least-connection.
        Note that service_group_lb_method and srvice_group_lc_method are mutually exclusive.
    required: false
    default: null
    aliases: ['lc-method']
    choices: ['least-connection','service-least-connection','weighted-least-connection','service-weighted-least-connection']
  partition:
    description:
      - Set active-partition
    required: false
    default: null
  servers:
    description:
      - A list of servers to add to the service group. Each list item should be a
        dictionary which specifies the C(name:) and C(port:), but can also optionally
        specify the C(member-status:). See the examples below for details.
    required: false
    default: null
  operation:
    description:
      - Create, Update or Remove SLB server. For create and update operation, we use the IP address and server
        name specified in the POST message. For delete operation, we use the server name in the request URI.
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
# Create a new server
- a10_service_group_axapi3:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    operation: create
    validate_certs: false
    write_config: yes
    service_group: sg1
    service_group_protocol: tcp
    servers:
      - name: sv1
        port: 8080
      - name: sv2
        port: 8080

'''
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call_v3, a10_argument_spec, axapi_authenticate_v3, axapi_failure
from ansible.module_utils.a10 import AXAPI_PORT_PROTOCOLS

VALID_SERVER_FIELDS = ['name', 'port', 'member-state']

# subroutine for validating server lists
def validate_servers(module, servers):
    for item in servers:
        for key in item:
            if key not in VALID_SERVER_FIELDS:
                module.fail_json(msg="invalid server field (%s), must be one of: %s" % (key, ','.join(VALID_SERVER_FIELDS)))

        # validate the server name is present
        if 'name' not in item:
            module.fail_json(msg="server name must be defined in the servers field")

        # validate the port number is present and an integer
        if 'port' in item:
            try:
                item['port'] = int(item['port'])
            except:
                module.fail_json(msg="server port definitions must be integers")
        else:
            module.fail_json(msg="server definitions must define the port field")

        # convert the status to the internal API integer value
        if 'member-state' in item:
            member_state = item['member-state']
            if member_state not in ['enable', 'disable']:
                module.fail_json(msg="server status must be enable or disable")
        else:
            item['member-state'] = 'enable'

# main routine
def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            operation=dict(type='str', default='create', choices=['create', 'update', 'delete']),
            service_group=dict(type='str', aliases=['service', 'pool', 'group'], required=True),
            service_group_protocol=dict(type='str', default='tcp', aliases=['proto', 'protocol'], choices=['tcp', 'udp']),
            service_group_lb_method=dict(type='str', required=False,
                                      aliases=['lb-method'],
                                      choices=['dst-ip-hash',
                                               'dst-ip-only-hash',
                                               'fastest-response',
                                               'least-request',
                                               'src-ip-hash',
                                               'src-ip-only-hash',
                                               'weighted-rr',
                                               'round-robin',
                                               'round-robin-strict']),
            service_group_lc_method=dict(type='str', required=False,
                                      aliases=['lc-method'],
                                      choices=['least-connection',
                                               'service-least-connection',
                                               'weighted-least-connection',
                                               'service-weighted-least-connection']),
            servers=dict(type='list', aliases=['server', 'member'], default=[]),
            partition=dict(type='str', required=False),
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
    slb_service_group = module.params['service_group']
    slb_service_group_proto = module.params['service_group_protocol']
    slb_service_group_lb_method = module.params['service_group_lb_method']
    slb_service_group_lc_method = module.params['service_group_lc_method']
    slb_servers = module.params['servers']

    # validate if service group name exists
    if slb_service_group is None:
        module.fail_json(msg='service_group is required')

    # validate the server list with using validate_servers
    validate_servers(module, slb_servers)

    # validate if there is both lb-method and lc-method
    if slb_service_group_lb_method and slb_service_group_lc_method:
        module.fail_json(msg='service_group_lb_method and service_group_lc_method are mutually exclusive')

    # Initialize JSON to be POST
    json_post = {
        "service-group": 
            {
                "name": slb_service_group,
                "protocol": slb_service_group_proto,
            }
    }

    json_post_create = {
        "service-group-list": [
            {
            }
        ]
    }

    # add optional module parameters to JSON
    if slb_servers:
        json_post['service-group']['member-list'] = slb_servers

    if slb_service_group_lb_method:
        json_post['service-group']['lb-method'] = slb_service_group_lb_method

    if slb_service_group_lc_method:
        json_post['service-group']['lc-method'] = slb_service_group_lc_method

    json_post_create['service-group-list'][0] = json_post['service-group']

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
        
    # GET existing service groups and check if the service group already exists
    slb_service_group_data = axapi_call_v3(module, axapi_base_url+'slb/service-group/', method='GET', body='', signature=signature)
    if axapi_failure(slb_service_group_data):
        slb_service_group_exists = False
    else:
        slb_service_group_list = [service_group['name'] for service_group in slb_service_group_data['service-group-list']]
        if slb_service_group in slb_service_group_list:
            slb_service_group_exists = True
        else:
            slb_service_group_exists = False

    # POST configuration
    changed = False
    if operation == 'create':
        if slb_service_group_exists is False:
            result = axapi_call_v3(module, axapi_base_url+'slb/service-group/', method='POST', body=json.dumps(json_post_create), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to create the service group: %s" % result['response']['err']['msg'])
            changed = True
        else:
            changed = False
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="service group already exists, use state='update' instead")
         # if we changed things, get the full info regarding result
        if changed:
            result = axapi_call_v3(module, axapi_base_url + 'slb/service-group/' + slb_service_group, method='GET', body='', signature=signature)
        else:
            result = slb_service_group_data
    elif operation == 'delete':
        if slb_service_group_exists:
            result = axapi_call_v3(module, axapi_base_url + 'slb/service-group/' + slb_service_group, method='DELETE', body='', signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to delete service group: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="the service group was not present")
    elif operation == 'update':
        if slb_service_group_exists:
            result = axapi_call_v3(module, axapi_base_url + 'slb/service-group/' + slb_service_group, method='PUT', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to update service group: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="the service group was not present")

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
