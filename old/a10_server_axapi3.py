#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
(c) 2014, Mischa Peters <mpeters@a10networks.com>, 2016, Eric Chou <ericc@a10networks.com>, 2018, Kentaro Ishizuka <kishizuka@a10networks.com>

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
module: a10_server_axapi3
version_added: 2.3
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage SLB (Server Load Balancer) server objects on A10 Networks devices via aXAPIv3.
author: "Kentaro Ishizuka (@kishizuka4989) based on previous work by Mischa Peters (@mischapeters) and Eric Chou (@ericchou)"
extends_documentation_fragment: a10
options:
  server_name:
    description:
      - The SLB (Server Load Balancer) server name.
    required: true
    aliases: ['server']
  server_ip:
    description:
      - The SLB (Server Load Balancer) server IPv4 address.
    required: true
    aliases: ['ip', 'address']
  server_status:
    description:
      - The SLB (Server Load Balancer) server status.
    required: false
    default: enable
    aliases: ['action']
    choices: ['enable', 'disable']
  template_server:
    description:
      - Server template assigned to SLB server.
    required: false
    default: null
  server_health_check_disable:
    description:
      - Disabling health check for the server.
    required: false
    default: ['no']
    choises: ['yes', 'no']
  server_conn_limit:
    description:
      - Connection limit per server (1-8000000).
    required: false
    default: 8000000
    choises: 1-8000000
  server_weight:
    description:
      - Weight for server (1-100).
    required: false
    default: 1
    choises: 1-100
  server_slow_start:
    description:
      - Setup slowly ramp up the connection number after server is up.
        (start from 128, then doubled every 10 sec til 4096)
    required: false
    default: ['no']
    choises: ['yes', 'no']
  server_ipv6_addr:
    description:
      - IPv6 address for physical server
    required: false
    default: null
  server_ports:
    description:
      - A list of ports to create for the server. Each list item should be a dictionary which specifies the C(port-number:),
        C(protocol:), C(action:), C(conn-limit:), C(weight:), C(template-port:), C(health-check:), and C(health-check-disable:).
    required: false
    default: null
  partition:
    description:
      - Set active-partition
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
- a10_server:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    server: test
    server_ip: 1.1.1.100
    validate_certs: no
    server_status: enable
    write_config: yes
    operation: create
    server_ports:
      - port-number: 8080
        protocol: tcp
        action: enable
      - port-number: 8443
        protocol: TCP

'''
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call_v3, a10_argument_spec, axapi_authenticate_v3, axapi_failure
from ansible.module_utils.a10 import AXAPI_PORT_PROTOCOLS

VALID_PORT_FIELDS = ['port-number', 'protocol', 'action', 'conn-limit', 'weight', 'template-port', 'health-check', 'health-check-disable']

# Sub-routine for validating port settings
def validate_ports(module, ports):
    for item in ports:
        port_health_check_exists = False
        port_health_check_disable_exists = False
        for key in item:
            if key not in VALID_PORT_FIELDS:
                module.fail_json(msg="invalid port field (%s), must be one of: %s" % (key, ','.join(VALID_PORT_FIELDS)))

        # validate the port number is present and an integer
        if 'port-number' in item:
            try:
                item['port-number'] = int(item['port-number'])
            except:
                module.fail_json(msg="port-number entries in the port definitions must be integers")
        else:
            module.fail_json(msg="port definitions must define the port-number field")

        # validate the port protocol is present, no need to convert to the internal API integer value in v3
        if 'protocol' in item:
            if item['protocol'] not in AXAPI_PORT_PROTOCOLS:
                module.fail_json(msg="invalid port protocol, must be one of: %s" % ','.join(AXAPI_PORT_PROTOCOLS))
        else:
            module.fail_json(msg="port definitions must define the port protocol (%s)" % ','.join(AXAPI_PORT_PROTOCOLS))

        # 'status' is 'action' in AXAPIv3
        # no need to convert the status, a.k.a action, to the internal API integer value in v3
        # action is either enabled or disabled
        if 'action' in item:
            action = item['action']
            if action not in ['enable', 'disable']:
                module.fail_json(msg="server action must be enable or disable")
        else:
            item['action'] = 'enable'

        if 'conn-limit' in item:
            try:
                item['conn-limit'] = int(item['conn-limit'])
            except:
                module.fail_json(msg="Port conn-limit entries in the port definitions must be integers")
            if item['conn-limit'] > 8000000 or item['conn-limit'] < 1:
                module.fail_json(msg="Port conn-limit should be between 1-8000000")

        if 'weight' in item:
            try:
                item['weight'] = int(item['weight'])
            except:
                module.fail_json(msg="Port weight entries in the port definitions must be integers")
            if item['weight'] > 100 or item['weight'] < 1:
                module.fail_json(msg="Port weight should be between 1-100")

        if 'template-port' in item:
            if len(item['template-port']) > 63:
                module.fail_json(msg="too long character for port template-port")
                
        if 'health-check' in item:
            port_health_check_exists = True
            if len(item['health-check']) > 31:
                module.fail_json(msg="too long character for port port health-check")

        if 'health-check-disable' in item:
            port_health_check_disable_exists = True
            try:
                item['health-check-disable'] = bool(item['health-check-disable'])
            except:
                module.fail_json(msg="Port health-check-disable must be 'yes' or 'no'")
            if item['health-check-disable']:
                item['health-check-disable'] = 1
            else:
                item['health-check-disable'] = 0

        if port_health_check_exists and port_health_check_disable_exists:
            module.fail_json(msg="health-check and health-chedk-disable are mutually exclusive for port %s" % (item['port-number']))


# Main routine
def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            partition=dict(type='str', required=False),
            operation=dict(type='str', default='create', choices=['create', 'update', 'delete']),
            server_name=dict(type='str', aliases=['server'], required=True),
            server_ip=dict(type='str', aliases=['ip', 'address'], required=True),
            server_status=dict(type='str', default='enable', aliases=['action'], choices=['enable', 'disable']),
            template_server=dict(type='str', required=False),
            server_health_check_disable=dict(type='str', required=False, choises=['yes', 'no']),
            server_conn_limit=dict(type='str', required=False),
            server_weight=dict(type='str', required=False),
            server_slow_start=dict(type='str', required=False, choises=['yes', 'no']),
            server_ipv6_addr=dict(type='str', required=False),
            server_ports=dict(type='list', aliases=['port'], default=[])
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
    slb_server = module.params['server_name']
    slb_server_ip = module.params['server_ip']
    slb_server_status = module.params['server_status']
    slb_server_template_server = module.params['template_server']
    slb_server_health_check_disable = module.params['server_health_check_disable']
    slb_server_conn_limit = module.params['server_conn_limit']
    slb_server_weight = module.params['server_weight']
    slb_server_slow_start = module.params['server_slow_start']
    slb_server_ipv6_addr = module.params['server_ipv6_addr']
    slb_server_ports = module.params['server_ports']

    # validate the ports data structure
    validate_ports(module, slb_server_ports)

    # Initialize JSON to be POST
    json_post = {
        "server": 
            {
                "name": slb_server,
                "host": slb_server_ip
            }
    }
    
    json_post_create = {
        "server-list": [
            {
            }
        ]
    }

    # add optional module parameters
    if slb_server_status:
        json_post['server']['action'] = slb_server_status

    if slb_server_template_server:
        json_post['server']['template-server'] = slb_server_template_server

    if slb_server_health_check_disable:
        json_post['server']['health-check-disable'] = slb_server_health_check_disable
        if slb_server_health_check_disable == 'True':
            json_post['server']['health-check-disable'] = 1
        elif slb_server_health_check_disable == 'False':
            json_post['server']['health-check-disable'] = 0
        else:
            module.fail_json(msg="Server health_check_disable shold be 'yes' or 'no'")            

    if slb_server_conn_limit:
        json_post['server']['conn-limit'] = slb_server_conn_limit

    if slb_server_weight:
        json_post['server']['weight'] = slb_server_weight

    if slb_server_slow_start:
        json_post['server']['slow-start'] = slb_server_slow_start
        if slb_server_slow_start == 'True':
            json_post['server']['slow-start'] = 1
        elif slb_server_slow_start == 'False':
            json_post['server']['slow-start'] = 0
        else:
            module.fail_json(msg="Server slow_start shold be 'yes' or 'no'")            

    if slb_server_ipv6_addr:
        json_post['server']['server-ipv6-addr'] = slb_server_ipv6_addr

    if slb_server_ports:
        json_post['server']['port-list'] = slb_server_ports

    json_post_create['server-list'][0] = json_post['server']

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
    slb_server_data = axapi_call_v3(module, axapi_base_url+'slb/server/', method='GET', body='', signature=signature)
    if axapi_failure(slb_server_data):
        slb_server_exists = False
    else:
        slb_server_list = [server['name'] for server in slb_server_data['server-list']]
        if slb_server in slb_server_list:
            slb_server_exists = True
        else:
            slb_server_exists = False

    # POST configuration
    changed = False
    if operation == 'create':
        if slb_server_exists is False:
            result = axapi_call_v3(module, axapi_base_url+'slb/server/', method='POST', body=json.dumps(json_post_create), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to create the server: %s" % result['response']['err']['msg'])
            changed = True
        else:
            changed = False
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="server %s already exists, use state='update' instead" % (slb_server))
        # if we changed things, get the full info regarding result
        if changed:
            result = axapi_call_v3(module, axapi_base_url + 'slb/server/' + slb_server, method='GET', body='', signature=signature)
        else:
            result = slb_server_data
    elif operation == 'delete':
        if slb_server_exists:
            result = axapi_call_v3(module, axapi_base_url + 'slb/server/' + slb_server, method='DELETE', body='', signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to delete server: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="the server was not present: %s" % (slb_server))
    elif operation == 'update':
        if slb_server_exists:
            result = axapi_call_v3(module, axapi_base_url + 'slb/server/' + slb_server, method='PUT', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to update server: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="the server was not present: %s" % (slb_server))

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
