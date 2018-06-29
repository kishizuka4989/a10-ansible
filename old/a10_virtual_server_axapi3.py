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
module: a10_virtual_server_axapi3
version_added: 2.0
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices' virtual-servser with aXAPIv3
description:
    - Manage SLB (Server Load Balancing) virtual server objects on A10 Networks devices via aXAPIv3.
author: "Kentaro Ishizuka (@kishizuka4989) based on previous works by Eric Shou (@ericshou) and Mischa Peters (@mischapeters)"
extends_documentation_fragment: a10
options:
  virtual_server: 
    description:
      - The SLB (Server Load Balancing) virtual-server name
    required: true
    default: null
  ip_address:
    description:
      - The SLB virtual-server IP address (IPv4).
        Note that mutually exclusive with ipv6_address and use_if_ip
    required: true if there is no ipv6_address and use_if_ip
    default: null
  ipv6_address:
    description:
      - The SLB virtual-server IP address (IPv6).
        Note that mutually exclusive with ip_address and use_if_ip
    required: true if there is no ip_address and use_if_ip
    default: null
  use_if_ip:
    description:
      - Use interface IP for the SLB virtual-server's IP address.
        Note that mutually exclusive with ip_address and ipv6_address
    required: true if there is no ip_address and ipv6_address
    default: null
	choises: ['yes', 'no']
  acl_name:
    description:
      - IPv4 access list name for SLB virtual-server
    required: false
    default: null
  ipv6_acl:
    description:
      - IPv6 access list name for SLB virtual-server
    required: false
    default: null
  enable_disable_action:
    description:
      - Enable/Disable action for SLB virtual-server
    required: false
    default: enable
    choices: ['enable','disable','disable-when-all-ports-down','diable-when-any-port-down']
  template_policy:
    description:
      - Policy template action for SLB virtual-server
    required: false
    default: null
  template_virtual_server:
    description:
      - Virtual-server template action for SLB virtual-server
    required: false
    default: null
  vrid:
    description:
      - VRRP-A vrid
    required: false
    default: null
  description:
    description:
      - The description for the SLB virtual-server
    required: false
    default: null
  port_list:
    description:
      - A list of ports to be added to the virtual-server. Each list item should be a
        dictionary which specifies the C(port-number:) and C(protocol:), and can also optionally
        specify the C(service-group:) and other specifications. See the examples below for details.
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
- a10_virtual_server_axapi3:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    operation: create
    validate_certs: no
    write_config: yes
    virtual_server: vs1
    ip_address: 192.168.10.1
    port_list:
      - port-number: 80
        protocol: http
        service-group: sg1
        pool: snat1
      - port-number: 443
        protocol: https
        service-group: sg2
        template-client-ssl: cssl
        pool: snat2

'''
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call_v3, a10_argument_spec, axapi_authenticate_v3, axapi_failure
from ansible.module_utils.a10 import AXAPI_PORT_PROTOCOLS

VALID_PORT_LIST_FIELDS = ['port-number', 'protocol', 'service-group', 'pool', 'action', 'acl-name-list', 'aflex-scripts', 'auto', 'conn-limit', 'ha-conn-mirror', 'name', 'no-dest-nat', 'persist-type', 'pool', 'port-translation', 'redirect-to-https', 'template-cache', 'template-client-ssl', 'template-connection-reuse', 'template-dns', 'template-dynamic-service', 'template-http', 'template-http-policy', 'template-persist-cookie', 'template-persist-destination-ip', 'template-persist-source-ip', 'template-persist-ssl-sid', 'template-policy', 'template-server-ssl', 'use-rcv-hop-for-resp','waf-template']

VALID_PORT_LIST_BOOLEAN_FIELDS = ['auto', 'ha-conn-mirror', 'no-dest-nat', 'port-translation', 'redirect-to-https', 'use-rcv-hop-for-resp']

VALID_PORT_LIST_PROTOCOLS = ['tcp', 'udp', 'others', 'diameter', 'dns-tcp', 'dns-udp','fast-http','fix','ftp','ftp-proxy', 'http', 'https', 'imap', 'mlb', 'mms', 'mysql', 'mssql', 'pop3', 'radius', 'rtsp', 'sip', 'sip-tcp', 'sips', 'smpp-tcp', 'spdy', 'spdys', 'smtp', 'sslproxy', 'ssli', 'ssh', 'tcp-proxy', 'tftp']

VALID_PORT_LIST_PERSIST_TYPE = ['src-dst-ip-swap-persist', 'use-src-ip-for-dst-persist', 'use-dst-ip-for-srcpersist']

# subroutine for validating server lists
def validate_port_list(module, port_list):
    for item in port_list:
        for key in item:
            if key not in VALID_PORT_LIST_FIELDS:
                module.fail_json(msg="invalid port-list field (%s), must be one of: %s" % (key, ','.join(VALID_PORT_LIST_FIELDS)))
            if key in VALID_PORT_LIST_BOOLEAN_FIELDS:
                try:
                    item[key] = bool(item[key])
                except:
                    module.fail_json(msg="Port-list %s setting must be 'yes' or 'no': %s" % (key, item[key]))
                if item[key]:
                    item[key] = 1
                else:
                    item[key] = 0
					

        # validate if the port-number is present and intgers
        if 'port-number' in item:
            try:
                item['port-number'] = int(item['port-number'])
            except:
                module.fail_json(msg="port-number must be integers")
            if item['port-number'] > 65534 or item['port-number'] < 0:
                module.fail_json(msg="Port-list port-number should be between: 0-65534")
        else:
            module.fail_json(msg="port-number must be defined in the port-list field")

        # validate if the protocol is present and its validity
        if 'protocol' in item:
            if item['protocol'] not in VALID_PORT_LIST_PROTOCOLS:
                module.fail_json(msg="invalid port-list protocol (%s), must be one of: %s" % (item['protocol'], ','.join(VALID_PORT_LIST_PROTOCOLS)))
        else:
            module.fail_json(msg="protocol must be defined in the port-list field")

        # Check validity of action state
        if 'action' in item:
            if item['action'] not in ['enable', 'diable']:
                module.fail_json(msg="port-list action should be 'enable' or 'disable'")

        # Check if conn-limit configuration is valid
        if 'conn-limit' in item:
            try:
                item['conn-limit'] = int(item['conn-limit'])
            except:
                module.fail_json(msg="Port-list conn-limit entries in the port definitions must be integers")
            if item['conn-limit'] > 8000000 or item['conn-limit'] < 1:
                module.fail_json(msg="Port-list conn-limit should be between 1-8000000")
		
        # Validate if persist-type configuration is valid
        if 'persist-type' in item:
            if item['persist-type'] not in VALID_PORT_LIST_PERSIST_TYPE:
                module.fail_json(msg="invalid port-list persist-type (%s), must be one of: %s" % (item['persist-type'], ','.join(VALID_PORT_LIST_PERSIST_TYPE)))
				
# main routine
def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            operation=dict(type='str', default='create', choices=['create', 'update', 'delete']),
            virtual_server=dict(type='str', required=True),
            ip_address=dict(type='str', required=False),
            ipv6_address=dict(type='str', required=False),
            use_if_ip=dict(type='str', required=False, choises=['yes', 'no']),
            acl_name=dict(type='str', required=False),
            ipv6_acl=dict(type='str',required=False),
            enable_disable_action=dict(type='str', required=False, choices=['enable', 'disable', 'disable-when-all-ports-down', 'disable-when-any-port-down']),
            template_policy=dict(type='str', required=False),
            template_virtual_server=dict(type='str', required=False),
            vrid=dict(type='str', required=False),
            description=dict(type='str', required=False),
            port_list=dict(type='list', default=[]),
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
    slb_virtual_server = module.params['virtual_server']
    slb_virtual_server_ip_address = module.params['ip_address']
    slb_virtual_server_ipv6_address = module.params['ipv6_address']
    slb_virtual_server_use_if_ip = module.params['use_if_ip']
    slb_virtual_server_acl_name = module.params['acl_name']
    slb_virtual_server_ipv6_acl = module.params['ipv6_acl']
    slb_virtual_server_enable_disable_action = module.params['enable_disable_action']
    slb_virtual_server_template_policy = module.params['template_policy']
    slb_virtual_server_template_virtual_server = module.params['template_virtual_server']
    slb_virtual_server_vrid = module.params['vrid']
    slb_virtual_server_description = module.params['description']
    slb_virtual_server_port_list = module.params['port_list']

    # validate if virtual-server name exists
    if slb_virtual_server is None:
        module.fail_json(msg="virtual-server name is required")

    # validate the server list with using validate_servers
    validate_port_list(module, slb_virtual_server_port_list)

    # validate if ip_address and ipv6_address and use_if_ip are exclusive
    if slb_virtual_server_ip_address:
        if slb_virtual_server_ipv6_address or slb_virtual_server_use_if_ip:
            module.fail_json(msg="ip_address and ipv6_address and use_if_ip are exclusive")
    elif slb_virtual_server_ipv6_address:
        if slb_virtual_server_use_if_ip:
            module.fail_json(msg="ip_address and ipv6_address and use_if_ip are exclusive")
    elif not slb_virtual_server_use_if_ip:
        module.fail_json(msg='One of ip_address or ipv6_address or use_if_ip should be defined')

    # Initialize JSON to be POST
    json_post = {
        "virtual-server": 
            {
                "name": slb_virtual_server,
            }
    }

    json_post_create = {
        "virtual-server-list": [
            {
            }
        ]
    }

    # add optional module parameters to JSON
    if slb_virtual_server_port_list:
        json_post['virtual-server']['port-list'] = slb_virtual_server_port_list

    if slb_virtual_server_ip_address:
        json_post['virtual-server']['ip-address'] = slb_virtual_server_ip_address

    if slb_virtual_server_ipv6_address:
        json_post['virtual-server']['ipv6-address'] = slb_virtual_server_ipv6_address

    if slb_virtual_server_use_if_ip:
        json_post['virtual-server']['use-if-ip'] = slb_virtual_server_use_if_ip
		
    if slb_virtual_server_acl_name:
        json_post['virtual-server']['acl-name'] = slb_virtual_server_acl_name
		
    if slb_virtual_server_ipv6_acl:
        json_post['virtual-server']['ipv6-acl'] = slb_virtual_server_ipv6_acl
		
    if slb_virtual_server_enable_disable_action:
        json_post['virtual-server']['enable-disable-action'] = slb_virtual_server_enable_disable_action
		
    if slb_virtual_server_template_policy:
        json_post['virtual-server']['template-policy'] = slb_virtual_server_template_policy
		
    if slb_virtual_server_template_virtual_server:
        json_post['virtual-server']['template-virtual-server'] = slb_virtual_server_template_virtual_server
		
    if slb_virtual_server_vrid:
        json_post['virtual-server']['vrid'] = slb_virtual_server_vrid
		
    if slb_virtual_server_description:
        json_post['virtual-server']['description'] = slb_virtual_server_description

    json_post_create['virtual-server-list'][0] = json_post['virtual-server']
		
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
                    module.fail_json(msg="failed to create the virtual server: %s" % result['response']['err']['msg'])                    
            else:
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="The partition does not exist: %s" % (partition))
        
    # GET existing service groups and check if the service group already exists
    slb_virtual_server_data = axapi_call_v3(module, axapi_base_url+'slb/virtual-server/', method='GET', body='', signature=signature)
    if axapi_failure(slb_virtual_server_data):
        slb_virtual_server_exists = False
    else:
        slb_virtual_server_list = [virtual_server['name'] for virtual_server in slb_virtual_server_data['virtual-server-list']]
        if slb_virtual_server in slb_virtual_server_list:
            slb_virtual_server_exists = True
        else:
            slb_virtual_server_exists = False

    # POST configuration
    changed = False
    if operation == 'create':
        if slb_virtual_server_exists is False:
            result = axapi_call_v3(module, axapi_base_url+'slb/virtual-server/', method='POST', body=json.dumps(json_post_create), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to create the virtual server: %s" % result['response']['err']['msg'])
            changed = True
        else:
            changed = False
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="The virtual server already exists, use state='update' instead")
         # if we changed things, get the full info regarding result
        if changed:
            result = axapi_call_v3(module, axapi_base_url + 'slb/virtual-server/' + slb_virtual_server, method='GET', body='', signature=signature)
        else:
            result = slb_virtual_server_data
    elif operation == 'delete':
        if slb_virtual_server_exists:
            result = axapi_call_v3(module, axapi_base_url + 'slb/virtual-server/' + slb_virtual_server, method='DELETE', body='', signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to delete the virtual server: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="The virtual server was not present")
    elif operation == 'update':
        if slb_virtual_server_exists:
            result = axapi_call_v3(module, axapi_base_url + 'slb/virtual-server/' + slb_virtual_server, method='PUT', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to update the virtual server: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="The virtual server was not present")

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
