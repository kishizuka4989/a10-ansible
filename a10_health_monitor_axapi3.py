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
module: a10_health_monitor_axapi3
version_added: 2.3
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage health monitor objects on A10 Networks devices via aXAPIv3.
author: "Kentaro Ishizuka (@kishizuka4989)"
extends_documentation_fragment: a10
options:
  health_monitor:
    description:
      - The health monitor name.
    required: true
  disable_after_down:
    description:
      - Disable the target if health check failed.
    required: false
    default: ['no']
    choises: ['yes', 'no']
  interval:
    description:
      - Healthcheck interaval in seconds.
    required: false
    default: 5
    choises: 1-180
  passive:
    description:
      - Specify passive mode.
    required: false
    default: ['no']
    choises: ['yes', 'no']
  passive_interval:
    description:
      - Interval to do manual health checking in seconds while in passive mode.
    required: false
    default: 10
    choises: 1-180
  retry:
    description:
      - Number of healthcheck retry.
    required: false
    default: 3
    choises: 1-10
  timeout:
    description:
      - Health check timeout.
    required: false
    default: 5
    choises: 1-180
  up_retry:
    description:
      - Specify the Healthcheck Retries before declaring target up.
    required: false
    default: 1
    choises: 1-10
  method:
    description:
      - Specify the health check method.
    required: false
    choises: ['tcp','http']
  method_options:
    description:
      - A list of options for health check method. 
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
# Create a new health monitor
- a10_health_monitor_axapi3:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    health_monitor: test
    interval: 5
    retry: 3
    timeout: 5
    partition: adp1
    write_config: yes
    operation: create
    method: http
    method_options:
      - http-port: 8080
        http-response-code: 200
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
            health_monitor=dict(type='str', required=True),
            disable_after_down=dict(type='str', required=False, choises=['yes', 'no']),
            interval=dict(type='str', required=False),
            passive=dict(type='str', required=False, choises=['yes', 'no']),
            passive_interval=dict(type='str', required=False),
            retry=dict(type='str', required=False),
            up_retry=dict(type='str', required=False),
            timeout=dict(type='str', required=False),
            method=dict(type='str', required=False, choises=['tcp', 'http']),
            method_options=dict(type='list', required=False)
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
    health_monitor_name = module.params['health_monitor']
    health_monitor_disable_after_down = module.params['disable_after_down']
    health_monitor_interval = module.params['interval']
    health_monitor_passive = module.params['passive']
    health_monitor_passive_interval = module.params['passive_interval']
    health_monitor_retry = module.params['retry']
    health_monitor_timeout = module.params['timeout']
    health_monitor_up_retry = module.params['up_retry']
    health_monitor_method = module.params['method']
    health_monitor_method_options = module.params['method_options']

    # Initialize JSON to be POST
    json_post = {
        "monitor": 
            {
                "name": health_monitor_name
            }
    }

    json_post_create = {
        "monitor-list": [
            {
            }
        ]
    }

    # add optional module parameters
    if health_monitor_disable_after_down:
        json_post['monitor']['disable-after-down'] = health_monitor_disable_after_down
        if health_monitor_disable_after_down == 'True':
            json_post['monitor']['disable-after-down'] = 1
        elif health_monitor_disable_after_down == 'False':
            json_post['monitor']['disable-after-down'] = 0
        else:
            module.fail_json(msg="Health monitor disable_after_down shold be 'yes' or 'no'")            

    if health_monitor_interval:
        json_post['monitor']['interval'] = health_monitor_interval

    if health_monitor_passive:
        json_post['monitor']['passive'] = health_monitor_passive
        if health_monitor_passive == 'True':
            json_post['monitor']['passive'] = 1
        elif health_monitor_passive == 'False':
            json_post['monitor']['passive'] = 0
        else:
            module.fail_json(msg="Health monitor passive shold be 'yes' or 'no'")            

    if health_monitor_passive_interval:
        json_post['monitor']['passive-interval'] = health_monitor_passive_interval

    if health_monitor_retry:
        json_post['monitor']['retry'] = health_monitor_retry

    if health_monitor_timeout:
        json_post['monitor']['timeout'] = health_monitor_timeout

    if health_monitor_up_retry:
        json_post['monitor']['up-retry'] = health_monitor_up_retry

    if health_monitor_method:
        health_method_block = {
            health_monitor_method: {
            }
        }
        if health_monitor_method_options:
            health_method_block[health_monitor_method] = health_monitor_method_options[0]
            health_method_block[health_monitor_method][health_monitor_method] = 1
        json_post['monitor']['method'] = health_method_block

    json_post_create['monitor-list'][0] = json_post['monitor']
    
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
    health_monitor_data = axapi_call_v3(module, axapi_base_url+'health/monitor/', method='GET', body='', signature=signature)
    if axapi_failure(health_monitor_data):
        health_monitor_exists = False
    else:
        health_monitor_list = [health_monitor['name'] for health_monitor in health_monitor_data['monitor-list']]
        if health_monitor_name in health_monitor_list:
            health_monitor_exists = True
        else:
            health_monitor_exists = False

    # POST configuration
    changed = False
    if operation == 'create':
        if health_monitor_exists is False:
            result = axapi_call_v3(module, axapi_base_url+'health/monitor/', method='POST', body=json.dumps(json_post_create), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to create the health monitor: %s" % result['response']['err']['msg'])
            changed = True
        else:
            changed = False
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="Health monitor %s already exists, use state='update' instead" % (health_monitor_name))
        # if we changed things, get the full info regarding result
        if changed:
            result = axapi_call_v3(module, axapi_base_url + 'health/monitor/' + health_monitor_name, method='GET', body='', signature=signature)
        else:
            result = health_monitor_data
    elif operation == 'delete':
        if slb_server_exists:
            result = axapi_call_v3(module, axapi_base_url + 'health/monitor/' + health_monitor_name, method='DELETE', body='', signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to delete health monitor: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="the health monitor was not present: %s" % (health_monitor_name))
    elif operation == 'update':
        if health_monitor_exists:
            result = axapi_call_v3(module, axapi_base_url + 'health/monitor/' + health_monitor_name, method='PUT', body=json.dumps(json_post), signature=signature)
            if axapi_failure(result):
                axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
                module.fail_json(msg="failed to update health monitor: %s" % result['response']['err']['msg'])
            changed = True
        else:
            result = dict(msg="the health monitor was not present: %s" % (health_monitor_name))

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
