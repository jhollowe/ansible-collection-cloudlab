#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2021 John Hollowell

import re
import xml.etree.ElementTree as ET

from distutils.version import LooseVersion
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import (
    AnsibleError,
    AnsibleAuthenticationFailure,
    AnsibleOptionsError,
)

# 3rd party imports
try:
    import requests

    if LooseVersion(requests.__version__) < LooseVersion("1.1.0"):
        raise ImportError
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

DOCUMENTATION = """
    name: cloudlab
    short_description: Cloudlab inventory source
    author:
        - John Hollowell <jhollowe@johnhollowell.com>
    requirements:
        - requests >= 1.1
    description:
        - Get inventory hosts from a Cloudlab experiment.
        - "Uses a configuration file as an inventory source, it must end in C(.cloudlab.yml) or C(.cloudlab.yaml)"
    options:
      plugin:
        description: The name of this plugin, it should always be set to C(cloudlab) for this plugin to recognize it as it's own.
        required: yes
        choices: ['cloudlab']
        type: str
      url:
        description:
          - URL to Cloudlab portal.
          - If the value is not specified in the inventory configuration, the value of environment variable C(CLOUDLAB_URL) will be used instead.
        default: 'https://www.cloudlab.us/'
        type: str
        env:
          - name: CLOUDLAB_URL
      user:
        description:
          - Cloudlab authentication user.
          - If the value is not specified in the inventory configuration, the value of environment variable C(CLOUDLAB_USER) will be used instead.
        required: yes
        type: str
        env:
          - name: CLOUDLAB_USER
      password:
        description:
          - Cloudlab authentication password.
          - If the value is not specified in the inventory configuration, the value of environment variable C(CLOUDLAB_PASSWORD) will be used instead.
        required: yes
        type: str
        env:
          - name: CLOUDLAB_PASSWORD
      uuid:
        description:
          - Cloudlab experiment UUID.
          - If the value is not specified in the inventory configuration, the value of environment variable C(CLOUDLAB_UUID) will be used instead.
        required: yes
        type: str
        env:
          - name: CLOUDLAB_UUID
      validate_certs:
        description: Verify SSL certificate if using HTTPS.
        type: boolean
        default: yes
      group_prefix:
        description: Prefix to apply to Cloudlab groups.
        default: cloudlab_
        type: str
      is_local:
        description: if true, the internet-facing SSH access will not be used and only the node names will be used for connection
        default: no
        type: bool
      group_per_physical_core:
        description: if true a group for each physical node will be created, grouping virtual nodes together that reside on the same hardware
        default: true
        type: bool
      group_per_site:
        description: if true a group for each site will be created
        default: true
        type: bool
      set_facts:
        description: if true sets additional facts on the hosts
        default: true
        type: bool
"""

EXAMPLES = """
# Minimal example
# By not specifying a URL the plugin will attempt to connect to the default portal
# experiment1.cloudlab.yml
plugin: cloudlab
user: ansible
password: secure
uuid: fd0cbbd4-4b87-12e9-720b-f4734b2322fb
"""


class InventoryModule(BaseInventoryPlugin):
    """Host inventory parser for ansible using Cloudlab as source."""

    NAME = "cloudlab"

    def __init__(self):

        super(InventoryModule, self).__init__()
        self._session = None
        self.cloudlab_url_base = ""

    def _get_session(self):
        if not self._session:
            self._session = requests.session()
            self._session.verify = self.get_option("validate_certs")
        return self._session

    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(("cloudlab.yaml", "cloudlab.yml")):
                valid = True
            else:
                self.display.vvv(
                    'Skipping due to inventory source not ending in "cloudlab.yaml" nor "cloudlab.yml"'
                )
        return valid

    def to_safe(self, word):
        """Converts 'bad' characters in a string to underscores so they can be used as Ansible names
        # > InventoryModule.to_safe("foo-bar baz")
        'foo_barbaz'
        """
        regex = r"[^A-Za-z0-9\_]"
        return re.sub(regex, "_", word.replace(" ", ""))

    def _cloudlab_login(self):
        login_url = f"{self.cloudlab_url_base}/login.php"
        data = {
            "uid": self.get_option("user"),
            "password": self.get_option("password"),
            "login": "",
        }

        ret = self._get_session().post(url=login_url, data=data)

        # ensure the login was a success
        if ret.url == login_url:
            raise AnsibleAuthenticationFailure(
                f"Unable to login to Cloudlab as {data['uid']}"
            )

    def _get_element_children(self, node, tag):
        """get immediate children of `node` and wildcard filter by tag (ignoring scheme URL)"""
        return [elem for elem in node if elem.tag.rpartition("}")[2] == tag]

    def _populate(self):
        # make sure we are authorized and save auth cookies in session
        self._cloudlab_login()

        data_url = f"{self.cloudlab_url_base}/server-ajax.php"

        # get the XML manifest of all the nodes in the experiment
        data = {
            "ajax_route": "status",
            "ajax_method": "GetInstanceManifest",
            "ajax_args[uuid]": self.get_option("uuid"),
        }

        ret = self._get_session().post(url=data_url, data=data)

        try:
            r_json = ret.json()["value"]
        except ValueError:
            raise AnsibleError("Unable to parse experiment data")

        if isinstance(r_json, str) and re.match(r"no such instance uuid:.*", r_json):
            raise AnsibleOptionsError(r_json)

        for location in r_json:
            # pull out the location's name from its URN
            match = re.match(r"urn:publicid:IDN\+(.*)\+authority\+cm", location)
            if match:
                location_name = match.group(1)
            else:
                location_name = location

            location_group = self.to_safe(
                f"{self.get_option('group_prefix')}{location_name}"
            )
            if self.get_option("group_per_site"):
                self.inventory.add_group(location_group)

            root = ET.fromstring(r_json[location])

            # filter out the node elements (ignoring the namespace of the scheme)
            nodes = self._get_element_children(root, "node")

            for node in nodes:
                node_name = node.attrib["client_id"]

                # for some reason the server gives all nodes for all locations to all locations
                # this filters the nodes to only the nodes at the current location
                if node.attrib.get("component_manager_id") == location:
                    # add host(node name) and put in site group
                    self.inventory.add_host(node_name)

                    # set facts on host (if configured)
                    if self.get_option("set_facts"):
                        facts = {"network": {}}
                        host = self._get_element_children(node, "host")[0]
                        pub_ip = host.attrib.get("ipv4")
                        if pub_ip:
                            facts["network"]["public"] = {}
                            facts["network"]["public"]["ipv4"] = host.attrib.get("ipv4")
                            facts["network"]["public"]["hostname"] = host.attrib.get(
                                "name"
                            )

                        for interface in self._get_element_children(node, "interface"):
                            if_name = self.to_safe(interface.attrib.get("client_id"))
                            facts["network"][if_name] = {}
                            facts["network"][if_name]["mac"] = interface.attrib.get(
                                "mac_address"
                            )
                            self.inventory.set_variable(
                                node_name,
                                f"cloudlab_network_{if_name}_mac",
                                interface.attrib.get("mac_address"),
                            )
                            for if_ip in self._get_element_children(interface, "ip"):
                                facts["network"][if_name][if_ip.attrib.get("type")] = {}
                                facts["network"][if_name][if_ip.attrib.get("type")][
                                    "address"
                                ] = if_ip.attrib.get("address")
                                facts["network"][if_name][if_ip.attrib.get("type")][
                                    "netmask"
                                ] = if_ip.attrib.get("netmask")

                                # create new list with this IP or add to existing list
                                facts["network"][
                                    "all_private_" + if_ip.attrib.get("type")
                                ] = (
                                    facts["network"].get(
                                        "all_private_" + if_ip.attrib.get("type")
                                    )
                                    or []
                                ) + [
                                    if_ip.attrib.get("address")
                                ]

                        sliver = self._get_element_children(node, "sliver_type")[0]
                        disk_urn = self._get_element_children(sliver, "disk_image")[
                            0
                        ].get("name")
                        if disk_urn:
                            facts["storage"] = {}
                            facts["storage"]["disk_urn"] = disk_urn

                        vnode = self._get_element_children(node, "vnode")[0]
                        facts["vnode"] = {}
                        facts["vnode"]["name"] = vnode.attrib.get("name")
                        facts["vnode"]["type"] = vnode.attrib.get("hardware_type")

                        self.inventory.set_variable(node_name, "cloudlab_facts", facts)

                    if self.get_option("group_per_site"):
                        self.inventory.add_child(location_group, node_name)

                    # create a group for each physical node (unless disabled)
                    if self.get_option("group_per_physical_core"):

                        # get the node number and site from the physical node
                        m = re.match(
                            r"urn:publicid:IDN\+(.*)\+node\+(.*)",
                            node.attrib.get("component_id"),
                        )
                        if m:
                            physical_node = m.group(2)

                            physical_node_group = self.to_safe(
                                f"{self.get_option('group_prefix')}{physical_node}"
                            )
                            node_location_group = self.to_safe(
                                f"{self.get_option('group_prefix')}{location_name}"
                            )

                            self.inventory.add_group(physical_node_group)
                            self.inventory.add_child(physical_node_group, node_name)
                            self.inventory.add_child(
                                node_location_group, physical_node_group
                            )

                    # add external (internet) access information if not local
                    if not self.get_option("is_local"):

                        login_found = False
                        for service in self._get_element_children(node, "services"):
                            for login in self._get_element_children(service, "login"):

                                # if this login is for the connected user, store the login
                                if login.attrib["username"] == self.get_option("user"):
                                    self.inventory.set_variable(
                                        node_name,
                                        "ansible_user",
                                        login.attrib["username"],
                                    )
                                    self.inventory.set_variable(
                                        node_name,
                                        "ansible_host",
                                        login.attrib["hostname"],
                                    )
                                    self.inventory.set_variable(
                                        node_name, "ansible_port", login.attrib["port"]
                                    )
                                    login_found = True
                                    break

                            if login_found:
                                break

    def parse(self, inventory, loader, path, cache=True):
        if not HAS_REQUESTS:
            raise AnsibleError(
                "This module requires Python Requests 1.1.0 or higher: "
                "https://github.com/psf/requests."
            )

        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path)

        # read config from file, this sets 'options'
        self._read_config_data(path)

        self.cloudlab_url_base = self.get_option("url").rstrip("/")

        self._populate()
