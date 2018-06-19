#!/usr/bin/env python

import pytest
import mock
from pytest_mock import mocker



from scapy.all import *
import configparser
import random
import re
import threading
import time
import syslog
import json
import argparse

import llmnr_sphinx


def test_randomword():
    assert len(llmnr_sphinx.randomword()) == 6
    assert len(llmnr_sphinx.randomword(7)) == 7
    pass

class TestParseConfigInterfaces():
    def test_non_existant_interface(self,mocker):
        interface_name='eth0'
        m_socket = mocker.patch.object(conf,'L3socket', side_effect=OSError)
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_config_interfaces(interface_name)
            pass
        pass
    
    def test_empty_string(self):
        assert llmnr_sphinx.parse_config_interfaces('') == None
        pass
    
    def test_none_as_option(self):
        assert llmnr_sphinx.parse_config_interfaces('None') == None
        pass

    def test_working_interface(self,mocker):
        interface_name = 'eth0'
        m_socket = mocker.patch.object(conf,'L3socket')
        llmnr_sphinx.parse_config_interfaces(interface_name)
        m_socket.assert_called_with(iface=interface_name)
        pass

    pass

class TestReadFile():

    config_file = '/etc/llmnr_sphinx/config.ini'

    def test_non_existant_file(self, mocker):
        mocker.patch('os.path.getsize', side_effect=FileNotFoundError)
        with pytest.raises(OSError):
            llmnr_sphinx.read_file(self.config_file)
            pass
        pass

    def test_non_readable_file(self, mocker):
        mocker.patch('os.path.getsize', return_value = 1024)
        mocker.patch('llmnr_sphinx.open', side_effect=PermissionError)
        with pytest.raises(OSError):
            llmnr_sphinx.read_file(self.config_file)
            pass
        pass

    def test_file_size_too_big(self, mocker):
        mocker.patch('os.path.getsize', return_value = 1 * 2**21)
        with pytest.raises(ValueError):
            llmnr_sphinx.read_file(self.config_file)
            pass
        pass

    #def test_file_changed_after_read(self, mocker):
    #    # Cannot figure out how to do this test. If someone can tell me I'll do it.
    #    mocker.patch('os.path.getsize', return_value = 1)
    #    with mock.patch('llmnr_sphinx.open', mock.mock_open(read_data="data")) as mock_file:
    #        with pytest.raises(ValueError):
    #            llmnr_sphinx.read_file(self.config_file)
    #            pass
    #        pass
    #    pass

    pass

class TestParseParameters():

    config_contents = [
    "[General]",
    "sending_delay = {sending_delay}",
    "timeout = {timeout}",
    "output = {output}",
    "interface= {interface}",
    "#send_interface= {send_interface}",
    "#listen_interface= {listen_interface}",
    "[round-1]",
    "$random = {$random}",
    "dc2 = {dc2}",
    "[round-2]",
    "localhost = {localhost}"
    ]

    config_values = {'sending_delay': "10", 'timeout': 5, 'output': "syslog", 'interface': "ens32", 'send_interface': "ens32", 'listen_interface': "ens32", '$random': "None", 'dc2': "192.168.1.1 10.0.0.1", 'localhost': "None"}

    def test_functioning_parser(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        assert type(llmnr_sphinx.parse_parameters('\n'.join(self.config_contents).format(**self.config_values))) == type(dict())
        pass

    def test_non_int_delay(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        config_vals_local = self.config_values.copy()
        config_vals_local['sending_delay'] = 'a string'
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_parameters('\n'.join(self.config_contents).format(**config_vals_local))
            pass
        pass

    def test_non_int_timeout(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        config_vals_local = self.config_values.copy()
        config_vals_local['timeout'] = 'a string'
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_parameters('\n'.join(self.config_contents).format(**config_vals_local))
            pass
        pass

    def test_timeout_larger_delay(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        config_vals_local = self.config_values.copy()
        config_vals_local['timeout'] = 15
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_parameters('\n'.join(self.config_contents).format(**config_vals_local))
            pass
        pass

    def test_multiple_int_types(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        config_vals_local = self.config_values.copy()
        config_contents_local = self.config_contents.copy()
        config_contents_local.insert(1,"send_interface= {send_interface}")
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_parameters('\n'.join(config_contents_local).format(**config_vals_local))
            pass
        pass


    def test_incorrect_output(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        config_vals_local = self.config_values.copy()
        config_vals_local['output'] = 'not_syslog'
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_parameters('\n'.join(self.config_contents).format(**config_vals_local))
            pass
        pass

    def test_empty_round(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        config_vals_local = self.config_values.copy()
        config_contents_local = self.config_contents.copy()
        del(config_contents_local[-1])
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_parameters('\n'.join(config_contents_local).format(**config_vals_local))
            pass
        pass

    def test_incorrect_ip_addr(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        config_vals_local = self.config_values.copy()
        config_contents_local = self.config_contents.copy()
        config_vals_local['dc2'] = '192.168.1.1,192.168.1.1'
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_parameters('\n'.join(config_contents_local).format(**config_vals_local))
            pass
        pass

    def test_missing_section(self, mocker):
        mocker.patch('llmnr_sphinx.parse_config_interfaces', return_value = self.config_values['interface'])
        config_vals_local = self.config_values.copy()
        config_contents_local = self.config_contents.copy()
        del(config_contents_local[-2:])
        with pytest.raises(ValueError):
            llmnr_sphinx.parse_parameters('\n'.join(config_contents_local).format(**config_vals_local))
            pass
        pass
    pass

