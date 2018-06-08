# llmnr-sphinx
Ask questions of your network to find a rogue LLMNR server.

## Introduction
This application operates by sending LLMNR queries to the local network attempting to identify if an attacker is running an LLMNR spoofer.

It is designed to be run on a workstation network to which an attacker could have access.

```
$ python llmnr_sphinx.py -h
usage: llmnr_sphinx.py [-h] [--config CONFIG]

A service that detects llmnr spoofers on a network

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        path to config file. Defaults to:
                        /etc/llmnr_sphinx/config.ini
```

### Demo

![Demo](https://github.com/SecurityRiskAdvisors/doc-repo/raw/master/llmnr_sphinx_demo.gif)

## Features
- LLMNR Spoofing Detection based on custom queries.

Sphinx allows you to create custom queries tuned to your envionrment to generate alerts only when a spoofer is on the network.

- Alerting with IP and MAC address information.

Sphinx will generate an alert including the MAC address information of the attacker. This information can be used with the `mac address table` for common managed routers to identify what port a device was plugged into.

Sample Alert Message:
```
LLMNR Spoofing confirmed from 84:7b:eb:b5:4d:de (192.168.89.130). Query Data: [{"qname": "$random:knjzjb", "name": "knjzjb.", "ans": "192.168.89.130"}, {"qname": "localhost", "name": "localhost.", "ans": "192.168.89.130"}].
```

- Multi-round detection

In order to decrease false-positives, multiple rounds are used to increase alert severity.

## Usage

- Clone the repo.

  `git clone https://github.com/SecurityRiskAdvisors/llmnr-sphinx.git`

- Go into the directory

  `cd llmnr-sphinx`

- Install the required dependencies.

   `pip install -r requirements.txt`

- Update the `config.ini` with the correct interface (see [here](#general))
- Update the `config.ini` with envionrment specific [rounds](#rounds), however generally the [default config](#default-config) is fine. _(Optional)_
- Launch the script using `sudo python /path/to/llmnr_sphinx -c /path/to/config.ini`
- Once you've determined it's working, you can use the `systemd` script to run it as a service. See here: [Installation](#installation).

### Configuration
To run the application update the `config.ini` file with the correct interfaces and the queries in the `[General]` section.

#### General

 - `sending_delay`: The time in seconds to send packets. Default: 10
 - `output`: Currently the only support output is syslog however more will be added. Default: syslog
 - `interface`: The interface to send and receive traffic. You can leave blank however this is **not reccomended.** While the script will attempt to auto-detect the interface to send the traffic, it's better to define your own interface.
 
 *Advanced Parameters*
 
 - `send_interface`/`listen_interface`: Send and listen on different interfaces.
 - `timeout`: The listen timeout, should be less than the sending delay.



```
[General]
sending_delay = 10
output = syslog
interface=

# Advanced
#send_interface=
#listen_interface=
#timeout = 5
```

#### Rounds
LLMNR-Sphinx has two rounds configured, one is used to identify an instance of Responder on the network, the second round is used to confirm the finding. These are defined as __Rounds__.

*Hostname Configuration*

The general format for hostname configuration is as follows:

`hostname = ip.ip.ip.ip`

Where `hostname` is what is queried, and `ip.ip.ip.ip` is the expected response, the script will generate an alert for any response returned other than the expected (configured) response.

You can also set the hostname to multiple expected IP addresses -- the IP addresses must be space seperated.

`hostname = ip.ip.ip.ip ip2.ip2.ip2.ip2`

#### Special Options

LLMNR-Sphinx supports special options to cover general cases.

- `hostname = None`

 In this case, any response for `hostname` will be considered an exception. Useful when you want to query a arbitrary host which should not have a response on your network.

- `$random = None`

 Using `$random` as a hostname will generate a random string with each query. Useful when coupled with `None` however it is not required, can be configured with an IP address.

__Round 1__

This round are the queries that are normally sent out. If there are multiple options provided for a round, the script will randomly choose one of them and send it out.
By default _Round 1_ is defined as follows:
```
[round-1]
$random = None
```
However, you can have as many hostname/IP pairs in the round as you want, and each will be randomly selected per loop.

__Round 2__

Everything that applied for _Round 1_ applies here, except that _Round 2_ only runs if there is a positive result from _Round 1_.

## Default Config
The default config is as follows:
```
[round-1]
$random = None

[round-2]
localhost = None
_http = None
_smtp = None
_kerberos = None
```

## Generating Alerts
This script will generate alerts directly to syslog. You can then use a syslog engine (such as `rsyslogd` or `syslog-ng`) to ship syslog messages.

Based on feature requests other output modes will be considered.

LLMNR-Sphinx will generate syslog messages at various priority levels to allow for easy filtering:

- Confirmed LLMNR Spoofer (2 responses): Alert
- Detected LLMNR Spoofer (1 Response): Critical
- Heartbeat Message: Notice
- Program Messages: Debug

### Sample rsyslog Config
A sample configuration as below can be used to only get alert messages and to only recieve heartbeat messages once a day.

```
if $programname startswith 'llmnr_sphinx' then {

  # Heartbeat Messages
  if $syslogseverity == '5' then {
		action(type="omfwd" target="logger.localhost" port="514" protocol="tcp" action.resumeRetryCount="100" queue.type="linkedList" queue.size="10000" action.execonlyonceeveryinterval="86400")
	}

  # Detection messages
  if $syslogseverity <= '4' then {
		action(type="omfwd" target="logger.localhost" port="514" protocol="tcp" action.resumeRetryCount="100" queue.type="linkedList" queue.size="10000" action.execOnlyOnceEveryInterval="30")
	}
	
}
```

## Installation
By default the application looks for a config in the `/etc/llmnr_sphinx/` directory. However, it can be overrided on the command-line with a `-c` parameter.

There is also a `systemd` service file provided for installation.

## Considerations

This tool uses Scapy to craft and parse packets and as a result requires `root`.

If it's determined that this is an issue that dependency can be removed, *however it will always have to start as root to set up the raw socket.*

This tool is not meant to work with Windows.

## Acknowledgments ##
- https://github.com/lgandx/Responder
- https://github.com/Kevin-Robertson/Conveigh
