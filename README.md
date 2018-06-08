# llmnr-sphinx
Ask questions of your network to find a rogue LLMNR server.

## Introduction
This application operates by sending LLMNR queries to the local network attempting to identify if an attacker is running an LLMNR spoofer.

It is designed to be run on a workstation network.

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

## Features
- LLMNR Spoofing Detection based on custom queries.

Sphinx allows you to create custom queries tuned to your envionrment to generate alerts only when a spoofer is on the network.

- Alerting with IP and MAC address information.

Sphinx will generate an alert including the MAC address information of the attacker. This information can be used with the `mac address table` for common managed routers to identify what port a device was plugged into.

- Multi-round detection

In order to decrease false-positives, multiple rounds are used to increase alert severity.

## Considerations

This tool requires `root` as a Scapy dependency. If overtime it is determined that root is an issue it can be removed. Please open an issue if that is a problem.

This tool also uses scapy to craft and parse packets.

This tool is not mean to work with Windows.


## Usage
Install the required dependencies.

`pip install -r requirements.txt`

To run the application update the `config.ini` file with the correct interfaces and the queries.

You can select whatever hostname you want, there are some custom options to handle special cases.

The general format for hostname configuration is as follows:
`hostname = ip.ip.ip.ip`
Where `hostname` is what is queried, and `ip.ip.ip.ip` is the expected response, the script will generate an alert for any response besides the expected response.

You can also set the hostname to multiple possible IP addresses where hosts are dual-homed, the IP addresses must be space seperated.
`hostname = ip.ip.ip.ip ip2.ip2.ip2.ip2`

Some special options are allowed instead of an IP:
`hostname = None`
In this case, any response for that hostname will be considered an exception.

Finally, a special option for hostname is also allowed:
`$random = None`
Using `$random`  for a hostanme value will generate a random hostname with each query.


### Rounds
LLMNR-Sphinx will send out a follow-up query if it detects a rogue unit is running. These are defined as __Rounds__.

#### Round 1
This round are the queries that are normally sent out. If there are multiple options provided for a round, the script will randomly choose one of them and send it out.
By default _Round 1_ is defined as follows:
```
[round-1]
$random = None
```
However, you can have as many hostname/IP pairs in the round as you want, and each will be randomly selected per loop.

#### Round 2
Everything that applied for _Round 1_ applies here, except that _Round 2_ only runs if there is a positive result from _Round 1_.

This is run as a follow up.


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

## Installation
By default the application looks for a config in the `/etc/llmnr_sphinx/` directory. However, it can be overrided on the command-line with a `-c` parameter.

There is also a `systemd` service file provided for installation.

## Acknowledgments ##
https://github.com/lgandx/Responder

https://github.com/Kevin-Robertson/Conveigh
