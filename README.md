# encrypted-syslog-amplifier
This is an encrypted syslog amplifier for data diodes. It is used to send logs in a network with a higher security level.

# syslog configuration

For Syslog via data diode you need to enable UDP server in /etc/rsyslog.conf or inside the included config file /etc/rsyslog.d/remote.conf:

module(load="imudp")
input(type="imudp" port="514" Address="127.0.0.1")

on the destination server. This is the syslog input for the concentrator where datadiode-syslog-deamplifier will send data to. 

Client syslog daemons should send data into the datadiode-syslog-amplifier:

*.* @datadiode-amplifier-host-ip:1514

 Similar settings for BSD syslog and syslog-ng if they are the choice over rsyslog.
