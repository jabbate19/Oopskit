# Oopskit
## Me when I kernel panic a router: "Oops"

## What is it?
Oopskit is a FreeBSD rootkit designed to provide shells and disable pfctl for red team to get better control.

## How does it work?
It does this by adding a hook to the beginning of the firewall chain and activating a command on the proper packet
This packet can be sent from "get_shell.py", or by sending any ICMP packet of type 105 and code 1.

## Reverse Shell
The reverse shell will be sent to the IP it received the packet from at port 4444.
