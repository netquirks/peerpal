# peerpal

Made available freely from netquirks.co.uk.

Author: Steven Crutchley

# Overview

Python script for automating Cisco CLI BGP peering configuration based on peeringdb.com

This simple script takes in two different ASNs and, reading from the PeeringDB API, will find and list where the ASNs have common peering points. You can then select from the list which sites you wish to configure peering for and it will generate the CLI config needed to paste onto the router to set up the peering (from the perspective of the first ASN).

Details of the BGP configuration, such as local ASN, neighbor-group, MD5 password or ttl-security are read in from a config file. The config file has a DEFAULT section and can optionally have section for specific exchange points that override the global defaults.

# Usage

After correctly configuring the config file (see below) run the script using 'python3 ./peerpal.py'. There are 3 optional arguments:

* -p <Peer_ASN_number> - where <Peer_ASN_number> is an integer representing the the ASN number of the potential peer you wish to setup. If this argument is omitted when running the script, peerpal will prompt for it. 

* -l <Local_ASN_number> - where <Local_ASN_number> is an integer representing the you local ASN. This will override what is configured in the config file. If this argument is omitted, the **as** value in the config file will be used.

* -d - debugging. This produces verbose debugging output.

The neighbor description and max-prefix values will autogenerate from the peeringDB IRR and IPv4/6 Prefix fields respectively. Other variables for peering are read from the config file.

# Config file

This python script utilizes the 'configparser' module. The config file must be named 'peerpal.conf' and be stored in the same folder as 'peerpal.py'. The peerpal config file is used to read in variables pertinent to the BGP configuration for each peering. A sample config has been provided in this git repository.

The config file is comprised of one DEFAULT section and multiple optional Internet Exchange (IX) sections.
Each IX section should be titled with the name of IX according to peeringDB. This is case sensitive and needs to be exact. Run peerpal against your own AS to get the extact list and spelling of the Exchanges you are present at.

Variables in the DEFAULT section can be optional or obligatory. 
All variables in IX sections are optional. 
All peering variables can be configured in both the DEFAULT and IX sections (see 'correction' and 'routers' for exceptions to this rule). If variables are absent of an IX section, and needed for the peering config, the values in the DEFAULT section will be used (see 'password' below for an exception to this rule).
Variables cannot contain spaces and are formatted as follows: 'variable_name = value'

Obligatory Peering Variables:
* **op_sys**: The operating system of the router for which the peering config will be generated. Valid values are 'ios','xr' or 'both'.
* **xr_neigh_grp_v4**: The neighbor group used in XR IPv4 BGP peerings
* **xr_neigh_grp_v6**: The neighbor group used in XR IPv6 BGP peerings
* **ios_neigh_grp_v4**: Used for IOS IPv4 peerings. This value can be either a single string or a comma separated list of length 2. If a single value is the used the peering output will use a peer-group named with the given string. If two variables are given via a comma separated list, the first variable will be a peer-session template name and the second variable will be a peer-policy template name. 
* **ios_neigh_grp_v6**: Used for IOS IPv6 peerings. Works on the same principle as ios_neigh_grp_v4.

Optional Peering Variables:
* **as**: Specifies the autonomous system of the user. If it is not in the DEFAULT section peerpal will prompt the user for it.
* **password**: Used to specify MD5 authentication on the BGP peering. If the password variable is absent from an IX section no MD5 password will be used. If a password variable named 'default' is defined in an IX section, the password defined in the DEFAULT section will be used. If a password variable of any other string is defined in an IX section, it will be used as an MD5 password.
* **ttl_sec**: Used for GTSM through ttl-security. Valid values are 'true' or 'false'. If set to 'true' ttl-security (with value 1) will be used.
* **routers**: Only to be used in an IX Section. This is comma seperated list that should contain the hostnames of the routers onto which the peering config should be applied. This has no bearing on the resulting BGP config and is printed to screen only as a reminder to the user what routers need to have the config applied. 
* **correction**: Only to be used in an IX Section. For any given IX, PeeringDBs API is sometimes not updated with the IX name. When this is the case the name of the IX will be defined by peerpal as Exchange_Number_<IX_Num>. Where IX_Num is the net_id given to the Exchange under the peeringDB API (e.g. https://www.peeringdb.com/api/ix/<net_id>). If an exchange that you are present at does not have a name it will show as Exchange_Number_<IX_Num> in the list of IX names when you run peerpal against your own ASN. The section in the config file must be named using the Exchange_Number_<IX_Num> format but if this section contains a variable called 'correction' then peerpal will replace all references to Exchange_Number_<IX_Num> with the correction variable. An example is shown below for DE-CIX Madrid, which has net id 1250. 


# Example

This example uses the sample config file in this repository and though the ASNs and company names are fake, it shows how the logic of the script works.

```
myhost:peerpal Steve$ python3 ./peerpal.py 5678
Starting peerpal
Attempting to read config file.
Reading defaults from config.
Config file successful read.
Using local ASN 5678 from config file
Using peer ASN 1234
Finding peering information. Standby...
Determining common exchange points.

The following are the locations where Netquirks and ACME have common IPv4 presence:
(IPs for ACME are displayed)
1: LINX LON1 - 192.168.101.1
2: Equinix Paris - 192.168.222.2
3: CATNIX - 10.10.1.50
4: DE-CIX Frankfurt - 172.16.1.90,172.16.1.95
5: LINX LON2 - 192.168.2.10
6: IXManchester - 10.11.11.25
7: GigaPIX - 172.16.30.30
8: France-IX Paris - 172.16.31.1,172.16.31.2
9: LONAP - 10.5.5.5
10: DE-CIX_Madrid - 192.168.7.7
Please enter comma-seperated list of desired peerings (e.g. 1,3,5) or enter 'n' not to peer over IPv4: 3,6

The following are the locations where Netquirks and ACME have common IPv6 presence:
(IPs for ACME are displayed)
1: LINX LON1 - 2001:1111:1::50
2: Equinix Paris - 2001:cafe:f00d::1
3: CATNIX - 2001:2345:6789::ca7
4: DE-CIX Frankfurt - 2001:abc:123::1,2001:abc:123::2
5: LINX LON2 - 2001:7777:aaaa:33::21fa:1
6: IXManchester - 2001:7ff:2:2::ea:1
7: GigaPIX - 2001:cafe:aaaa:1::5
8: France-IX Paris - 2001:abab:1aaa::60,2001:abab:1aaa::61
9: LONAP - 2001:cccc:3333::30ea:1
10: DE-CIX_Madrid - 2001:7f9:e12::fa:0:1
Please enter comma-seperated list of desired peerings (e.g. 1,3,5) or enter 'n' not to peer over IPv6: 6,10,8

IPv4 Peerings:
****************

The CATNIX IPv4 peerings are as follows:
=============================================================
Enter the following config onto these routers:
cat-rtr1.netquirks.co.uk

IOS CONFIG
----------
router bgp 5678
 neighbor 10.10.1.50 remote-as 1234
 neighbor 10.10.1.50 description AS-ACME
 neighbor 10.10.1.50 inherit peer-session EXTERNAL
 neighbor 10.10.1.50 ttl-security hops 1
 address-family ipv4 unicast
  neighbor 10.10.1.50 activate
  neighbor 10.10.1.50 maximum-prefix 800 90 restart 60
  neighbor 10.10.1.50 inherit peer-policy CATNIX

The IXManchester IPv4 peerings are as follows:
=============================================================
Enter the following config onto these routers:
mchr-rtr1.netquirks.co.uk
mchr-rtr3.netquirks.co.uk

XR CONFIG
----------
router bgp 5678
 neighbor 10.11.11.25
  remote-as 1234
  use neighbor-group default_v4_neigh_group
  ttl-security
  description AS-ACME
  address-family ipv4 unicast
   maximum-prefix 800 90 restart 60

IOS CONFIG
----------
router bgp 5678
 neighbor 10.11.11.25 remote-as 1234
 neighbor 10.11.11.25 description AS-ACME
 neighbor 10.11.11.25 inherit peer-session peer-sess-mchr4
 neighbor 10.11.11.25 ttl-security hops 1
 address-family ipv4 unicast
  neighbor 10.11.11.25 activate
  neighbor 10.11.11.25 maximum-prefix 800 90 restart 60
  neighbor 10.11.11.25 inherit peer-policy peer-pol-mchr4

IPv6 Peerings:
****************

The IXManchester IPv6 peerings are as follows:
=============================================================
Enter the following config onto these routers:
mchr-rtr1.netquirks.co.uk
mchr-rtr3.netquirks.co.uk

XR CONFIG
----------
router bgp 5678
 neighbor 2001:7ff:2:2::ea:1
  remote-as 1234
  use neighbor-group default_v6_neigh_group
  ttl-security
  description AS-ACME
  address-family ipv6 unicast
   maximum-prefix 40 90 restart 60

IOS CONFIG
----------
router bgp 5678
 neighbor 2001:7ff:2:2::ea:1 remote-as 1234
 neighbor 2001:7ff:2:2::ea:1 description AS-ACME
 neighbor 2001:7ff:2:2::ea:1 inherit peer-session peer-sess-mchr6
 neighbor 2001:7ff:2:2::ea:1 ttl-security hops 1
 address-family ipv6 unicast
  neighbor 2001:7ff:2:2::ea:1 activate
  neighbor 2001:7ff:2:2::ea:1 maximum-prefix 40 90 restart 60
  neighbor 2001:7ff:2:2::ea:1 inherit peer-policy peer-pol-mchr6

The DE-CIX_Madrid IPv6 peerings are as follows:
=============================================================

IOS CONFIG
----------
router bgp 1042
 neighbor 2001:7f9:e12::fa:0:1 remote-as 1234
 neighbor 2001:7f9:e12::fa:0:1 description AS-ACME
 neighbor 2001:7f9:e12::fa:0:1 peer-group Mad1-6
 neighbor 2001:7f9:e12::fa:0:1 ttl-security hops 1
 address-family ipv6 unicast
  neighbor 2001:7f9:e12::fa:0:1 activate
  neighbor 2001:7f9:e12::fa:0:1 maximum-prefix 40 90 restart 60

The France-IX Paris IPv6 peerings are as follows:
=============================================================

XR CONFIG
----------
router bgp 5678
 neighbor 2001:abab:1aaa::60
  remote-as 1234
  use neighbor-group FRANCE-NEIGH-IXv6
  description AS-ACME
  address-family ipv6 unicast
   maximum-prefix 40 90 restart 60

XR CONFIG
----------
router bgp 5678
 neighbor 2001:abab:1aaa::61
  remote-as 1234
  use neighbor-group FRANCE-NEIGH-IXv6
  description AS-ACME
  address-family ipv6 unicast
   maximum-prefix 40 90 restart 60
myhost:peerpal Steve$
```

# Known issues

You cannot use the "Also Known As" field for the ASN
