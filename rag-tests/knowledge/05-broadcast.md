# The broadcast variant is out of scope

A Deauthentication frame addressed to broadcast MAC address (ff:ff:ff:ff:ff:ff) reaches every client associated with the Basic Service Set (BSS) at once. 
In an IEEE 802.11 network with Protected Management Frames (PMF) enabled, an unprotected broadcast Deauthentication frame satisfies three of the four signature conditions - Management type (wlan.fc.type = 0), Deauthentication subtype (wlan.fc.subtype = 12), and unprotected flag (wlan.fc.protected = 0).

It is nonetheless a different attack and is not reported here. The scope is the unicast variant: a forged frame addressed to one named station.

## Telling them apart

The recipient address decides, and nothing else does:
- wlan.da = ff:ff:ff:ff:ff:ff - broadcast, out of scope
- wlan.da = a station MAC address - unicast, in scope

## Why the broadcast exclusion is necessary

A detection system that fails to check wlan.da will mistakenly count unprotected broadcast frames as unicast attack attempts. 
Because broadcast frames match the frame type (wlan.fc.type = 0), frame subtype (wlan.fc.subtype = 12), 
and unprotected flag (wlan.fc.protected = 0), treating them as unicast attacks inflates frame and episode counts, 
leading to false positive alerts and silent classification failures.

---
PROVENANCE: The addressing rule follows from the frame format based on the 802.11w-2009 - IEEE Standard for Information technology - Telecommunications and information exchange between systems - Local and metropolitan area networks - Specific requirements. Part 11: Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications Amendment 4: Protected Management Frames document from the section 11.12 - Broadcast and multicast Robust Management frame procedures
and AWID3 dataset feature schemas and appearance.