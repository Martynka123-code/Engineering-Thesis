# IEEE 802.11 Deauthentication frame - detailed description

The Deauthentication frame is an IEEE 802.11 Management frame used to explicitly terminate an existing 
authentication connection between a wireless station (STA) and an Access Point (AP).
It could be sent by either the AP or the STA to immediately end the connection.
In 802.11 network the deauthentication means the invalidation both authentication and association, 
dropping the client back to the first state - an unauthenticated and unassociated.
In 802.11w network where the PMF was enabled it is important to remember that only robust management frames are protected and should 
be used in the communication between the AP and other devices. These include Disassociation, Deauthentication and Robust Action frames.
The unprotected unicast ones for example the Deauthentication should be taken as a possible attack.

There are 2 possible kinds of this frame: unicast or broadcast. 
The difference is mainly focused on the destination if it is an attack on one station or on all the devices from the network.

## Deauthentication frame fields and structure

A Deauthentication frame contains specific header fields defined by the IEEE 802.11 standard:

- wlan.fc.type = 0 - This specifies what type the frame is the Management frame type (type 0).
- wlan.fc.subtype = 12 - This informs that it is the Deauthentication subtype (subtype = 12, or hexadecimal 0x000c).
- wlan.sa - Source Address; This is a MAC address of the source, which transmits the frame.
- wlan.da - Destination Address; This is a MAC address of the intended recipient node or the broadcast address (ff:ff:ff:ff:ff:ff).
- wlan.bssid - Basic Service Set Identifier; It contains the MAC address of the Access Point's wireless interface.
- wlan.fixed.reason_code - A 16-bit integer field indicating why the Deauthentication or Disassociation attacks were intended (e.g., Reason Code = 7 - Class 3 frame received from nonassociated STA; Reason Code = 1 - Unspecified reason).
- wlan.fc.protected - This field indicates whether the Management frame is cryptographically protected or not (1 = protected; 0 = unprotected) using Protected Management Frames (PMF / IEEE 802.11w).

## One-way notification nature

Unlike handshakes or association requests, a Deauthentication frame is a one-way notification command rather than a request
or negotiation. In traditional 802.11 networks lacking the Protected Management Frames (PMF), the receiving device cannot decline, 
ignore or reject a Deauthentication frame. From receiving a frame with correct victim's MAC address, the recipient must immediately 
end the Security Association and disassociate.

When IEEE 802.11w (PMF) is enabled, legitimate Deauthentication unicast frames sent by the AP or by the STA must have 
wlan.fc.protected = 1. An unprotected unicast Deauthentication frame (wlan.fc.protected = 0) received during an active PMF session
cannot be blindly trusted, and it is treated as a potential spoofing attack.

## The difference of Deauthentication frame and Disassociation frame

While both Deauthentication and Disassociation frames are Management frames used to tear down wireless connections,
they differ in subtype, protocol layer scope and impact on the device state:

- Frame subtype - Deauthentication uses wlan.fc.subtype = 12 (0x000c), whereas Disassociation uses wlan.fc.subtype = 10 (0x000a).
- State transition - Deauthentication tears down both the authentication and association, moving the client from State 3, which means being authenticated and associated or State 2 - being authenticated and unassociated down to State 1 - being unauthenticated and unassociated. Disassociation tears down only the association, moving client from being authenticated and associated to authenticated and unassociated.
- Protocol flow - Disassociation typically occurs during roaming or controlled disconnects when authentication credentials remain valid. Deauthentication represents a complete termination requiring full re-authentication (e.g. 802.1X/EAP exchange or WPA PSK handshake) to reconnect.

---
PROVENANCE: The frames' format and state transitions are based on the IEEE 802.11-2020, and the AWID3 appearance.