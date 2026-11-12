# The SA Query exchange and attack defense mechanism

The Security Association (SA) Query procedure is a protective mechanism in IEEE 802.11w (Protected Management Frames - PMF) 
to defend active wireless connections against Deauthentication and Disassociation attacks. When a device is operating under
PMF receives an unprotected or suspicious Management frame attempting to end its connection, it does not immediately
terminate its Security Association. Instead, it may initiate an SA Query exchange to verify whether 
the legitimate peer actually requested the termination.

## Reason code filtering and SA Query triggering

A station operating under PMF evaluates the reason code (wlan.fixed.reason_code) of incoming unprotected Deauthentication frame before taking action:

- Triggering SA Query (Reason Code 6 and 7) - A station initiates an SA Query exchange only when receiving an unprotected Deauthentication frame with Reason Code wlan.fixed.reason_code = 6 "Class 2 frame received from nonauthenticated station" or Reason Code wlan.fixed.reason_code = 7 "Class 3 frame received from nonassociated station". These codes signal that the AP supposedly lost session context while the station believes the session is active.
- Silent drop (other Reason Codes) - For all other Reason Codes, the station silently discards the unprotected frame without initiating an SA Query exchange, maintaining its active session uninterrupted.

Therefore, absence of an SA Query exchange does not automatically imply that an attack succeeded.

## The SA Query sequence and frame parameters

The SA Query exchange consists of a protected two-way Action frame exchange:

1. SA Query Request - Sent by the recipient of the unprotected Deauthentication frame to its peer. Header fields: wlan.fc.type = 0 (Management frame), wlan.fc.subtype = 13 (Action frame) and wlan.fc.protected = 1 (cryptographically encrypted and protected).
2. SA Query Response - Sent back by the peer after receiving the request, using identical header fields: wlan.fc.type = 0, wlan.fc.subtype = 13 and wlan.fc.protected = 1.

The requirement of wlan.fc.protected = 1 guarantees that both frames are encrypted and are from real nodes from wireless network, because an attacker has no keys to protect them.

## The meaning of the SA Query presence

The appearance of the SA Query exchange after the first signature-match frame (wlan.fc.protected = 0)
provides direct evidence that the receiving station challenged the forged frame and refused to disconnect: the attack was blocked. When data frames
involving the client also continue afterward the last signature-match frame, the attack was blocked. 
This holds even when the capture is truncated and the data frames after the last signature-match frame are UNKNOWN.

## The meaning of the SA Query absence

When no SA Query exchange appears after the first signature-match frame, the outcome is determined by the client data traffic after the last signature-match frame and by the length of the post-attack observation window:

- Successful attack (No SA Query frames and client falls silent) - If the observation window after the last forged frame is sufficient and no further client traffic occurs after the last signature-match frame, it indicates that the attack probably succeeded and forced a disconnection.
- Unsuccessful attack (No SA Query frames, but client still sends data frames) - Reason for this is that the station silently dropped the forged frame (e.g. due to reason code filtering) and remained connected as previous scenario. When data traffic involving the client continues after the last forged frame, the attack failed and the outcome is the attack was blocked.
- Truncated capture (Unknown outcome) - If the post-attack observation window is truncated, the Data frame line reads UNKNOWN. The absence of SA Query or data traffic cannot be evaluated, so whether the attack did succeed is unknown.

In case of a failed SA Query procedure, if the AP receives an Association frame from the STA with which it has an existing SA, 
then the AP shall send a protected Disassociation frame to this STA prior to terminating the old SA, with Reason Code “Previous Authentication no longer valid.”
---
PROVENANCE: Protocol procedure frame details defined in 802.11w-2009 - IEEE Standard for Information technology - Telecommunications and information exchange between systems - Local and metropolitan area networks - Specific requirements. Part 11: Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications Amendment 4: Protected Management Frames in sections: 11.3.2.2 - AP association procedures.
Own assumptions of this work: SA Query frames are counted from the first signature-match frame and data frames from the last one. 
Limitation: without keys a protected Action frame (subtype 13) cannot be told apart from other protected Action frames, so every protected Action frame involving the client is counted as SA Query.