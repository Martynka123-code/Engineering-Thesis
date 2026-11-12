# The protected management frames in IEEE 802.11 networks with PMF enabled

In an IEEE 802.11 network operating with Protected Management Frames (PMF / 802.11w) enabled, 
Management frames transmitted between authenticated stations(STAs) and the Access Point (AP) are cryptographically
encrypted and integrity-protected. This protection is indicated by the frame field wlan.fc.protected = 1 dedicated for unicast connections.
A Deauthentication frame with the protected flag set to 1 (wlan.fc.protected = 1) is not a forged attack.

Crucially, any Management unicast frame with wlan.fc.protected = 1 is a real frame transmitted by a legitimate network node possessing valid key material. 
These protected frames must NEVER be classified or reported as attacks. Conversely, unicast Deauthentication, Disassociation and 
Robust Action frames arriving with wlan.fc.protected = 0 in a PMF-enabled network represent unprotected, 
potentially forged frames that must be evaluated as potential attack attempts. 
Beacon, probe, authentication and association frames are never protected and are not evidence of an attack.

A protected frame can only exist after a successful 4-way handshake.
During this handshake, the Pairwise Transient Key (PTK) was derived to protect unicast Management frames, and 
the Integrity Group Temporal Key (IGTK) was distributed via EAPOL-Key Message 3 to protect broadcast/multicast Management frames after successful establishment of an IGTKSA
using the Broadcast Integrity Protocol (BIP), which was defined in 802.11w.
BIP protects broadcast Management frames only with an integrity check and does not set the protected bit: 
a genuine broadcast Deauthentication frame protected by BIP still has wlan.fc.protected = 0.

If a non-AP STA that has an SA with its AP for an association that negotiated Management Frame Protection receives an unprotected Deauthentication or Disassociation frame with reason code 6 or 7 from the AP,
the non-AP STA may use this as an indication that there may be a mismatch in the association state between
itself and the AP. In such a case, the non-AP STA may initiate the SA Query procedure with the AP to verify
the validity of the SA by issuing one MLME-SAQuery.request primitive every
dot11AssociationSAQueryRetryTimeout until a matching MLME-SAQuery.confirm is received or
dot11AssociationSAQueryMaximumTimeout TUs from the beginning of the SA Query procedure has
passed. If the AP replies to the SA Query request with a valid SA Query response that has a matching transaction identifier, the non-AP STA may continue to use the SA. If no valid SA Query response is received,
the non-AP STA may destroy the SA and move into State 1 with the AP.

## The legitimate situations for the protected Management frames

Protected Management frames (wlan.fc.protected = 1) legally and routinely appear in normal network operations under several scenarios:

- Deauthentication unicast frames (wlan.fc.subtype = 12) - Transmitted by the real AP or STA with wlan.fc.protected = 1 when a session is legitimately terminated or credentials expire.
- Disassociation unicast frames (wlan.fc.subtype = 10) - Transmitted with wlan.fc.protected = 1 during controlled client roaming or normal disassociation events.
- SA Query Exchange frames (wlan.fc.subtype = 13) - Both SA Query Request and SA Query Response frames are required by IEEE 802.11w to have wlan.fc.protected = 1 to challenge unauthenticated disconnect attempts and verify active Security Associations.

---
PROVENANCE: Information was taken from Cisco's document dedicated to 802.11w standard and from 802.11w-2009 - IEEE Standard for Information technology - Telecommunications and information exchange between systems - Local and metropolitan area networks - Specific requirements. Part 11: Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications Amendment 4: Protected Management Frames directly from the section 11.13 - SA Query procedures.