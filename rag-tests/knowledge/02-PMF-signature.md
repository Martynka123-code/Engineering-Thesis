# The signature of forged Deauthentication frame under PMF

When an IEEE 802.11 network operates with Protected Management Frames (PMF / 802.11w)
enabled, Deauthentication frames transmitted by legitimate network nodes are cryptographically
protected. The enhanced data confidentiality, data authentication, and replay protection mechanisms require fresh
cryptographic keys and corresponding security associations. The procedures defined in this standard provide
fresh keys by means of protocols called the 4-Way Handshake, FT 4-Way Handshake, FT Protocol, FT
Resource Request Protocol, and Group Key Handshake. An attacker lacking the active Pairwise Transient Key (PTK), or Integrity Group Temporal Key (IGTK) is forced to send unprotected frames.
This creates a definitive, deterministic attack signature for detecting unicast Deauthentication attacks.

## The Deauthentication attack signature terms

A frame is classified as a forged unicast Deauthentication attack if and only if it satisfies four simultaneous conditions:

1. wlan.fc.type = 0 - This indicates that it is a Management frame.
2. wlan.fc.subtype = 12 - This specifies a Deauthentication frame (0x000c).
3. wlan.fc.protected = 0 - This field indicates an unprotected frame, arriving in a network where PMF is enabled.
4. wlan.da != ff:ff:ff:ff:ff:ff - Indicates an unicast destination address targeting a specific station, excluding broadcast frames.

These four-field terms represent reliable indicators focused on the potential Deauthentication unicast attack. 
It does not depend on the frame rate, traffic volume or sequence number anomalies. A single frame matching
all four conditions proves that an attack occurred, which means that a thousand matching frames represent the same attack repeated.

## Counting frames and episodes

To ensure accurate reporting, there are some frame counts and attack episodes conditions defined strictly by discrete categorical properties:

- Frame count - The total number of individual frames matching all four signature terms in the capture window.
- Episode count - The number of distinct (sender, recipient) MAC address pairs among the signature-matching frames.

Counting episodes by unique (sender, recipient) address pairs rather than time thresholds avoids any misunderstandings or mistakes.
For example, if an attacker floods Deauthentication frames spoofing the AP to the station (AP -> STA) and simultaneously floods frames spoofing
the station to the AP (STA -> AP), the frame count equals the total frames, while the episode count equals two (representing the two distinct directional pairs).

## The PMF line in the evidence card

The line "Network protects management frames (PMF)" tells whether the signature can be applied at all. 
It is determined for the whole capture, which contains a single network, and is checked in the order:

- "yes" - A Management frame of subtype 10, 12 or 13 (Disassociation, Deauthentication, SA Query action) has wlan.fc.protected = 1, or a Management frame of subtype 0, 2, 5 or 8 (Association Request, Reassociation Request, Probe Response, Beacon) carries wlan.rsn.capabilities.mfpc = 1. The network supports PMF and the signature applies: an unprotected unicast Deauthentication frame is forged.
- "NO - the network advertises no PMF support (MFPC = 0); the signature does not apply" - Frames of subtype 0, 2, 5 or 8 are present and all of them carry wlan.rsn.capabilities.mfpc = 0. Legitimate Deauthentication frames are unprotected in such network, so unprotected frames are not evidence of an attack.
- "UNDETERMINED - no protected Management frames and no frames advertising MFPC (subtype 0, 2, 5, 8); the signature cannot be applied" - The capture contains nothing that shows whether PMF is supported, which is possible in short capture slices. The signature cannot be confirmed, so without other evidence the verdict is "insufficient evidence".

Unprotected Management frames are never used as evidence that PMF is absent: under PMF, genuine broadcast frames protected by BIP and 
frames forged by the attacker also have wlan.fc.protected = 0.

## The n/a values in the evidence card

The value "n/a" in the evidence card means that a line needs a reference point that does not exist. 
SA Query frames, data frames and truncation are measured from signature-match frames; when the group has no signature-match frame 
(for example only protected Deauthentication frames from the real access point), these lines read "n/a". 
In the card of a clean capture with no Deauthentication or Disassociation frames, the time window, recipient, senders and 
reason codes also read "n/a", and all frame counts are 0. "n/a" is not a missing measurement and not evidence of an attack.

## What signature does not cover

To prevent false positive detections, five specific cases for frame categories are explicitly excluded from this signature:

- Protected Deauthentication frames (wlan.fc.protected = 1) - Genuine frames sent by the real AP or station. This kind of frames must never be reported as attacks, but have to be counted as the real PMF frame and traffic.
- Broadcast Deauthentication frames (wlan.da = ff:ff:ff:ff:ff:ff) - The broadcast Deauthentication attacks are out of scope for this analysis.
- Disassociation frames (wlan.fc.subtype = 10) - This is a different management frame subtype, and it is also out of scope.
- Networks lacking PMF - In traditional networks without 802.11w, legitimate Deauthentication frames have wlan.fc.protected = 0.
- Clients without PMF in a PMF-optional network - When PMF is configured as optional (capable, not required), a station that did not negotiate PMF during association keeps receiving legitimate Deauthentication frames with wlan.fc.protected = 0.

---
PROVENANCE: The attack signature methodology for PMF Deauthentication analysis. This is a methodological assumption 
based on 802.11w functioning against AWID3 dataset feature schemas and appearance. The evidence of protection and enhanced data methods are from 
"802.11w-2009 - IEEE Standard for Information technology - Telecommunications and information exchange between systems - Local and metropolitan area networks - Specific requirements. Part 11: Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications Amendment 4: Protected Management Frames" - section 5.4.3.4 Key management.
The PMF state is determined for the whole capture, assuming a single network (one BSSID). Frames of subtype 0 and 2 are sent by the client, 
frames of subtype 5 and 8 by the access point; probe requests (subtype 4) are not used.
AWID3 CSV files contain wlan.rsn.capabilities.mfpc but not mfpr, so required and optional PMF cannot be told apart.