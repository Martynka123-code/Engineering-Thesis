# Handling capture truncation and evaluation thresholds

A network traffic capture file represents a finite time window of observed IEEE 802.11 traffic.
When evaluating the outcome of forged unicast Deauthentication attack, the position of the attack relative
to the capture boundaries determines whether a definitive verdict can be
reached or if the outcome must be reported as unknown due to capture truncation.

## Post-attack window definition and the 1.0 s boundary

The post-attack observation window is defined relative to the last forged Deauthentication frame of the group (bssid, client), 
taken across all attack episodes of that group. Episodes are counted by sender/recipient pairs and do not have separate time windows.

- Starting point - The post-attack window begins immediately after the timestamp of the last frame matching the signature (type 0, subtype 12,
  protected 0, unicast recipient). Its length is the post-attack gap: capture end timestamp minus that timestamp.
- Closed 1.0 s boundary (the threshold is an assumption of this work, not a value from the standard):
  - Sufficient window (gap >= 1.0 s) - Post-attack traffic can be evaluated. Data frames involving the client after the last forged frame are counted. If no SA Query exchange followed and the client falls silent, the attack probably succeeded.
  - Truncated window (gap < 1.0 s) - The capture ends too soon after the last forged frame. The count of Data frames is reported as UNKNOWN, never as 0, because the absence of traffic reflects the end of the file, not the behaviour of the network.

SA Query frames are counted from the FIRST forged frame, not from the last one, because the station challenges the first forged frame immediately. 
Their presence is evidence that the attack was blocked regardless of truncation. The outcome is therefore "unknown" only when the capture is truncated AND no SA Query exchange was observed.

## Capture truncation at the start of the file

If the capture file begins shortly before or during an attack sequence (first forged frame timestamp minus capture start timestamp < 1.0 s), 
pre-attack context, such as prior PMF negotiation or established session status may be missing from the recording window.

## Reading the TRUNCATION line in the evidence card

A "TRUNCATION:" line appears in the evidence card only when the capture is cut close to the attack. 
The distance is measured from the first and the last unprotected Deauthentication frame (wlan.fc.type = 0, wlan.fc.subtype = 12, wlan.fc.protected = 0, wlan.da != ff:ff:ff:ff:ff:ff) 
to the first and the last frame of the capture, with a threshold of 1.0 s:

- "TRUNCATION: the capture starts X s before the first signature-match frame" - fewer than 1.0 s of traffic was recorded before the attack, so pre-attack context such as earlier PMF evidence may be missing.
- "TRUNCATION: the capture ends X s after the last signature-match frame" - fewer than 1.0 s of traffic was recorded after the attack. The Data frame line then reads "UNKNOWN - the capture ends X s after the signature-match frame", and the outcome of the attack is unknown.

Truncation does not cancel the detection itself: the number of signature-matching frames and episodes stays valid, and a single matching frame still proves the attack. 
Only the outcome (successful or the attack was blocked) becomes uncertain. 
When no TRUNCATION line is present, the capture extends at least 1.0 s beyond the attack on both sides.

---
PROVENANCE: The 1.0 s truncation threshold, its closed boundary (< 1.0 s truncated, >= 1.0 s sufficient) and the way it is measured (capture start = earliest frame timestamp, capture end = latest frame timestamp, compared with the first and the last signature-match frame) are methodological assumptions of this project.
SA Query frames are counted from the first signature-match frame, Data frames from the last one. Time differences are compared with microsecond precision.