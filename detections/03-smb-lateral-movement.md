# Suspicious ADMIN$ Network Share Access

## What it detects

This detection looks for access to the Windows `ADMIN$` administrative network share.

ADMIN$ is a built-in Windows administrative share that can be used by administrators and remote management tools. Unexpected access can also be associated with lateral movement.

## Events Used

- Windows Security Event ID 5140 — A network share object was accessed
- Windows Security Event ID 5145 — A network share object was checked to see whether client access was granted

## Detection Logic

The query looks specifically for access to:

`\\*\ADMIN$`

It then groups the activity by source IP and username and shows the accessed target paths.

The detection is based on the actual share name and event fields rather than the scenario label in the dataset.

## SPL

```spl
index=winevtlog500 (EventID=5140 OR EventID=5145) ShareName="\\*\ADMIN$"
| stats count as share_accesses values(EventID) as EventIDs values(RelativeTargetName) as targets values(ShareName) as shares by IpAddress, SubjectUserName
| eval detection="Suspicious ADMIN$ Network Share Access"
| table IpAddress, SubjectUserName, share_accesses, EventIDs, shares, targets, detection
| sort - share_accesses

Result Observed
The detection identified ADMIN$ activity from:
- 10.20.30.40 using admin — 2 accesses
- 10.20.30.41 using admin — 1 access
The events included access to:
Windows\Temp\lab.txt
Investigation
If this alert appeared in a real environment, I would check:
- Whether the source system is an authorized administrative workstation
- Whether the account normally performs remote administration
- Which files or paths were accessed
- Whether there were other SMB connections around the same time
- Whether remote logons occurred from the same source
- Whether processes such as PsExec or other remote administration tools were involved
False Positives and Tuning
Possible false positives include:
- Legitimate Windows administration
- Software deployment tools
- Backup systems
- Remote management tools
ADMIN$ access by itself does not confirm malicious activity. The source system, account, timing, and surrounding events should be considered before treating it as suspicious.
