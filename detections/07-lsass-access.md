# Suspicious LSASS Process Access

## What it detects

This detection looks for processes accessing the Windows Local Security Authority Subsystem Service (`lsass.exe`).

LSASS handles sensitive authentication information, so unexpected process access to it can be an indicator of credential access activity.

## Event Used

- Sysmon Event ID 10 — Process Access

## Detection Logic

The query filters Sysmon Event ID 10 events where the target process is `lsass.exe`.

It then shows:

- The process accessing LSASS
- The user associated with the source process
- The requested access mask
- The number of LSASS access events

The detection is intended to identify activity that should be investigated rather than automatically treating every LSASS access as malicious.

## SPL

```spl
index=winevtlog500 EventID=10
| where match(TargetImage, "(?i)\\\\lsass\.exe$")
| stats count as lsass_accesses values(SourceImage) as source_images values(GrantedAccess) as access_masks values(SourceUser) as source_users by TargetImage
| eval detection="Suspicious LSASS Process Access"
| table TargetImage, source_users, source_images, access_masks, lsass_accesses, detection
| sort - lsass_accesses

Result Observed
The detection identified LSASS process access involving:
- Target: C:\Windows\System32\lsass.exe
- Source process: C:\Tools\diagtool.exe
- Source user: CORP\admin
- Granted access: 0x1010
- LSASS access events: 2
The source process and account would require investigation to determine whether the access was legitimate.
Investigation
If this alert appeared in a real environment, I would check:
- Whether the source process is an approved security or diagnostic tool
- The file path and hash of the source executable
- Which user launched the process
- The parent process that started it
- Other processes executed by the same account
- Authentication activity around the same time
- Whether there were signs of credential dumping or other credential access activity
False Positives and Tuning
Legitimate security, diagnostic, monitoring, and endpoint management software may access LSASS.
Possible false positives include:
- Antivirus or EDR software
- Diagnostic tools
- System administration utilities
- Security monitoring software
The source process, user, path, signature, and surrounding activity should be reviewed before treating the event as malicious.
