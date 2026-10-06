# Suspicious Remote Logon Detection

## What it detects

This detection looks for multiple remote interactive logons from the same IP address targeting different user accounts within a short period.

A pattern like this can indicate suspicious remote access or lateral movement.

## Event Used

- Windows Security Event ID: 4624
- Logon Type: 10
- Logon Type 10 represents a RemoteInteractive logon, commonly associated with Remote Desktop Protocol (RDP).

## Detection Logic

The query groups successful remote logons by source IP address.

It triggers when:

- At least 2 remote logons occur
- At least 2 different user accounts are involved
- The logons occur within 10 minutes

Using multiple accounts helps reduce alerts caused by a normal user reconnecting to a remote system.

## SPL

```spl
index=winevtlog500 EventID=4624 LogonType=10
| stats count as remote_logons dc(TargetUserName) as unique_users values(TargetUserName) as users min(_time) as first_logon max(_time) as last_logon by IpAddress
| eval window_seconds=last_logon-first_logon
| where remote_logons >= 2 AND unique_users >= 2 AND window_seconds <= 600
| convert ctime(first_logon) ctime(last_logon)
| table IpAddress, remote_logons, unique_users, users, first_logon, last_logon, window_seconds
| sort - remote_logons

Result Observed
The detection identified two source IPs:
- 10.20.30.41 — accounts david and admin
- 192.168.2.101 — accounts alice and charlie
The logons occurred within the configured 10-minute window.
Investigation
If this alert appeared in a real environment, I would check:
- Whether the source IP belongs to an expected workstation or administrator system
- Which destination systems were accessed
- Whether the accounts normally use RDP
- Whether the accounts are privileged
- Other activity from the source IP around the same time
- Whether successful remote logons were preceded by failed logons
- Whether the activity is consistent with normal administrative behavior
False Positives and Tuning
Possible false positives include:
- System administrators connecting to multiple machines
- Help-desk activity
- Remote support sessions
- Shared administrative workstations
The threshold and time window should be adjusted based on normal RDP usage in the environment
