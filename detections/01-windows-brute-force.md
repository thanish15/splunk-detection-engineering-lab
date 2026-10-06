# Windows Brute Force Detection

## What it detects

This detection looks for repeated failed Windows logon attempts against the same user from the same IP address within a short period.

It is intended to identify possible brute force or password guessing activity.

## Event Used

- Windows Security Event ID: 4625
- Event: An account failed to log on

## Detection Logic

The query groups failed logons into 10-minute windows based on:

- Source IP address
- Target username

An alert is generated when there are 5 or more failed attempts in the same window.

The threshold is kept relatively low for this lab so the detection can identify the simulated activity in the dataset. In a production environment, the threshold would need to be tuned based on normal authentication behavior.

## SPL

```spl
index=winevtlog500 EventID=4625
| bin _time span=10m
| stats count as failed_attempts by _time, IpAddress, TargetUserName
| where failed_attempts >= 5
| sort - failed_attempts

Result Observed
The detection identified:
- Source IP: 10.20.30.40
- Target user: admin
- Failed attempts: 6
The result matched the failed logon activity present in the dataset.
Investigation
If this alert appeared in a real environment, I would check:
- Whether the source IP belongs to an expected internal system
- Whether the targeted account is privileged or a normal user
- Whether successful logons followed the failed attempts
- Other authentication activity from the same source IP
- Whether multiple accounts were targeted
- Whether the activity came from a known administrator, service, or application
False Positives and Tuning
Possible false positives include:
- A user repeatedly entering an incorrect password
- A service using an outdated password
- Misconfigured applications
- Administrative scripts or scheduled jobs
For a production environment, the threshold and time window should be adjusted based on the organization's normal authentication patterns.
