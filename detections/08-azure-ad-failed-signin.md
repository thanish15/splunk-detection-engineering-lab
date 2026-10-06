# Azure AD Suspicious Failed Sign-Ins

## What it detects

This detection looks for repeated Azure AD sign-in failures with the result code `50126`, which indicates an invalid username or password.

Repeated authentication failures from the same IP address can be a sign of password guessing or other suspicious authentication activity.

## Data Source

- Azure AD Sign-In Logs
- Category: `SignInLogs`
- Result Type: `50126`

## Detection Logic

The query groups failed sign-ins by source IP address and calculates:

- Number of failed sign-ins
- Number of unique users
- Users involved
- Risk level
- Risk state
- First and last attempt

The detection triggers when an IP address produces at least 5 failed sign-ins.

The threshold is intentionally simple for this lab and would need to be tuned for a production environment.

## SPL

```spl
index=winevtlog500 EventType="AZURE_AD" Category="SignInLogs" ResultType="50126"
| stats count as failed_signins dc(UserPrincipalName) as unique_users values(UserPrincipalName) as users values(RiskLevelDuringSignIn) as risk_levels values(RiskState) as risk_states min(_time) as first_attempt max(_time) as last_attempt by IPAddress
| eval window_seconds=last_attempt-first_attempt
| where failed_signins >= 5
| eval detection="Azure AD Suspicious Failed Sign-Ins"
| convert ctime(first_attempt) ctime(last_attempt)
| table IPAddress, failed_signins, unique_users, users, risk_levels, risk_states, first_attempt, last_attempt, window_seconds, detection
| sort - failed_signins

Result Observed
The detection identified:
- Source IP: 198.51.100.200
- Failed sign-ins: 8
- Unique users: 1
- User: alice@corp.example
- Risk level: Medium
- Risk state: AtRisk
- Time window: approximately 14 minutes
Because the activity in this dataset targeted only one user, I would describe it as repeated suspicious failed authentication rather than confirmed password spraying.
If multiple user accounts were targeted from the same IP, confidence in a password spraying pattern would be higher.
Investigation
If this alert appeared in a real environment, I would check:
- Whether the source IP is known or expected
- Which accounts were targeted
- Whether any successful sign-in followed the failures
- Risk level and risk state for the accounts
- MFA activity around the same time
- Other sign-in activity from the same IP
- Whether the affected account showed any other suspicious activity
False Positives and Tuning
Possible false positives include:
- Users repeatedly entering an incorrect password
- Applications using an outdated password
- Automated authentication attempts from misconfigured systems
- Legitimate testing activity
For production use, the threshold should be based on normal authentication behavior. A rule that requires multiple targeted users could also be used when specifically looking for password spraying.
This detection identifies suspicious authentication activity and does not by itself confirm a compromised account.
