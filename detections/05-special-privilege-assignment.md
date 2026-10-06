# Suspicious Special Privilege Assignment

## What it detects

This detection looks for Windows logon events where the `SeDebugPrivilege` privilege is assigned to an account.

`SeDebugPrivilege` is a powerful Windows privilege that can allow a process to interact with processes owned by other users. Unexpected assignment of this privilege can therefore be worth investigating.

## Event Used

- Windows Security Event ID 4672 — Special privileges assigned to new logon

## Detection Logic

The query searches Event ID 4672 for `SeDebugPrivilege` in the `PrivilegeList` field.

I used the privilege itself as the detection condition because the dataset did not provide enough reliable information to correlate the 4672 event with a specific process creation event.

## SPL

```spl
index=winevtlog500 EventID=4672
| where match(PrivilegeList, "(?i)SeDebugPrivilege")
| stats count as privilege_events values(PrivilegeList) as privileges by SubjectUserName, SubjectDomainName
| eval detection="Suspicious Special Privilege Assignment"
| table SubjectUserName, SubjectDomainName, privilege_events, privileges, detection
| sort - privilege_events

Result Observed
The detection identified one event involving:
- User: DC01$
- Domain: CORP
- Privilege: SeDebugPrivilege
The event also contained other Windows special privileges.
Investigation
If this alert appeared in a real environment, I would check:
- Which account received the privilege
- Whether the account is a machine account, service account, or user account
- Whether the privilege assignment is expected
- The logon activity associated with the account
- Process creation activity around the same time
- Whether there were other suspicious actions from the same host
False Positives and Tuning
Event ID 4672 can occur during legitimate administrative or system activity.
Possible false positives include:
- Domain controllers
- System accounts
- Administrative accounts
- Legitimate security or management software
The account type and surrounding activity should be considered before treating the event as suspicious.
This detection is an indicator for investigation, not proof of malicious privilege escalation.
