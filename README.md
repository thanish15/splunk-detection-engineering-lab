# Splunk Detection Engineering Lab

This is a hands-on Splunk project where I built and tested security detections using a synthetic Windows and Azure AD dataset.

I worked through each detection by first looking at the available events and fields, then writing and testing the SPL, checking the results, and finally creating a Splunk alert.

The main goal of this project was to get practical experience with detection logic and understand how a SOC analyst would investigate different types of suspicious activity.

## Tools and Technologies

- Splunk Enterprise
- SPL (Search Processing Language) 
- Windows Security Event Logs
- Sysmon
- PowerShell Script Block Logging
- Azure AD Sign-In Logs
- MITRE ATT&CK

## Detections

| # | Detection | Data Source |
|---|---|---|
| 1 | Windows Brute Force | Windows Event ID 4625 |
| 2 | Suspicious Remote Logon | Windows Event ID 4624 |
| 3 | Suspicious ADMIN$ Network Share Access | Windows Event ID 5140 / 5145 |
| 4 | Suspicious PowerShell Activity | Windows Event ID 4104 |
| 5 | Suspicious Special Privilege Assignment | Windows Event ID 4672 |
| 6 | Suspicious Scheduled Task Persistence | Windows Event ID 4702 |
| 7 | Suspicious LSASS Process Access | Sysmon Event ID 10 |
| 8 | Azure AD Suspicious Failed Sign-Ins | Azure AD Sign-In Logs |

## How I Built the Detections

For each detection, I followed a simple process:

1. Identify the relevant event type.
2. Check which fields are available in the data.
3. Look at the actual events in Splunk.
4. Build the detection query.
5. Test the query against the dataset.
6. Check whether the results match the expected behavior.
7. Create a scheduled alert after validating the query.

I avoided using the scenario labels included in the dataset as detection conditions. The detections are based on the actual event fields and observed behavior.

## Dataset

The project uses a synthetic dataset containing 500 Windows and Azure AD security events.

The dataset includes examples of:

- Failed Windows logons
- Remote logons
- SMB network share access
- PowerShell activity
- Special privilege assignments
- Scheduled task activity
- LSASS process access
- Azure AD sign-in failures

The raw dataset is not included in this repository.

## Alert Configuration

After validating each detection, I created a scheduled Splunk alert.

The alerts use:

- Scheduled execution
- Result-based triggering
- Triggered Alerts
- Medium severity
- 600-second throttling

## Project Structure

```text
splunk-detection-engineering-lab/
│
├── README.md
│
├── detections/
│   ├── 01-windows-brute-force.md
│   ├── 02-suspicious-remote-logon.md
│   ├── 03-smb-lateral-movement.md
│   ├── 04-suspicious-powershell.md
│   ├── 05-special-privilege-assignment.md
│   ├── 06-scheduled-task-persistence.md
│   ├── 07-lsass-access.md
│   └── 08-azure-ad-failed-signin.md
│
├── spl/
│   ├── 01-windows-brute-force.spl
│   ├── 02-suspicious-remote-logon.spl
│   ├── 03-smb-lateral-movement.spl
│   ├── 04-suspicious-powershell.spl
│   ├── 05-special-privilege-assignment.spl
│   ├── 06-scheduled-task-persistence.spl
│   ├── 07-lsass-access.spl
│   └── 08-azure-ad-failed-signin.spl
│
├── screenshots/
│
└── docs/
    ├── detection-matrix.md
    └── false-positive-tuning.md
