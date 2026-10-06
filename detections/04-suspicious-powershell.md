# Suspicious PowerShell Activity

## What it detects

This detection looks for PowerShell script blocks containing commands that can be useful during system discovery or security-related investigation.

The commands checked in this lab are:

- `Get-Process lsass`
- `Get-ScheduledTask`
- `Get-LocalUser`

These commands are not malicious by themselves. They become more interesting when they appear unexpectedly or as part of a larger sequence of activity.

## Event Used

- Windows PowerShell Script Block Logging — Event ID 4104

## Detection Logic

The query searches the `ScriptBlockText` field for the selected commands and groups the results by the account that executed them.

I chose Event ID 4104 because it provides the actual PowerShell script content rather than only showing that PowerShell was started.

## SPL

```spl
index=winevtlog500 EventID=4104
| where match(ScriptBlockText, "(?i)Get-Process\s+lsass|Get-ScheduledTask|Get-LocalUser")
| stats count as suspicious_commands values(ScriptBlockText) as commands values(Path) as script_paths by AccountName
| eval detection="Suspicious PowerShell Activity"
| table AccountName, suspicious_commands, commands, script_paths, detection
| sort - suspicious_commands

Result Observed
The detection identified five events:
- admin — Get-ScheduledTask
- alice — Get-LocalUser
- bob — Get-Process lsass
- charlie — Get-ScheduledTask
- eve — Get-Process lsass
The script path associated with the events was:
C:\Users\Public\script.ps1
I also checked PowerShell process creation events in the dataset. There were PowerShell process creation events involving wsmprovhost.exe, but I kept the final detection focused on the 4104 script-block telemetry because it provided the actual commands being executed.
Investigation
If this alert appeared in a real environment, I would check:
- Which user executed the command
- The PowerShell script path and contents
- Whether PowerShell was started interactively or remotely
- The parent process
- Other commands executed by the same account
- Whether the account normally performs administrative tasks
- Other authentication or process activity around the same time
False Positives and Tuning
Possible false positives include:
- System administrators performing routine checks
- Security tools and monitoring scripts
- IT automation
- Troubleshooting activity
The command list should be expanded or tuned based on the organization's normal PowerShell usage.
The detection should not treat these commands as automatically malicious. They are indicators that may require investigation when they occur unexpectedly.
