# Suspicious Scheduled Task Persistence

## What it detects

This detection looks for scheduled task modifications where a task under the `Updater` path is configured to execute PowerShell.

Scheduled tasks can be used for legitimate automation, but unexpected task modifications can also provide a way to maintain persistence on a Windows system.

## Event Used

- Windows Security Event ID 4702 — A scheduled task was updated

## Detection Logic

The query looks for:

- Event ID 4702
- A task name beginning with `\Updater\`
- `powershell.exe` in the task action

The combination makes the detection more specific than alerting on every scheduled task modification.

## SPL

```spl
index=winevtlog500 EventID=4702
| where match(TaskName, "(?i)^\\\\Updater\\\\") AND match(TaskContent, "(?i)powershell\.exe")
| stats count as task_updates values(TaskName) as task_names values(TaskContent) as task_actions values(UserName) as users by Author
| eval detection="Suspicious Scheduled Task Persistence"
| table Author, users, task_updates, task_names, task_actions, detection
| sort - task_updates

Result Observed
The detection identified two scheduled task updates:
- \Updater\SystemUpdate5
- \Updater\SystemUpdate6
Both tasks were associated with the CORP\admin account and contained powershell.exe in their actions.
Investigation
If this alert appeared in a real environment, I would check:
- Who modified the scheduled task
- Whether the task was expected
- The full task action and PowerShell command
- When the task was created or modified
- Whether the task runs as a privileged account
- Other process creation and authentication activity from the same host
- Whether the task name and location match approved administrative software
False Positives and Tuning
Possible false positives include:
- Software update mechanisms
- IT automation
- Monitoring tools
- Legitimate administrative scripts
The task name alone should not be treated as malicious. The command, account, host, and timing should be reviewed together.
In a production environment, approved task paths and known software update mechanisms could be added as exclusions.
