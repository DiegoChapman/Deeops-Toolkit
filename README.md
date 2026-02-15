# DeeOps Toolkit v1.3 (Simple Guide)

This project is a desktop cyber toolkit made in Python + Tkinter.
It is designed so you can run tools, save results, and manage plugins/users in one app.

## 1) Where your project is

Folder:
- `C:\Users\deech\OneDrive\Documents\Coding\CyberToolkit`

Main files:
- `my_cyber_toolkit_v1.py` -> main app
- `my_cyber_toolkit_v1_original.py` -> backup
- `README.md` -> this guide
- `build_exe.bat` -> build a Windows `.exe`

Data folders/files:
- `Vault\` -> protected file browser area
- `results\` -> tool run outputs (`.json` + `.txt`)
- `logs\` -> log folder
- `plugins\` -> plugin tool files
- `profiles.json` -> saved tool profiles
- `plugin_trust.json` -> plugin trust/blocked state
- `credentials.json` -> users + password hashes + roles
- `config.json` -> theme settings

## 2) Run the app

```powershell
python C:\Users\deech\OneDrive\Documents\Coding\CyberToolkit\my_cyber_toolkit_v1.py
```

If needed:

```powershell
py C:\Users\deech\OneDrive\Documents\Coding\CyberToolkit\my_cyber_toolkit_v1.py
```

## 3) Sidebar panels

- `Files` -> browse files inside Vault only
- `Network Tools` -> run tools (Ping/DNS/Traceroute/Port checks)
- `Results` -> dashboard + past run explorer + diff + HTML report
- `Plugins` -> trust/block/reload plugins
- `Logs` -> activity log and export
- `Settings` -> users, roles, password change, theme, self-test

## 4) Users and roles

The app now supports multiple users.

Roles:
- `admin` -> full control (add users, change roles, broader actions)
- `analyst` -> safer restrictions (public scan limits)

How to add a user:
1. Login as admin
2. Open `Settings`
3. In `Manage users`, enter username + password + role
4. Click `Add User`

How to change your password:
1. Open `Settings`
2. In `Change my password`, enter current + new password
3. Click `Update`

How to switch session role:
1. Open `Settings`
2. Choose role in `Session role`
3. Click `Apply Role`

## 5) Network tools + profiles

Basic use:
1. Open `Network Tools`
2. Pick a tool
3. Enter input values
4. Click `Run`

Quality-of-life features:
- `Favorite` button marks tools with `★` and moves them to top of tool list
- `Recent target` dropdown stores your last targets/domains (click `Use`)
- `Copy Output` copies tool output to clipboard
- `Clear Output` clears the output box
- Status now shows a mini badge (`READY/RUNNING/DONE/ERROR/CANCELED`) and run duration
- Tool help hint can be hidden/shown with `Hide Help` / `Show Help`
- Last selected tool + inputs auto-save and restore on next launch

Save profile:
1. Fill tool and inputs
2. Enter profile name
3. Click `Save Profile`

Run profile:
1. Pick profile from list
2. Click `Run Profile`

Delete profile:
1. Pick profile
2. Click `Delete`

## 6) Results dashboard and explorer

Open `Results` panel to get:
- summary cards (`Runs`, `Done`, `Errors`, `Top Tool`)
- filter by tool/status
- search text
- JSON viewer + text viewer

Extra actions:
- `Show Diff` -> compares selected result with previous same tool+target
- `Export HTML Report` -> creates a simple report file

## 7) Plugin manager

Open `Plugins` panel:
- `Reload Plugins`
- `Toggle Trust` (allow/block selected plugin)
- `Open Plugins Folder`

Plugin rule:
- plugin file must define `register_tools(ToolBase)`
- return one tool instance or a list of tool instances

## 8) Command palette (quick navigation)

Press:
- `Ctrl + K`
- `Ctrl + R` -> run selected network tool
- `Ctrl + L` -> clear tool output
- `Ctrl + Shift + C` -> copy tool output

Then use arrows + Enter to:
- jump panels
- run quick workflow helper
- open results folder

## 9) Self test

In `Settings`, click `Run Self Test`.
This runs quick internal checks and shows pass count in status/logs.

Also in `Settings`:
- `Reset to Default` resets theme colors/font
- `Reset UI Layout` resets tool view to default layout/state

## 10) First-time onboarding popup

On first successful login, a Quick Start popup appears automatically.

It gives simple next steps and buttons for:
- `Open Network Tools`
- `Open README`
- `Got It`

After you close it once, it will not show again unless `config.json` resets.

## 11) Build EXE (Windows)

Use:
- `build_exe.bat`

It runs PyInstaller and outputs:
- `dist\MyCyberToolkit_v1_3.exe`

## 12) Safety notes

- Use scanning tools only on targets you are authorized to test.
- Analyst role is intentionally more limited.
- Inputs and target checks are validated before tool execution.

## 13) Troubleshooting

If app does not open:
- run it from terminal and read error text

If plugins do not load:
- check `Plugins` panel status
- verify plugin trust is enabled
- run syntax check:

```powershell
python -m py_compile C:\Users\deech\OneDrive\Documents\Coding\CyberToolkit\plugins\your_plugin.py
```
