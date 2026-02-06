# Windows IR Containment Script (Host-Level)

## Overview

This PowerShell script performs **host-level incident response containment** for a specified user account. It is intended to be run locally during an active security investigation to quickly reduce attacker access while maintaining a clear audit trail.

The script focuses on **identity containment, session control, and process termination** on the local machine only. Good to pair with EDR for host quarantine action.

---

## What This Script Does

Given a target username, the script can:

- Disable the Active Directory account (if the AD module is available)
- Reset the user’s password using a high-entropy random value
- Enumerate and terminate active logon sessions (RDP / console)
- Enumerate and terminate processes owned by the target user
- Purge cached Kerberos tickets on the local host
- Optionally reboot the system
- Log all actions and outcomes for review

Each step is executed independently with error handling so that failures do not halt the entire workflow.

---

## Scope and Limitations

- **Local host only** (no remote execution)
- **No domain-wide cleanup**
- Kerberos ticket purging applies only to the local machine

---

## Requirements

- Administrative privileges
- PowerShell 5.1 or later
- Active Directory PowerShell module (for AD actions, attempted import in script)

---

## Usage

- Outlined in top level comments of script

## Logging and Output

Logs are written to C:\IR\ with timestamped filenames

A structured summary is displayed at the end of execution

Results are exported to ir_results.csv for reporting or review

## Safety Notes

Passwords are never displayed, logged, or stored (created and ran in memoru)

High-impact actions require explicit confirmation unless -Force is used

Use -WhatIfMode to validate behavior before live containment
