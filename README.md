# RDP Brute Force Detection using Splunk

## Overview
This project simulates a brute-force attack on a Windows system and detects it using Splunk SIEM.

## Objective
To identify high-frequency failed login attempts and detect brute-force attack behavior.

## Setup
- Attacker: Kali Linux (Hydra)
- Target: Windows System
- SIEM: Splunk

## Attack Simulation
A brute-force attack was performed using Hydra targeting RDP (Port 3389), generating multiple failed login attempts.

## Log Analysis
- Windows Event ID 4625 was used to identify failed login attempts
- Logs were forwarded to Splunk for analysis

## Detection Rule
```spl
index=* EventCode=4625 Logon_Type=3
| bucket _time span=1m
| stats count by _time, Source_Network_Address
| where count > 10
