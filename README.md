# Sentinel IR Automation — Azure SIEM Project

## Overview
An end-to-end automated incident response pipeline built on Microsoft Azure Sentinel. This project simulates real-world SOC operations by ingesting security logs, detecting threats using KQL analytics rules, and automatically responding to incidents via Logic App playbooks.

## Architecture
## Detection Rules
| Rule | Severity | Description |
|------|----------|-------------|
| Brute Force Detection | High | Detects 10+ failed logins from same IP within 10 minutes |
| Impossible Travel Detection | Medium | Detects logins from 2 different countries within 1 hour |
| Privilege Escalation Detection | High | Detects Global Administrator role assignment |

## Tech Stack
- Microsoft Azure Sentinel (SIEM)
- Azure Log Analytics Workspace
- Azure Logic Apps (Playbook automation)
- Python 3.11 (Log simulator)
- KQL (Kusto Query Language)
- Azure CLI

## Project Structure
## Results
- 40+ incidents automatically generated and triaged
- Logic App playbook triggered on every new incident
- Automated comments added to incidents for SOC analyst review

## Author
Nithin Jangu — MSc Computer Science (Cybersecurity), University of Roehampton  
[LinkedIn](https://linkedin.com/in/your-profile) | [GitHub](https://github.com/jangunithin26-coder)
