# Yara Whitelist Rule Creator

## Requirements
### Other repositories
- TheOracle (YARA rules git repository)
- yara-designer-responder (Cortex responder)
- yara-designer-web (Web GUI, frontend)

#### Setup
1. Upload the `responder/` directory as `/opt/Cortex-Analyzers/responders/` on the remote host.
2. Restart cortex and thehive.
3. Enable the responder in cortex.

#### Usage
1. Start the listener.
2. Use the responder on a case.

## Workflow
![responder-workflow](docs/assets/responder_workflow_diagram.png)


## YARA Rule Designer

## Workflow
