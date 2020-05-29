# YARA-Designer Core (backend)

## Dependencies
### Git repository
The following Git repository must be set up and available.
- TheOracle (YARA rules git repository)
### Projects
The following projects must be running and available over network.
- yara-designer-responder (Cortex responder)
- yara-designer-web (Web GUI, frontend)

#### Setup
1. Copy `config.json.sample` to `config.json` and configure it.
2. Make sure Cortex is set up with `yara-designer-responder` and is available over network.

#### Usage
1. Start the YARA-Designer core/backend by running `main.py`.
2. Use the responder on a case in TheHive which will populate core database.

## Workflow
![responder-workflow](docs/assets/responder_workflow_diagram.png)

