# YARA-Designer Core (backend)

## Dependencies
### Git repository
The following Git repository must be set up and available.
- TheOracle (YARA rules git repository)
### Projects
The following projects must be running and available over network.
- yara-designer-responder (Cortex responder)
- yara-designer-web (Web GUI, frontend)

## Setup
1. Set up an environment using [Pipenv](https://pipenv.pypa.io/en/latest/) (recommended) or [Virtualenv](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/):
    - Pipenv:
        ```console
        # Install environment.
        $ pipenv install
        # Install and update dependencies.
        $ pipenv update
        ```
    - Virtualenv
        ```console
        # Install environment.
        $ python3 -m venv env
        # Enable environment.
        $ source env/bin/activate
        # Install dependencies.
        $ pip install -r requirements.txt
        ```
2. Copy `config.json.sample` to `config.json` and configure it.
3. Make sure Cortex is set up with `yara-designer-responder` and is available over network.

## Usage
1. Start the YARA-Designer core/backend by running `main.py`.
2. Use the responder on a case in TheHive which will populate core database.

## Workflow
![responder-workflow](docs/assets/responder_workflow_diagram.png)

