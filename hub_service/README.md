# SMART on FHIR JupyterHub Service

This project contains a demo of a JupyterHub service that acts as a confidential client for a SMART on FHIR server and authenticates asymmetrically.

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/jupyterhealth/smart-fhir-jupyter-demo.git
   cd smart-fhir-jupyter-demo/hub_service
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate 
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Connect to the SMART sandbox (either [locally](https://github.com/smart-on-fhir/smart-launcher-v2/) or [online](https://launch.smarthealthit.org/))

4. Run `jupyter` and go to `localhost:8000` to test the authentication flow, and/or

4. Use the sandbox and point it towards
   ```
   http://localhost:8000/services/fhir
   ```

## Configuration

1. Update the `jupyterhub_config.py` file with your SMART on FHIR server details:
   - Set the `fhir_base_url` to the sandbox server's URL

2. As a confidential client, this needs a public/private key pair. For demo purposes, the script takes care of generating this keypair.

## Usage

Once authenticated, users can make requests to the FHIR server through the service. The service handles token management and SMART on FHIR authentication flow.

Example:
- Accessing `http://localhost:8000/hub/fhir` will fetch Condition resources from the FHIR server.