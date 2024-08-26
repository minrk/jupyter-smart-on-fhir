# SMART App demo with Jupyter

This is a Jupyter server extension that fetches data from a SMART on FHIR endpoint. 

# Installation

## Local Installation with pip

1. Clone the repository:
   ```
   git clone https://github.com/jupyterhealth/smart-fhir-jupyter-demo.git
   cd smart-fhir-jupyter-demo/server_extension
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

4. Install the Jupyter server extension:
   ```
   pip install -e .
   ```

5. Generate a public/private key pair
   ```
   openssl genrsa -out jwtRS256.key 2048
   openssl rsa -in jwtRS256.key -pubout -out jwtRS256.key.pub
   ```

## Installation with Docker

1. Clone the repository:
   ```
   git clone https://github.com/jupyterhealth/smart-fhir-jupyter-demo.git
   cd smart-fhir-jupyter-demo/server_extension
   ```

2. Build the Docker image:
   ```
   docker build -t smart-server-extension .
   ```

# Running the Application

## Running Locally

1. Ensure you're in the project directory and your virtual environment is activated.

2. Start the Jupyter server:
   ```
   jupyter server --ip=0.0.0.0 --allow-root --NotebookApp.token='' --NotebookApp.password=''
   ```

3. Open a web browser and navigate to `http://localhost:8888` to access the Jupyter interface.

## Running with Docker

1. Run the Docker container:
   ```
   docker run -p 8888:8888 smart-server-extension
   ```

2. Open a web browser and navigate to `http://localhost:8888` to access the Jupyter interface.

# Testing with a SMART app

1. Use the sandbox (either [locally]() or [online]()) and point it towards
   ```
   http://localhost:8888/extension/smart
   ```




