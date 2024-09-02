FROM python:3.12

WORKDIR /app
COPY pyproject.toml examples/server_extension/config.py ./
COPY jupyter_smart_on_fhir/ ./jupyter_smart_on_fhir/
RUN pip install --no-cache-dir .
# Expose the default Jupyter port
EXPOSE 8888

# Set the entrypoint to run Jupyter server
ENTRYPOINT ["jupyter", "server", "--config", "config.py"]
