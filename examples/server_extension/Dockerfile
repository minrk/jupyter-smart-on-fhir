FROM python:3.12

WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY fhir.py .

RUN pip install -e .
RUN jupyter server extension enable fhir
# Expose the default Jupyter port
EXPOSE 8888

# Set the entrypoint to run Jupyter server
ENTRYPOINT ["jupyter", "server", "--ip=0.0.0.0", "--allow-root", "--NotebookApp.token=''", "--NotebookApp.password=''"]
