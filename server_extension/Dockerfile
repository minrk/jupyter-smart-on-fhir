FROM python:3.12

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY main.py .

# Generate RSA key pair
RUN openssl genrsa -out jwtRS256.key 2048 && \
    openssl rsa -in jwtRS256.key -pubout -out jwtRS256.key.pub

RUN jupyter server extension enable server_extension.main
# Expose the default Jupyter port
EXPOSE 8888

# Set the entrypoint to run Jupyter server
ENTRYPOINT ["jupyter", "server", "--ip=0.0.0.0", "--allow-root", "--NotebookApp.token=''", "--NotebookApp.password=''"]
