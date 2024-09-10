import pytest
import os
import subprocess
import requests
import time


@pytest.fixture(scope="function")  # module?
def sandbox():
    port = 5555
    os.environ["PORT"] = str(port)
    a = subprocess.Popen(
        ["npm", "run", "start:prod"], cwd=os.environ.get("SANDBOX_DIR", ".")
    )
    url = f"http://localhost:{port}"

    # Wait until the frontend is ready
    for _ in range(10):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                break
        except requests.ConnectionError:
            pass
        time.sleep(1)  # Wait for 1 second before retrying
    else:
        raise requests.ConnectionError(f"Cannot connect to {url}")
    yield url
    a.kill()
