import os
import subprocess
from urllib.parse import urlencode, unquote
import requests
import pytest
from conftest import wait_for_server, SandboxConfig
from jupyter_smart_on_fhir.server_extension import smart_path, login_path, callback_path

PORT = os.getenv("TEST_PORT", 18888)
ext_url = f"http://localhost:{PORT}"


def request_api(url, session=None, params=None, **kwargs):
    query_args = {"token": "secret"}
    query_args.update(params or {})
    session = session or requests.Session()
    return session.get(url, params=query_args, **kwargs)


@pytest.fixture
def jupyterdir(tmpdir):
    path = tmpdir.join("jupyter")
    path.mkdir()
    return str(path)


@pytest.fixture
def jupyter_server(tmpdir, jupyterdir):
    client_id = os.environ["CLIENT_ID"] = "client_id"
    env = os.environ.copy()
    # avoid interacting with user configuration, state
    env["JUPYTER_CONFIG_DIR"] = str(tmpdir / "dotjupyter")
    env["JUPYTER_RUNTIME_DIR"] = str(tmpdir / "runjupyter")

    extension_command = ["jupyter", "server", "extension"]
    command = [
        "jupyter-server",
        "--ServerApp.token=secret",
        "--SMARTExtensionApp.client_id={}".format(client_id),
        "--port={}".format(PORT),
    ]
    subprocess.check_call(
        extension_command + ["enable", "jupyter_smart_on_fhir.server_extension"],
        env=env,
    )

    # launch the server
    with subprocess.Popen(command, cwd=jupyterdir, env=env) as jupyter_proc:
        wait_for_server(ext_url)
        yield jupyter_proc
        jupyter_proc.terminate()


def test_uninformed_endpoint(jupyter_server):
    response = request_api(ext_url + smart_path)
    assert response.status_code == 400


@pytest.fixture(scope="function")
def public_client():
    return SandboxConfig(
        client_id=os.environ["CLIENT_ID"],
        client_type=0,
        pkce_validation=2,
        # setting IDs so we omit login screen in sandbox; unsure I would test that flow
        patient_ids=["6bb97c2b-8762-4763-ad16-2d88db590b74"],
        provider_ids=["63003abb-3924-46df-a75a-0a1f42733189"],
    )


def test_login_handler(jupyter_server, sandbox, public_client):
    session = requests.Session()
    # Try endpoint and get redirected to login
    query = {"iss": f"{sandbox}/v/r4/fhir", "launch": public_client.get_launch_code()}
    response = request_api(
        ext_url + smart_path, params=query, allow_redirects=False, session=session
    )
    assert response.status_code == 302
    assert response.headers["Location"] == login_path

    # Login with headers and get redirected to auth url
    response = request_api(ext_url + login_path, session=session, allow_redirects=False)
    assert response.status_code == 302
    auth_url = response.headers["Location"]
    assert auth_url.startswith(sandbox)

    # Internally, get redirected to provider-auth
    response = request_api(auth_url, session=session, allow_redirects=False)
    assert response.status_code == 302
    auth_url = response.headers["Location"]
    callback_url = response.headers["Location"]
    assert callback_url.startswith(ext_url + callback_path)
    assert "code=" in callback_url
    response = request_api(callback_url, session=session)
    assert response.status_code == 200
    assert response.url.startswith(ext_url + smart_path)

    # TODO: Should I test token existence? And how?
