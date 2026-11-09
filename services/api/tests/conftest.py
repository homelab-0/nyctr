import pytest
from fastapi.testclient import TestClient

from nyctr.config import Settings
from nyctr.main import create_app


@pytest.fixture
def app():
    return create_app(Settings(mode="demo", database_url="sqlite:///:memory:",
                               public_url="http://testserver", cookie_secure=False))


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def signin(client, member=False):
    response = client.post("/api/auth/login", json={"email": "jamie@nyctr.demo" if member else "admin@nyctr.demo",
                                                    "password": "nyctr-demo"})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


@pytest.fixture
def admin_headers(client):
    return signin(client)


@pytest.fixture
def member_headers(client):
    return signin(client, member=True)
