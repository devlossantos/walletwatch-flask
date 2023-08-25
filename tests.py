import pytest
from flask import session
from walletwatch import app, get_balance, get_expenses
from walletwatch import bcrypt
from unittest.mock import patch


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "cct"
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["token"] = "test_token"
        yield client


@pytest.fixture
def mock_execute_query():
    with patch("walletwatch.execute_query") as mock_execute_query:
        yield mock_execute_query


def test_home_route_authenticated(client):
    response = client.get("/")
    assert response.status_code == 200


def test_home_route_unauthenticated(client):
    with client.session_transaction() as session:
        session.clear()

    response = client.get("/")
    assert response.status_code == 302
    assert response.location == "/login"


def test_signup_route_post(client):
    with patch("walletwatch.bcrypt.hashpw") as mock_hashpw, patch(
        "walletwatch.bcrypt.gensalt"
    ) as mock_gensalt, patch("walletwatch.execute_query") as mock_execute_query:
        mock_hashpw.return_value = b"hashed_password"
        mock_gensalt.return_value = b"salt"

        response = client.post(
            "/signup",
            data={"user_email": "test@example.com", "user_password": "testpassword"},
        )

        assert response.status_code == 200
        assert b"User registered successfully" in response.data

        encoded_hashed_password = "hashed_password".encode("utf-8")

        mock_hashpw.assert_called_once_with(b"testpassword", b"salt")

        expected_query = "INSERT INTO users (user_email, user_password) VALUES (%s, %s)"
        expected_args = ("test@example.com", encoded_hashed_password)
        mock_execute_query.assert_called_once_with(
            expected_query, expected_args, commit=True
        )


def test_get_balance_successful(mock_execute_query):
    mock_execute_query.return_value = [(150.0,)]

    balance = get_balance(123)

    assert balance == 150.0


def test_current_expenses_route(mock_execute_query):
    mock_execute_query.return_value = [(150.0,)]

    expenses = get_expenses(150.0)

    assert expenses == 150.0
