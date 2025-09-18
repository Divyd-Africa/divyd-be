import json
import requests
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from Divyd_be import settings

SERVICE_ACCOUNT_FILE = settings.SERVICE_FILE_PATH
SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
def get_access_token():
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    credentials.refresh(Request())
    return credentials.token


def stringify_data(data: dict) -> dict:
    """
    Recursively flattens and stringifies all values for FCM data payload.
    """
    flat = {}

    def _flatten(prefix, value):
        if isinstance(value, dict):
            for k, v in value.items():
                _flatten(f"{prefix}.{k}" if prefix else k, v)
        else:
            flat[prefix] = str(value)

    _flatten("", data)
    return flat

def send_fcm_v1_message(token, title, body, data=None):
    access_token = get_access_token()

    project_id = json.load(open(SERVICE_ACCOUNT_FILE))["project_id"]
    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json; UTF-8",
    }

    payload = {
        "message": {
            "token": token,
            "notification": {
                "title": title,
                "body": body,
            },
            "data": stringify_data(data or {}),
        }
    }

    response = requests.post(url, headers=headers, json=payload)
    # print(response.json())
    return response.json()

