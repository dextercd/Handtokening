import base64
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from handtokening.clients.models import Client, ClientSecret


User = get_user_model()


def basic_auth(user, pwd):
    return "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()


class MiddlewareTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create(username="signer")
        cls.sign_client = Client.objects.create(
            user=cls.user, default_secret_duration=timedelta(days=1)
        )

    def test_client_doesnt_exist(self):
        response = self.client.get(
            "/",
            headers={
                "authorization": basic_auth(
                    "notexist", "htkey,_L5t_hyeNjvHkiNkRudUfDhVYy0"
                )
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_wrong_password(self):
        response = self.client.get(
            "/",
            headers={
                "authorization": basic_auth(
                    "signer", "htkey,_L5t_hyeNjvHkiNkRudUfDhVYy0"
                )
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_right_password(self):
        self.sign_client.set_new_secret()
        secret = self.sign_client.new_secret
        self.sign_client.save()

        response = self.client.get(
            "/",
            headers={"authorization": basic_auth("signer", secret)},
        )

        # Authentication successful, but no matching route so we expect 404
        self.assertEqual(response.status_code, 404)

    def test_secret_expiry(self):
        self.sign_client.set_new_secret()
        secret = self.sign_client.new_secret

        ClientSecret.objects.update(valid_until=timezone.now())

        response = self.client.get(
            "/",
            headers={"authorization": basic_auth("signer", secret)},
        )
        self.assertEqual(response.status_code, 403)
