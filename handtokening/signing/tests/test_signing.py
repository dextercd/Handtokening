import base64
from unittest.mock import patch
import tempfile
import shutil
from pathlib import Path
from urllib.parse import urlencode
import os
import importlib.metadata
import hashlib

from django.test import TestCase
from django.core.management import call_command

from handtokening.signing.conf import config
from handtokening.clients.models import Client
from handtokening.signing.models import SigningLog
from handtokening.signing.apps import set_up_directories


def basic_auth(user, pwd):
    return "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()


TEST_SCRIPT = """
Write-Host "Hello, world!"
"""
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class SigningTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.run_dir = Path(tempfile.mkdtemp())
        cls.addClassCleanup(lambda: shutil.rmtree(cls.run_dir))
        os.chmod(cls.run_dir, 0o755)  # ClamAV needs to be able to access this

        dirs = ["PIN_COMMS_LOCATION", "STATE_DIRECTORY", "TEST_CERTIFICATE_DIRECTORY"]
        for dir in dirs:
            patcher = patch.object(config, dir, cls.run_dir)
            patcher.start()
            cls.addClassCleanup(patcher.stop)

        set_up_directories()

        call_command("set_up_test_signing")

        cls.sign_client = Client.objects.first()
        cls.sign_client.set_new_secret()
        cls.sign_client.save()
        cls.auth = basic_auth("test", cls.sign_client.new_secret)
        cls.headers = {
            "authorization": cls.auth,
            "content-disposition": 'attachment; filename="test.ps1"',
            "user-agent": "HT Test Agent",
        }

    def setUp(self):
        clear_dirs = ["in", "out"]
        for dir in clear_dirs:
            for f in (self.run_dir / dir).glob("*"):
                f.unlink()

    def test_without_signing_profile(self):
        resp = self.client.post(
            "/api/sign",
            TEST_SCRIPT,
            content_type="application/octet-stream",
            headers=self.headers,
        )

        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["signing-profile"], ["This field is required."])

    def test_non_existent_signing_profile(self):
        resp = self.client.post(
            "/api/sign?" + urlencode({"signing-profile": "bloop-signing"}),
            TEST_SCRIPT,
            content_type="application/octet-stream",
            headers=self.headers,
        )

        self.assertEqual(resp.status_code, 404)
        self.assertEqual(
            resp.json().get("detail"), "No SigningProfile matches the given query."
        )

    def test_signing(self):
        resp = self.client.post(
            "/api/sign?" + urlencode({"signing-profile": "test-signing"}),
            TEST_SCRIPT,
            content_type="application/octet-stream",
            headers=self.headers,
        )

        self.assertEqual(resp.status_code, 200)

        response_file = b"".join(resp.streaming_content).decode()
        self.assertTrue(response_file.startswith(TEST_SCRIPT))
        self.assertTrue("# SIG # Begin signature block" in response_file)
        self.assertTrue("# SIG # End signature block" in response_file)

    def test_eicars(self):
        resp = self.client.post(
            "/api/sign?" + urlencode({"signing-profile": "test-signing"}),
            EICAR,
            content_type="application/octet-stream",
            headers=self.headers,
        )

        self.assertEqual(resp.status_code, 400)
        self.assertTrue("Win.Test.EICAR_HDB-1 FOUND" in resp.json().get("detail"))

        log = SigningLog.objects.first()
        assert log.result == SigningLog.Result.AV_POSITIVE

    def test_bad_extension(self):
        resp = self.client.post(
            "/api/sign?" + urlencode({"signing-profile": "test-signing"}),
            TEST_SCRIPT,
            content_type="application/octet-stream",
            headers={
                **self.headers,
                "content-disposition": 'attachment; filename="TEST.FZO"',
            },
        )

        self.assertEqual(resp.status_code, 400)
        self.assertTrue(
            "Unsupported file extension: 'fzo'" in resp.json().get("detail")
        )

    def test_success_log(self):
        resp = self.client.post(
            "/api/sign?"
            + urlencode(
                {
                    "signing-profile": "test-signing",
                    "description": "Test PowerShell",
                    "url": "http://example.com/test",
                }
            ),
            TEST_SCRIPT,
            content_type="application/octet-stream",
            headers=self.headers,
        )

        self.assertEqual(resp.status_code, 200)
        response_file = b"".join(resp.streaming_content).decode()

        log = SigningLog.objects.first()
        self.assertLess(log.created, log.finished)
        self.assertEqual(
            log.handtokening_version, importlib.metadata.version("handtokening")
        )
        self.assertEqual(log.ip, "127.0.0.1")
        self.assertEqual(log.user_agent, "HT Test Agent")

        self.assertEqual(log.client, self.sign_client)
        self.assertEqual(log.client_name, "test")

        self.assertIsNotNone(log.signing_profile)
        self.assertEqual(log.signing_profile_name, "test-signing")
        self.assertIsNotNone(log.certificate)
        self.assertTrue(log.certificate_name.startswith("Test Certificate "))

        self.assertEqual(log.description, "Test PowerShell")
        self.assertEqual(log.url, "http://example.com/test")

        self.assertEqual(log.submitted_file_name, "test.ps1")

        self.assertTrue(log.in_path.endswith("in/1-test.ps1"))
        self.assertEqual(log.in_file_size, len(TEST_SCRIPT))
        self.assertEqual(
            log.in_file_sha256, hashlib.sha256(TEST_SCRIPT.encode()).hexdigest()
        )

        self.assertTrue(log.out_path.endswith("out/1-test.ps1"))
        self.assertEqual(log.out_file_size, len(response_file))
        self.assertEqual(
            log.out_file_sha256, hashlib.sha256(response_file.encode()).hexdigest()
        )

        self.assertEqual(log.osslsigncode_returncode, 0)
        self.assertEqual(log.osslsigncode_stderr, "")
        self.assertTrue("Script file format: .ps1" in log.osslsigncode_stdout)
        self.assertTrue("Succeeded" in log.osslsigncode_stdout)

        self.assertIsNone(log.vt_analysis)

        self.assertEqual(log.result, SigningLog.Result.SUCCESS)
        self.assertIsNone(log.exception)

    def test_early_error_log(self):
        # Trigger an early error by putting an unrecognised file extension
        resp = self.client.post(
            "/api/sign?"
            + urlencode(
                {
                    "signing-profile": "test-signing",
                    "description": "Test PowerShell",
                    "url": "http://example.com/test",
                }
            ),
            TEST_SCRIPT,
            content_type="application/octet-stream",
            headers={
                **self.headers,
                "content-disposition": 'attachment; filename="TEST.FZO"',
            },
        )

        self.assertEqual(resp.status_code, 400)

        log = SigningLog.objects.first()
        self.assertLess(log.created, log.finished)
        self.assertEqual(
            log.handtokening_version, importlib.metadata.version("handtokening")
        )
        self.assertEqual(log.ip, "127.0.0.1")
        self.assertEqual(log.user_agent, "HT Test Agent")

        self.assertEqual(log.client, self.sign_client)
        self.assertEqual(log.client_name, "test")

        self.assertIsNone(log.signing_profile)
        self.assertEqual(log.signing_profile_name, "test-signing")
        self.assertIsNone(log.certificate)
        self.assertIsNone(log.certificate_name)

        self.assertEqual(log.description, "Test PowerShell")
        self.assertEqual(log.url, "http://example.com/test")

        self.assertEqual(log.submitted_file_name, "TEST.FZO")

        self.assertIsNone(log.in_path)
        self.assertIsNone(log.in_file_size)
        self.assertIsNone(log.in_file_sha256)

        self.assertIsNone(log.out_path)
        self.assertIsNone(log.out_file_size)
        self.assertIsNone(log.out_file_sha256)

        self.assertIsNone(log.osslsigncode_returncode)
        self.assertIsNone(log.osslsigncode_stderr)
        self.assertIsNone(log.osslsigncode_stdout)

        self.assertIsNone(log.vt_analysis)

        self.assertEqual(log.result, SigningLog.Result.UNSUPPORTED_EXTENSION)
        self.assertIsNotNone(log.exception)
        self.assertTrue(
            "Unsupported file extension: 'fzo'" in resp.json().get("detail")
        )
        self.assertTrue(repr(resp.json().get("detail")) in log.exception)

    def test_late_error(self):
        # Trigger a late error by submitting powershell with a .exe extension
        resp = self.client.post(
            "/api/sign?"
            + urlencode(
                {
                    "signing-profile": "test-signing",
                    "description": "Test PowerShell",
                    "url": "http://example.com/test",
                }
            ),
            TEST_SCRIPT,
            content_type="application/octet-stream",
            headers={
                **self.headers,
                "content-disposition": 'attachment; filename="test.exe"',
            },
        )

        self.assertEqual(resp.status_code, 400)

        log = SigningLog.objects.first()
        self.assertLess(log.created, log.finished)
        self.assertEqual(
            log.handtokening_version, importlib.metadata.version("handtokening")
        )
        self.assertEqual(log.ip, "127.0.0.1")
        self.assertEqual(log.user_agent, "HT Test Agent")

        self.assertEqual(log.client, self.sign_client)
        self.assertEqual(log.client_name, "test")

        self.assertIsNotNone(log.signing_profile)
        self.assertEqual(log.signing_profile_name, "test-signing")
        self.assertIsNotNone(log.certificate)
        self.assertTrue(log.certificate_name.startswith("Test Certificate "))

        self.assertEqual(log.description, "Test PowerShell")
        self.assertEqual(log.url, "http://example.com/test")

        self.assertEqual(log.submitted_file_name, "test.exe")

        self.assertTrue(log.in_path.endswith("in/1-test.exe"))
        self.assertEqual(log.in_file_size, len(TEST_SCRIPT))
        self.assertEqual(
            log.in_file_sha256, hashlib.sha256(TEST_SCRIPT.encode()).hexdigest()
        )

        self.assertTrue(log.out_path.endswith("out/1-test.exe"))
        self.assertIsNone(log.out_file_size)
        self.assertIsNone(log.out_file_sha256)

        self.assertEqual(log.osslsigncode_returncode, 1)
        self.assertTrue(
            "Initialization error or unsupported input file type."
            in log.osslsigncode_stderr
        )
        self.assertTrue("Failed" in log.osslsigncode_stdout)

        self.assertIsNone(log.vt_analysis)

        self.assertEqual(log.result, SigningLog.Result.SIGN_ERROR)
        self.assertTrue("osslsigncode error code: 1" in resp.json().get("detail"))
        self.assertTrue(repr(resp.json().get("detail")) in log.exception)
