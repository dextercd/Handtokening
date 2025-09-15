import hashlib
import logging
import os
import random
from pathlib import Path
import string
import subprocess
import tempfile
import base64

from asn1crypto import cms
from django.core.files.uploadedfile import UploadedFile
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.text import slugify
from ipware import get_client_ip
from rest_framework.parsers import FileUploadParser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .conf import config
from .external_value import ExternalValue
from .models import SigningProfile, SigningLog
from .osslsigncode import (
    OSSLSignCodeCommand,
    OSSLSignCodePkcs11,
    OSSLSignCodeResult,
    command_log_string,
)
from .serializers import SigningRequestSerializer
from .virustotal import vt_scan_file


logger = logging.getLogger(__name__)


SUPPORTED_FILE_EXTENSIONS = [
    "dll",
    "exe",
    "sys",
    "msi",
    "ps1",
    "ps1xml",
    "psc1",
    "psd1",
    "psm1",
    "cdxml",
    "mof",
    "js",
    "cab",
    "cat",
    "appx",
]


class SigningError(RuntimeError):
    result = SigningLog.Result.SIGN_ERROR


class AVPositive(SigningError):
    result = SigningLog.Result.AV_POSITIVE


class VirusTotalPositive(AVPositive):
    pass


class NoCertificates(SigningError):
    result = SigningLog.Result.NO_CERTIFICATES


class UnsupportedExtension(SigningError):
    result = SigningLog.Result.UNSUPPORTED_EXTENSION


class SigningCancelled(SigningError):
    result = SigningLog.Result.CANCELLED


class PinTimeout(SigningError):
    result = SigningLog.Result.PIN_TIMEOUT


def sha256_file_path(path: str | Path) -> str:
    """Return SHA256 hash of the bytes in the file at the provided path."""
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


_random_chars = string.ascii_letters + string.digits


def random_file_name() -> Path:
    return Path(tempfile.gettempdir()) / "".join(random.choices(_random_chars, k=10))


class SignView(APIView):
    parser_classes = [FileUploadParser]

    def post(self, request: Request, format=None):
        query_serializer = SigningRequestSerializer(data=request.query_params)
        query_serializer.is_valid(raise_exception=True)
        query = query_serializer.validated_data

        incoming_file: UploadedFile = request.data["file"]

        result: OSSLSignCodeResult | None = None
        cmd = OSSLSignCodeCommand()
        cmd.program_path = config.OSSLSIGNCODE_PATH
        cmd.description = query.get("description")
        cmd.url = query.get("url")

        ip, _ = get_client_ip(request)
        signing_log = SigningLog(
            ip=ip,
            user_agent=request.META.get("HTTP_USER_AGENT"),
            client=request.user.client,
            client_name=request.user.username,
            signing_profile_name=query["signing-profile"],
            description=query.get("description"),
            url=query.get("url"),
            submitted_file_name=incoming_file.name,
        )
        signing_log.save()

        in_path_sha256: str | None = None

        try:
            file_basename, _, file_extension = incoming_file.name.rpartition(".")
            file_extension = file_extension.lower()

            if file_extension not in SUPPORTED_FILE_EXTENSIONS:
                raise UnsupportedExtension(
                    f"Unsupported file extension: '{file_extension}'"
                )

            signing_profile: SigningProfile = get_object_or_404(
                SigningProfile.objects.filter(
                    users_with_access__id__contains=request.user.id,
                    name=query["signing-profile"],
                )
            )
            signing_log.signing_profile = signing_profile

            certificates = signing_profile.certificates.filter(
                is_enabled=True, expires__gt=timezone.now()
            )

            if not certificates:
                raise NoCertificates(
                    f"No valid certificates in signing profile '{signing_profile.name}'"
                )

            certificate = random.choice(certificates)

            signing_log.certificate = certificate
            signing_log.certificate_name = certificate.name

            cmd.cert_path = certificate.cert_path
            cmd.key_path = certificate.key_path

            # PKCS #11
            if certificate.is_pkcs11:
                cmd.pkcs11 = OSSLSignCodePkcs11(
                    provider=certificate.ossl_provider or config.OSSL_PROVIDER_PATH,
                    module=certificate.pkcs11_module or config.PKCS11_MODULE_PATH,
                )

            cmd.timestamp_servers = list(
                signing_profile.timestamp_servers.filter(is_enabled=True)
            )
            cmd.shuffle_timestamp_servers()

            local_file_name = (
                f"{signing_log.id}-{slugify(file_basename)}.{file_extension}"
            )

            cmd.in_path = config.STATE_DIRECTORY / "in" / local_file_name

            # Write submitted file to local path
            with open(cmd.in_path, "wb") as on_disk:
                for chunk in incoming_file.chunks():
                    on_disk.write(chunk)

            in_path_sha256 = sha256_file_path(cmd.in_path)

            # ClamAV scan
            clamscan = subprocess.run(
                [
                    config.CLAMSCAN_PATH,
                    "--no-summary",
                    cmd.in_path,
                ],
                timeout=30,
                text=True,
                capture_output=True,
            )

            if clamscan.returncode != 0:
                raise AVPositive(f"ClamAV: {clamscan.stdout.strip()}")

            if signing_profile.vt_scan != SigningProfile.VirusTotalScanSetting.NO:
                try:
                    analysis = vt_scan_file(cmd.in_path, in_path_sha256)
                    engine_results = list(analysis.results.all())

                    signing_log.vt_analysis = analysis

                    fatal_candidates = signing_profile.get_vt_fatal_engines_list()
                    fatal_engines: list[str] = []
                    for engine_result in engine_results:
                        if (
                            engine_result.bad
                            and engine_result.name.lower() in fatal_candidates
                        ):
                            fatal_engines.append(str(engine_result))

                    if fatal_engines:
                        raise VirusTotalPositive(
                            f"Detected as bad by required engine: {', '.join(fatal_engines)}"
                        )

                    bad_count = sum(r.bad for r in engine_results)
                    percent_bad = bad_count / len(engine_results) * 100
                    if percent_bad > signing_profile.vt_max_bad_percent:
                        raise VirusTotalPositive(
                            "Too many engines marked the code as bad"
                        )
                except Exception as exc:
                    if isinstance(exc, SigningError):
                        raise  # Pass on up
                    elif (
                        signing_profile.vt_scan
                        == SigningProfile.VirusTotalScanSetting.REQUIRED
                    ):
                        raise  # VirusTotal analysis is required so abort signing process
                    else:
                        # Not required, so we log the error and continue
                        logger.exception("VirusTotal scan error")

            if certificate.is_pkcs11:
                # Get pin for accessing the hardware token
                request = {
                    "user": request.user.username,
                    "certificate": certificate.name,
                    "description": query.get("description") or "No description",
                }
                with ExternalValue(request) as external:
                    try:
                        resp = external.read_for(60)
                    except TimeoutError:
                        raise PinTimeout("Didn't receive pin on time")

                if resp["result"] == "cancelled":
                    raise SigningCancelled("Received cancelled response")
                elif resp["result"] != "approve":
                    raise SigningError(
                        f"Unexpected response result: {repr(resp['result'])}"
                    )

                cmd.pin = resp["code"]

            cmd.out_path = config.STATE_DIRECTORY / "out" / local_file_name
            signing_log.osslsigncode_command = command_log_string(cmd.build_command())
            result = cmd.run()

            if not result.success:
                raise SigningError(f"osslsigncode error code: {result.returncode}")

            signing_log.result = SigningLog.Result.SUCCESS

            if query["response-type"] == "complete":
                return FileResponse(
                    open(cmd.out_path, "rb"),
                    as_attachment=True,
                    filename=local_file_name,
                )
            elif query["response-type"] == "pkcs7":
                pkcs7_temp_path = random_file_name()
                subprocess.run(
                    [
                        config.OSSLSIGNCODE_PATH,
                        "extract-signature",
                        "-in",
                        cmd.out_path,
                        "-out",
                        pkcs7_temp_path,
                    ],
                    check=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                with open(pkcs7_temp_path, "rb") as f:
                    pkcs7_data = f.read()
                pkcs7_temp_path.unlink()

                signer_info = cms.ContentInfo.load(pkcs7_data)["content"][
                    "signer_infos"
                ][0]
                signature = base64.b64encode(signer_info["signature"].native)
                return HttpResponse(
                    pkcs7_data,
                    content_type="application/pkcs7-signature",
                    headers={
                        "ht-signed": signature,
                    },
                )
        except Exception as exc:
            signing_log.exception = repr(exc)

            if isinstance(exc, SigningError):
                signing_log.result = exc.result
                return Response({"message": str(exc)}, status=400)
            else:
                signing_log.result = SigningLog.Result.INTERNAL_ERROR
                raise
        finally:
            if cmd.in_path:
                signing_log.in_path = str(cmd.in_path)
                try:
                    signing_log.in_file_size = os.path.getsize(cmd.in_path)
                    signing_log.in_file_sha256 = in_path_sha256
                except Exception:
                    pass

            if cmd.out_path:
                signing_log.out_path = str(cmd.out_path)
                try:
                    signing_log.out_file_size = os.path.getsize(cmd.out_path)
                    signing_log.out_file_sha256 = sha256_file_path(cmd.out_path)
                except Exception:
                    pass

            if result:
                signing_log.osslsigncode_returncode = result.returncode
                signing_log.osslsigncode_stdout = result.stdout
                signing_log.osslsigncode_stderr = result.stderr

            signing_log.finished = timezone.now()
            signing_log.save()
