import subprocess
import os
import itertools
import random
import hashlib

from django.core.files.uploadedfile import UploadedFile
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.text import slugify
from ipware import get_client_ip
from rest_framework.parsers import FileUploadParser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import SigningProfile, SigningLog
from .conf import config
from .external_value import ExternalValue


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


class NoCertificates(SigningError):
    result = SigningLog.Result.NO_CERTIFICATES


class UnsupportedExtension(SigningError):
    result = SigningLog.Result.UNSUPPORTED_EXTENSION


class SigningCancelled(SigningError):
    result = SigningLog.Result.CANCELLED


class PinTimeout(SigningError):
    result = SigningLog.Result.PIN_TIMEOUT


class SignView(APIView):
    parser_classes = [FileUploadParser]

    def post(self, request: Request, format=None):
        ip, _ = get_client_ip(request)
        signing_log = SigningLog(
            ip=ip,
            user_agent=request.META.get("HTTP_USER_AGENT"),
            client=request.user.client,
            client_name=request.user.username,
        )
        signing_log.save()

        try:
            signing_profile_name = request.query_params["signing-profile"]
            description = request.query_params.get("description") or None
            url = request.query_params.get("url") or None

            signing_log.signing_profile_name = signing_profile_name
            signing_log.description = description
            signing_log.url = url

            incoming_file: UploadedFile = request.data["file"]
            signing_log.submitted_file_name = incoming_file.name
            file_basename, _, file_extension = incoming_file.name.rpartition(".")

            if file_extension not in SUPPORTED_FILE_EXTENSIONS:
                raise UnsupportedExtension(
                    f"Unsupported file extensions: '{file_extension}'"
                )

            signing_profile: SigningProfile = get_object_or_404(
                SigningProfile.objects.filter(
                    users_with_access__id__contains=request.user.id,
                    name=signing_profile_name,
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

            timestamp_servers = list(
                signing_profile.timestamp_servers.filter(is_enabled=True)
            )
            random.shuffle(timestamp_servers)

            file_name = f"{signing_log.id}-{slugify(file_basename)}.{file_extension}"

            in_path = config.STATE_DIRECTORY / "in" / file_name
            signing_log.in_path = str(in_path)

            with open(in_path, "wb") as on_disk:
                for chunk in incoming_file.chunks():
                    on_disk.write(chunk)

            signing_log.in_file_size = os.path.getsize(in_path)
            with open(in_path, "rb") as f:
                signing_log.in_file_sha256 = hashlib.file_digest(
                    f, "sha256"
                ).hexdigest()

            clamscan = subprocess.run(
                [
                    config.CLAMSCAN_PATH,
                    "--no-summary",
                    in_path,
                ],
                timeout=30,
                text=True,
                capture_output=True,
            )

            if clamscan.returncode != 0:
                raise AVPositive(clamscan.stdout.strip())

            out_path = config.STATE_DIRECTORY / "out" / file_name
            signing_log.out_path = str(out_path)

            # Build the osslsigncode command
            osslsigncode_command = [
                config.OSSLSIGNCODE_PATH,
                "sign",
                "-in",
                in_path,
                "-out",
                str(out_path),
            ]

            # PKCS #11
            if certificate.is_pkcs11:
                osslsigncode_command.extend(
                    [
                        "-login",
                        "-provider",
                        certificate.ossl_provider or config.OSSL_PROVIDER_PATH,
                        "-pkcs11module",
                        certificate.pkcs11_module or config.PKCS11_MODULE_PATH,
                    ]
                )

            # Certificate
            if certificate.is_pkcs11 and certificate.cert_path.startswith("pkcs11:"):
                osslsigncode_command.append("-pkcs11cert")
            else:
                osslsigncode_command.append("-certs")

            osslsigncode_command.append(certificate.cert_path)

            # Key
            osslsigncode_command.extend(["-key", certificate.key_path])

            # Timestamp servers
            osslsigncode_command.extend(
                list(
                    itertools.chain.from_iterable(
                        ["-ts", ts.url] for ts in timestamp_servers
                    )
                )
            )

            # Signed content description
            if description:
                osslsigncode_command.extend(["-n", description])
            if url:
                osslsigncode_command.extend(["-i", url])

            proc_env = os.environ.copy()

            if certificate.is_pkcs11:
                request = {
                    "user": request.user.username,
                    "certificate": certificate.name,
                    "description": description or "No description",
                }
                with ExternalValue(request) as external:
                    try:
                        resp = external.read(60)
                    except TimeoutError:
                        raise PinTimeout("Didn't receive pin on time")

                if resp["result"] == "cancelled":
                    raise SigningCancelled("Received cancelled response")
                elif resp["result"] != "approve":
                    raise SigningError(
                        f"Unexpected response result: {repr(resp['result'])}"
                    )

                pwd = resp["code"]
                proc_env["PKCS11_PIN"] = pwd
                proc_env["PKCS11_FORCE_LOGIN"] = "1"

            signresult = subprocess.run(
                osslsigncode_command, capture_output=True, text=True, env=proc_env
            )
            signing_log.osslsigncode_returncode = signresult.returncode
            signing_log.osslsigncode_stdout = signresult.stdout
            signing_log.osslsigncode_stderr = signresult.stderr

            if signresult.returncode != 0:
                raise SigningError(f"osslsigncode error code: {signresult.returncode}")

            signing_log.out_file_size = os.path.getsize(out_path)
            with open(out_path, "rb") as f:
                signing_log.out_file_sha256 = hashlib.file_digest(
                    f, "sha256"
                ).hexdigest()

            signing_log.result = SigningLog.Result.SUCCESS
            return FileResponse(
                open(out_path, "rb"), as_attachment=True, filename=file_name
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
            signing_log.finished = timezone.now()
            signing_log.save()
