from datetime import datetime, timezone, timedelta
from time import sleep, time
from pathlib import Path

import vt

from .models import VirusTotalAnalysis, VirusTotalEngineResult
from .conf import config


ANALYSIS_REUSE_TIME = timedelta(days=10)


def get_configured_client() -> vt.Client:
    if not config.VIRUS_TOTAL_API_KEY:
        raise RuntimeError("No VirusTotal API key configured")

    return vt.Client(config.VIRUS_TOTAL_API_KEY, "handtokening")


def create_analysis_from_object(
    sha256: str, object: vt.Object, key_prefix: str, extra_fields: dict = {}
) -> VirusTotalAnalysis:
    analysis = VirusTotalAnalysis(
        sha256=sha256,
        date=datetime.fromtimestamp(object.get(f"{key_prefix}date"), timezone.utc),
        **extra_fields,
    )
    analysis.save()

    analysis.results.bulk_create(
        VirusTotalEngineResult(
            analysis=analysis,
            category=result.get("category"),
            name=result["engine_name"],
            update=result["engine_update"],
            version=result["engine_version"],
            method=result["method"],
            result=result.get("result"),
        )
        for result in object.get(f"{key_prefix}results").values()
    )

    return analysis


def can_reuse_file_analysis(file: vt.Object):
    if not file.get("last_analysis_date"):
        return False

    now = datetime.now(timezone.utc)
    last_analysis = datetime.fromtimestamp(file.get("last_analysis_date"), timezone.utc)

    return now - last_analysis < ANALYSIS_REUSE_TIME


def vt_scan_file(path: str | Path, sha256: str) -> VirusTotalAnalysis:
    existing_analysis = (
        VirusTotalAnalysis.objects.filter(sha256=sha256).order_by("-date").first()
    )
    if (
        existing_analysis
        and datetime.now(timezone.utc) - existing_analysis.date < ANALYSIS_REUSE_TIME
    ):
        return existing_analysis

    with get_configured_client() as client:
        existing_file: vt.Object | None = None
        try:
            existing_file = client.get_object(f"/files/{sha256}")
        except vt.APIError as exc:
            if exc.code != "NotFoundError":
                raise

        if existing_file and can_reuse_file_analysis(existing_file):
            return create_analysis_from_object(sha256, existing_file, "last_analysis_")

        # Need to (re)scan
        if existing_file:
            analysis = client.post_object(f"/files/{sha256}/analyse")
        else:
            with open(path, "rb") as f:
                analysis = client.scan_file(f)

        analysis_start = time()

        # It'll take some time for the analysis to complete. Sleep for some extra
        # time before fetching a new analysis object.
        sleep(25)

        while analysis.get("status") != "completed":
            sleep(20)
            analysis = client.get_object("/analyses/{}", analysis.id)

        analysis_end = time()

        return create_analysis_from_object(
            sha256, analysis, "", {"analysis_time": analysis_end - analysis_start}
        )
