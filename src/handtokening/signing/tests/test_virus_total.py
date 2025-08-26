from datetime import datetime, timezone

import vt
from django.test import TestCase

from handtokening.signing.models import VirusTotalAnalysis, VirusTotalEngineResult
from handtokening.signing.virustotal import create_analysis_from_object


class VirusTotalTestCase(TestCase):
    def setUp(self):
        self.file = vt.Object.from_dict(
            {
                "type": "file",
                "id": "03e57d8e097811a562a8287c6f2b1e2161d810c36c9f2b4fc3934aefec025047",
                "attributes": {
                    "last_analysis_date": 1756147763,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 5,
                        "harmless": 0,
                        "timeout": 0,
                        "confirmed-timeout": 0,
                        "failure": 0,
                        "type-unsupported": 1,
                    },
                    "last_analysis_results": {
                        "Malwarebytes": {
                            "method": "blacklist",
                            "engine_name": "Malwarebytes",
                            "engine_version": "3.1.0.150",
                            "engine_update": "20250825",
                            "category": "undetected",
                            "result": None,
                        },
                        "CrowdStrike": {
                            "method": "blacklist",
                            "engine_name": "CrowdStrike",
                            "engine_version": "1.0",
                            "engine_update": "20231026",
                            "category": "undetected",
                            "result": None,
                        },
                        "Symantec": {
                            "method": "blacklist",
                            "engine_name": "Symantec",
                            "engine_version": "1.22.0.0",
                            "engine_update": "20250825",
                            "category": "undetected",
                            "result": None,
                        },
                        "ClamAV": {
                            "method": "blacklist",
                            "engine_name": "ClamAV",
                            "engine_version": "1.4.3.0",
                            "engine_update": "20250825",
                            "category": "undetected",
                            "result": None,
                        },
                        "Microsoft": {
                            "method": "blacklist",
                            "engine_name": "Microsoft",
                            "engine_version": "1.1.25070.4",
                            "engine_update": "20250825",
                            "category": "undetected",
                            "result": None,
                        },
                        "SymantecMobileInsight": {
                            "method": "blacklist",
                            "engine_name": "SymantecMobileInsight",
                            "engine_version": "2.0",
                            "engine_update": "20250124",
                            "category": "type-unsupported",
                            "result": None,
                        },
                    },
                },
            }
        )

    def test_analysis_from_object(self):
        analysis = create_analysis_from_object(
            "30820519414911ccbed8591f390e7c272df07237aad475a3147d0e673b7eb2ca",
            self.file,
            "last_analysis_",
        )

        self.assertIsInstance(analysis, VirusTotalAnalysis)

        self.assertEqual(
            analysis.sha256,
            "30820519414911ccbed8591f390e7c272df07237aad475a3147d0e673b7eb2ca",
        )
        self.assertEqual(
            analysis.date, datetime(2025, 8, 25, 18, 49, 23, tzinfo=timezone.utc)
        )

        results = list(analysis.results.all())
        self.assertEqual(len(results), 6)

        for result in results:
            self.assertTrue(not result.bad)

        smi: VirusTotalEngineResult = next(
            r for r in results if r.name == "SymantecMobileInsight"
        )
        self.assertFalse(smi.bad)
        self.assertFalse(smi.good)

        self.assertEqual(str(smi), "SymantecMobileInsight type-unsupported")
