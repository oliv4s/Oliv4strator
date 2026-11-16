"""Offline checks for minimal-PoC records and review drafts."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import program_findings
import program_policy


class ProgramFindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, cls.digest = program_policy.load(ROOT, "demo-program")

    def test_verified_poc_generates_redacted_manual_draft(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            scope = {"program_id": "demo-program", "program_policy_sha256": self.digest}
            request = {
                "title": "Lectura indebida de un recurso de prueba",
                "category": "IDOR",
                "affected_url": "https://api.example.test/v1/items",
                "proof": "La respuesta mostró el marcador de nuestra segunda cuenta de prueba.",
                "impact_hypothesis": "Otra cuenta podría leer recursos ajenos si se confirma el mismo control.",
                "technical_reproduction": "curl -i 'https://api.example.test/v1/items?token=secret123'",
                "reproduction_steps": [
                    "Autenticarse con la cuenta de prueba propia alice@example.test.",
                    "Enviar GET /v1/items?token=secret123 con el identificador de la segunda cuenta de prueba.",
                ],
                "confirming_attempt_ids": ["a" * 12, "b" * 12],
            }
            result = program_findings.add(root, scope, self.policy, request,
                                          {"a" * 12, "b" * 12})
            draft = Path(result["report_file"]).read_text(encoding="utf-8")
            self.assertIn("GET /v1/items?token=[REDACTED]", draft)
            self.assertIn("curl -i", draft)
            self.assertNotIn("secret123", draft)
            self.assertNotIn("alice@example.test", draft)
            self.assertIn("Detén las pruebas", result["next_action"])
            self.assertEqual(program_findings.view(root, scope)["total"], 1)
            self.assertEqual(program_findings.view(root, scope, result["finding_id"])["status"],
                             "verified_minimal_poc")

    def test_requires_scope_and_decisive_attempts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            scope = {"program_id": "demo-program", "program_policy_sha256": self.digest}
            request = {
                "title": "PoC de control de acceso", "category": "IDOR",
                "affected_url": "https://blog.example.test/",
                "proof": "Respuesta de prueba confirmada de forma reproducible.",
                "impact_hypothesis": "Podría afectar a otros recursos.",
                "technical_reproduction": "curl -i 'https://api.example.test/v1'",
                "reproduction_steps": ["Preparar la cuenta de prueba", "Enviar una petición de control"],
                "confirming_attempt_ids": ["a" * 12],
            }
            with self.assertRaisesRegex(ValueError, "activo autorizado"):
                program_findings.add(root, scope, self.policy, request, {"a" * 12})
            request["affected_url"] = "https://api.example.test/v1"
            request["confirming_attempt_ids"] = ["a" * 12, "b" * 12, "c" * 12]
            with self.assertRaisesRegex(ValueError, "uno o dos"):
                program_findings.add(root, scope, self.policy, request,
                                     {"a" * 12, "b" * 12, "c" * 12})


if __name__ == "__main__":
    unittest.main()
