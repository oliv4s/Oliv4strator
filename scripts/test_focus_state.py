"""Offline regression tests for the investigation budget and pivot rules."""

from datetime import timedelta
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import casebook
import focus_state


TARGET = "10.10.10.10"


def plan(key: str, action: str = "start", **extra: str) -> dict:
    return {"action": action, "avenue": "recon", "branch_key": key,
            "question": "¿Qué servicio explica la señal observada?",
            "basis": "Hay un banner observado y una respuesta HTTP distinta.",
            "test": "Comparar una petición normal con un control negativo.",
            "expected": "Una diferencia estable en código, cuerpo o estado.", **extra}


class FocusStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "scope.json").write_text(json.dumps({"target_ip": TARGET}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_budget_blocks_and_requires_real_pivot(self):
        self.assertTrue(focus_state.status(self.root, TARGET)["needs_focus"])
        focus_state.change(self.root, TARGET, plan("service-map"))
        for index in range(focus_state.BASE_ACTIONS):
            casebook.record_event(self.root, TARGET, "shell", {"index": index})
        with self.assertRaisesRegex(ValueError, "agotada"):
            focus_state.enforce(self.root, TARGET)
        with self.assertRaisesRegex(ValueError, "diferentes"):
            focus_state.change(self.root, TARGET,
                               plan("service-map", "pivot", prior_result="La prueba no encontró diferencias repetibles."))
        with self.assertRaisesRegex(ValueError, "misma área"):
            focus_state.change(self.root, TARGET,
                               plan("more-service-map", "pivot",
                                    question="¿Otro banner revela una versión diferente?",
                                    prior_result="La prueba no encontró diferencias repetibles."))
        next_plan = plan("auth-boundary", "pivot",
                         avenue="authentication",
                         question="¿La sesión cruza la frontera entre dos usuarios?",
                         prior_result="El banner y la comparación no aportaron una vía de acceso.")
        result = focus_state.change(self.root, TARGET, next_plan)
        self.assertFalse(result["exhausted"])
        self.assertEqual(result["remaining_actions"], focus_state.BASE_ACTIONS)
        self.assertEqual(result["history"][-1]["branch_key"], "service-map")

    def test_one_extension_needs_new_action_evidence(self):
        focus_state.change(self.root, TARGET, plan("ticket-flow"))
        focus_event = next(row for row in casebook.events(self.root, TARGET, 10)
                           if row["kind"] == "focus")
        extension = {"action": "extend", "evidence_id": focus_event["event_id"],
                     "new_observation": "La respuesta contiene un campo nuevo verificable.",
                     "test": "Comprobar el campo nuevo con un control negativo."}
        with self.assertRaisesRegex(ValueError, "event_id nuevo"):
            focus_state.change(self.root, TARGET, extension)
        observed = casebook.record_event(self.root, TARGET, "shell", {"observation": "new"})
        extension["evidence_id"] = observed["event_id"]
        result = focus_state.change(self.root, TARGET, extension)
        self.assertEqual(result["remaining_actions"], focus_state.EXTENSION_ACTIONS)
        with self.assertRaisesRegex(ValueError, "única ampliación"):
            focus_state.change(self.root, TARGET, extension)

    def test_time_budget_expires_without_actions(self):
        focus_state.change(self.root, TARGET, plan("login-control"))
        state = focus_state.load(self.root, TARGET)
        state["expires_at"] = focus_state.stamp(focus_state.now() - timedelta(seconds=1))
        casebook.atomic_json(focus_state.path(self.root, TARGET), state)
        with self.assertRaisesRegex(ValueError, "agotada"):
            focus_state.enforce(self.root, TARGET)


if __name__ == "__main__":
    unittest.main()
