import ast
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "node-manager"


class PythonCompatibilityTests(unittest.TestCase):
    def test_runtime_modules_postpone_annotation_evaluation(self):
        missing = []
        for source_path in APP_ROOT.rglob("*.py"):
            module = ast.parse(source_path.read_text(encoding="utf-8"))
            has_future_annotations = any(
                isinstance(statement, ast.ImportFrom)
                and statement.module == "__future__"
                and any(alias.name == "annotations" for alias in statement.names)
                for statement in module.body
            )
            if not has_future_annotations:
                missing.append(str(source_path.relative_to(PROJECT_ROOT)))

        self.assertEqual([], missing)


if __name__ == "__main__":
    unittest.main()
