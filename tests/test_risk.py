"""Tests for CVSS risk calculation."""

import unittest

from risk.risk_assessor import calculate_risk


class RiskAssessorTests(unittest.TestCase):
    """Validate risk rating boundaries."""

    def test_risk_boundaries(self) -> None:
        expected = {
            0.0: "Low",
            3.9: "Low",
            4.0: "Medium",
            6.9: "Medium",
            7.0: "High",
            8.9: "High",
            9.0: "Critical",
            10.0: "Critical",
        }

        for score, rating in expected.items():
            with self.subTest(score=score):
                self.assertEqual(calculate_risk(score), rating)

    def test_invalid_score_raises(self) -> None:
        with self.assertRaises(ValueError):
            calculate_risk(10.1)


if __name__ == "__main__":
    unittest.main()
