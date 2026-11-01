import math
import unittest

from loglab.events import build_event
from loglab.features import (FEATURE_NAMES, FEATURE_VERSION, compute_features,
                             feature_vector, sort_events, validate_features)

ACCOUNT_A = "a" * 64
CLIENT = "b" * 64
STREAM = "11111111-1111-4111-8111-111111111111"


def make(number, second, kind="login.failure", account=ACCOUNT_A, millis=0):
    """Event valid pada detik ke-`second` dalam menit 00:00."""
    reason = "SUCCESS" if kind == "login.success" else "INVALID_CREDENTIALS"
    stamp = "2026-01-01T00:00:%02d.%03dZ" % (second, millis)
    return build_event(
        source_id="login-lab-a", stream_id=STREAM, sequence=number, occurred_at=stamp,
        event_type=kind, account_token=account, client_token=CLIENT, reason_code=reason,
        event_id="00000000-0000-4000-8000-%012d" % number)


class FeatureTests(unittest.TestCase):
    def test_schema_order_is_fixed(self):
        self.assertEqual(FEATURE_VERSION, "login-window-v1")
        self.assertEqual(FEATURE_NAMES, (
            "event_count", "failure_count", "success_count", "failure_ratio",
            "distinct_accounts", "max_consecutive_failures", "active_span_seconds"))

    def test_manual_example_four_failures_then_success(self):
        events = [make(1, 0), make(2, 10), make(3, 20), make(4, 30), make(5, 40, "login.success")]
        values = compute_features(events)
        self.assertEqual(list(values), list(FEATURE_NAMES))
        self.assertEqual(values, {
            "event_count": 5, "failure_count": 4, "success_count": 1, "failure_ratio": 0.8,
            "distinct_accounts": 1, "max_consecutive_failures": 4, "active_span_seconds": 40.0})
        self.assertEqual(feature_vector(values), [5.0, 4.0, 1.0, 0.8, 1.0, 4.0, 40.0])

    def test_single_event_has_zero_span(self):
        values = compute_features([make(1, 5, "login.success")])
        self.assertEqual(values["active_span_seconds"], 0.0)
        self.assertEqual(values["failure_ratio"], 0.0)
        self.assertEqual(values["max_consecutive_failures"], 0)

    def test_longest_failure_run_uses_event_order_not_input_order(self):
        events = [make(1, 0), make(2, 5), make(3, 10, "login.success"), make(4, 15), make(5, 20), make(6, 25)]
        shuffled = [events[4], events[0], events[5], events[2], events[1], events[3]]
        self.assertEqual(compute_features(shuffled)["max_consecutive_failures"], 3)

    def test_distinct_accounts_counts_unique_pseudonyms(self):
        events = [make(n, n, account=("%064x" % (n % 3 + 1))) for n in range(1, 8)]
        self.assertEqual(compute_features(events)["distinct_accounts"], 3)

    def test_ties_break_by_event_id_not_by_arrival(self):
        first, second = make(2, 7), make(1, 7)  # waktu sama; event_id ...0001 lebih kecil
        self.assertEqual([e["event_id"][-1] for e in sort_events([first, second])], ["1", "2"])

    def test_time_is_parsed_not_compared_as_text(self):
        # "00:00:05Z" lebih awal dari "00:00:05.5Z" walaupun urutan teksnya sebaliknya
        early, late = make(1, 5, "login.success"), make(2, 5, "login.failure", millis=500)
        self.assertEqual(sort_events([late, early])[0]["event_id"], early["event_id"])
        self.assertEqual(compute_features([late, early])["active_span_seconds"], 0.5)

    def test_bad_input_is_rejected_not_defaulted_to_zero(self):
        with self.assertRaises(ValueError):
            compute_features([])
        with self.assertRaises(ValueError):
            compute_features([make(1, 0), make(1, 1)])  # event_id ganda
        broken = dict(make(1, 0), event_type="login.other")
        with self.assertRaises(ValueError):
            compute_features([broken])
        with self.assertRaises(ValueError):
            compute_features([make(1, 0), make(2, 59), dict(make(3, 59), occurred_at="2026-01-01T00:01:01.000Z")])

    def test_validate_rejects_missing_nan_wrong_type_and_inconsistent_values(self):
        good = compute_features([make(1, 0), make(2, 1, "login.success")])
        validate_features(good)
        missing = dict(good)
        del missing["failure_ratio"]
        cases = {
            "missing": missing,
            "extra": dict(good, extra=1),
            "nan": dict(good, failure_ratio=math.nan),
            "inf": dict(good, active_span_seconds=math.inf),
            "text": dict(good, failure_count="1"),
            "bool": dict(good, event_count=True),
            "float_for_int": dict(good, event_count=2.0),
            "sum_mismatch": dict(good, success_count=0),
            "ratio_range": dict(good, failure_ratio=1.5),
            "span_range": dict(good, active_span_seconds=60.0),
        }
        for name, values in cases.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    validate_features(values)


if __name__ == "__main__":
    unittest.main()
