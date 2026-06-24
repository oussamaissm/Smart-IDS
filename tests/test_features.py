"""
Unit tests for the feature extractor.
Run with:  python -m pytest tests/
"""

import math
import sys
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from core.feature_extractor import extract_features
from core.state             import FlowState


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_stats_log(
    uptime: int = 60,
    total_flows: int = 100,
    timestamp: str = "2024-01-01T00:01:00.000000+0000",
) -> dict:
    return {
        "timestamp": timestamp,
        "event_type": "stats",
        "stats": {
            "uptime": uptime,
            "decoder": {
                "avg_pkt_size": 512,
                "tcp": 80,
                "udp": 20,
                "icmpv4": 0,
                "icmpv6": 0,
                "ipv4": 90,
                "ipv6": 10,
                "ethernet": 100,
                "arp": 0,
            },
            "flow": {"total": total_flows},
            "app_layer": {
                "flow": {"http": 50, "https": 30, "dns_udp": 10},
                "tx":   {"http": 40, "https": 20, "dns_udp": 8},
            },
            "tcp": {
                "syn": 10, "fin": 5, "rst": 0, "psh": 3,
                "ack": 70, "ack_unseen_data": 2, "urg": 0,
                "ece": 0,  "cwr": 0,
            },
        },
    }


def _make_state(
    inbound_bytes:  list[int] | None = None,
    outbound_bytes: list[int] | None = None,
    inbound_count:  int = 0,
    outbound_count: int = 0,
    last_time:      str = "2024-01-01T00:00:00.000000+0000",
) -> FlowState:
    state = FlowState()
    state.inbound_bytes  = inbound_bytes  or []
    state.outbound_bytes = outbound_bytes or []
    state.inbound_count  = inbound_count
    state.outbound_count = outbound_count
    state.last_time      = last_time
    return state


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestExtractFeatures:

    def test_returns_dict(self):
        feat = extract_features(_make_stats_log(), _make_state())
        assert isinstance(feat, dict)

    def test_required_keys_present(self):
        required = [
            "flow_duration", "Duration", "Rate", "Srate", "Drate",
            "fin_flag_number", "syn_flag_number", "TCP", "UDP",
            "HTTP", "HTTPS", "DNS", "Min", "Max", "AVG", "Std",
            "Tot size", "Magnitue", "Radius", "Covariance", "Variance",
            "Weight", "IAT", "Number",
        ]
        feat = extract_features(_make_stats_log(), _make_state())
        for key in required:
            assert key in feat, f"Missing feature: {key}"

    def test_rate_calculation(self):
        feat = extract_features(_make_stats_log(uptime=60, total_flows=120), _make_state())
        assert feat["Rate"] == pytest.approx(2.0)

    def test_iat_is_float(self):
        feat = extract_features(
            _make_stats_log(timestamp="2024-01-01T00:01:00.000000+0000"),
            _make_state(last_time="2024-01-01T00:00:00.000000+0000"),
        )
        assert isinstance(feat["IAT"], float)
        assert feat["IAT"] == pytest.approx(60.0)

    def test_weight(self):
        state = _make_state(inbound_count=4, outbound_count=6)
        feat  = extract_features(_make_stats_log(), state)
        assert feat["Weight"] == 24

    def test_std_with_single_packet(self):
        """Variance is undefined for n=1; should not raise."""
        state = _make_state(inbound_bytes=[100], outbound_bytes=[200])
        feat  = extract_features(_make_stats_log(), state)
        assert feat["Std"] == pytest.approx(0.0)

    def test_std_with_multiple_packets(self):
        state = _make_state(
            inbound_bytes=[100, 200, 300],
            outbound_bytes=[150, 250, 350],
        )
        feat = extract_features(_make_stats_log(), state)
        assert feat["Std"] > 0

    def test_magnitude_non_negative(self):
        state = _make_state(
            inbound_bytes=[100, 200],
            outbound_bytes=[150, 250],
            inbound_count=2,
            outbound_count=2,
        )
        feat = extract_features(_make_stats_log(), state)
        assert feat["Magnitue"] >= 0

    def test_variance_ratio_zero_when_no_outgoing(self):
        state = _make_state(inbound_bytes=[100, 200], outbound_bytes=[])
        feat  = extract_features(_make_stats_log(), state)
        assert feat["Variance"] == pytest.approx(0.0)

    def test_protocol_flags_binary(self):
        feat = extract_features(_make_stats_log(), _make_state())
        for flag in ("HTTP", "HTTPS", "DNS", "TCP", "UDP", "ICMP", "IPv", "LLC"):
            assert feat[flag] in (0, 1), f"{flag} should be 0 or 1"

    def test_empty_state_does_not_raise(self):
        """All-zero state — no division errors or statistics exceptions."""
        feat = extract_features(_make_stats_log(), FlowState())
        assert feat["Weight"] == 0


class TestFlowState:

    def test_reset_clears_counters(self):
        state = _make_state(inbound_count=5, outbound_count=3)
        state.last_stats_timestamp = "ts-abc"
        state.reset()
        assert state.inbound_count  == 0
        assert state.outbound_count == 0
        assert state.inbound_bytes  == []
        # last_stats_timestamp is preserved across reset
        assert state.last_stats_timestamp == "ts-abc"

    def test_record_flow_inbound(self):
        state = FlowState()
        state.record_flow(
            src_ip  = "1.2.3.4",
            host_ip = "10.0.0.1",
            log     = {"timestamp": "2024-01-01T00:00:00.000000+0000",
                       "flow": {"bytes_toclient": 500, "bytes_toserver": 200}},
        )
        assert state.inbound_count  == 1
        assert state.outbound_count == 0
        assert state.inbound_bytes  == [500]

    def test_record_flow_outbound(self):
        state = FlowState()
        state.record_flow(
            src_ip  = "10.0.0.1",
            host_ip = "10.0.0.1",
            log     = {"timestamp": "2024-01-01T00:00:00.000000+0000",
                       "flow": {"bytes_toclient": 100, "bytes_toserver": 800}},
        )
        assert state.outbound_count == 1
        assert state.inbound_count  == 0

    def test_timestamp_only_set_once(self):
        state = FlowState()
        entry = lambda ts: {
            "timestamp": ts,
            "flow": {"bytes_toclient": 0, "bytes_toserver": 0},
        }
        state.record_flow("x", "y", entry("T1"))
        state.record_flow("x", "y", entry("T2"))
        assert state.last_time == "T1"   # only the first call sets it
