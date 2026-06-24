"""
Converts one Suricata 'stats' log entry + accumulated FlowState
into a flat feature dict ready for model inference.
"""

import math
import logging
import statistics
from typing import Any

from core.state import FlowState
from core.utils import timestamp_diff

log = logging.getLogger(__name__)


def extract_features(stats_log: dict[str, Any], state: FlowState) -> dict[str, Any]:
    """
    Parameters
    ----------
    stats_log : the raw Suricata 'stats' JSON object
    state     : accumulated counters for the current window

    Returns
    -------
    A flat dict of feature_name → value, matching the training schema.
    """
    stats       = stats_log.get("stats", {})
    decoder     = stats.get("decoder", {})
    flow        = stats.get("flow", {})
    app_layer   = stats.get("app_layer", {}).get("flow", {})
    app_tx      = stats.get("app_layer", {}).get("tx",   {})
    tcp         = stats.get("tcp", {})

    uptime      = stats.get("uptime", 1) or 1          # avoid /0
    total_flows = flow.get("total", 0)

    # ── Packet lengths ───────────────────────────────────────────────────────
    packet_lengths = state.inbound_bytes + state.outbound_bytes
    pkt_min  = min(packet_lengths) if packet_lengths else 0
    pkt_max  = max(packet_lengths) if packet_lengths else 0
    pkt_avg  = decoder.get("avg_pkt_size", 0)
    pkt_var  = statistics.variance(packet_lengths) if len(packet_lengths) >= 2 else 0.0
    pkt_std  = math.sqrt(pkt_var)
    pkt_sum  = sum(packet_lengths)

    # ── Per-direction averages ────────────────────────────────────────────────
    avg_in  = (sum(state.inbound_bytes)  / state.inbound_count)  if state.inbound_count  else 0.0
    avg_out = (sum(state.outbound_bytes) / state.outbound_count) if state.outbound_count else 0.0

    # ── Per-direction variance ────────────────────────────────────────────────
    var_in  = statistics.variance(state.inbound_bytes)  if len(state.inbound_bytes)  >= 2 else 0.0
    var_out = statistics.variance(state.outbound_bytes) if len(state.outbound_bytes) >= 2 else 0.0

    # ── Covariance (equal-length slices) ─────────────────────────────────────
    min_len    = min(len(state.inbound_bytes), len(state.outbound_bytes))
    covariance = (
        statistics.covariance(
            state.inbound_bytes[:min_len],
            state.outbound_bytes[:min_len],
        )
        if min_len >= 2 else 0.0
    )

    feat: dict[str, Any] = {
        # ── Timing ───────────────────────────────────────────────────────────
        "flow_duration": uptime,
        "Duration":      uptime,
        "IAT":           timestamp_diff(stats_log.get("timestamp", ""), state.last_time),

        # ── Rates ────────────────────────────────────────────────────────────
        "Rate":  total_flows / uptime,
        "Srate": state.outbound_count / uptime,
        "Drate": state.inbound_count  / uptime,

        # ── Header / size ─────────────────────────────────────────────────────
        "Header_Length": pkt_avg,
        "Protocol Type": total_flows / 14,

        # ── TCP flags (binary) ────────────────────────────────────────────────
        "fin_flag_number": int(bool(tcp.get("fin",           0))),
        "syn_flag_number": int(bool(tcp.get("syn",           0))),
        "rst_flag_number": int(bool(tcp.get("rst",           0))),
        "psh_flag_number": int(bool(tcp.get("psh",           0))),
        "ack_flag_number": int(bool(tcp.get("ack_unseen_data",0))),
        "ece_flag_number": int(bool(tcp.get("ece",           0))),
        "cwr_flag_number": int(bool(tcp.get("cwr",           0))),

        # ── TCP flag counts ───────────────────────────────────────────────────
        "ack_count": tcp.get("ack", 0),
        "syn_count": tcp.get("syn", 0),
        "fin_count": tcp.get("fin", 0),
        "urg_count": tcp.get("urg", 0),
        "rst_count": tcp.get("rst", 0),

        # ── Protocol presence flags ───────────────────────────────────────────
        "HTTP":   int(bool(app_layer.get("http",    0))),
        "HTTPS":  int(bool(app_layer.get("https",   0))),
        "DNS":    int(bool(app_layer.get("dns_udp", 0) or app_layer.get("dns_tcp", 0))),
        "Telnet": int(bool(app_layer.get("telnet",  0))),
        "SMTP":   int(bool(app_layer.get("smtp",    0))),
        "SSH":    int(bool(app_layer.get("ssh",     0))),
        "IRC":    int(bool(app_layer.get("irc",     0))),
        "TCP":    int(bool(decoder.get("tcp",        0))),
        "UDP":    int(bool(decoder.get("udp",        0))),
        "DHCP":   int(bool(app_layer.get("dhcp",    0))),
        "ARP":    int(bool(decoder.get("arp",        0))),
        "ICMP":   int(bool(decoder.get("icmpv4",    0) or decoder.get("icmpv6", 0))),
        "IPv":    int(bool(decoder.get("ipv4",       0) or decoder.get("ipv6",  0))),
        "LLC":    int(bool(decoder.get("ethernet",   0))),

        # ── Packet length stats ───────────────────────────────────────────────
        "Tot sum":  total_flows,
        "Min":      pkt_min,
        "Max":      pkt_max,
        "AVG":      pkt_avg,
        "Std":      pkt_std,
        "Tot size": pkt_sum,
        "Number":   total_flows,

        # ── Derived features ──────────────────────────────────────────────────
        "Magnitue":  math.sqrt(avg_in + avg_out),          # magnitude
        "Radius":    math.sqrt(var_in + var_out),
        "Covariance": covariance,
        "Variance":  (var_in / var_out) if var_out else 0.0,
        "Weight":    state.inbound_count * state.outbound_count,
    }

    log.debug("Extracted %d features for ts=%s", len(feat), stats_log.get("timestamp"))
    return feat
