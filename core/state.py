from dataclasses import dataclass, field


@dataclass
class FlowState:
    inbound_count:  int        = 0
    outbound_count: int        = 0
    last_time:      str        = ""
    inbound_bytes:  list[int]  = field(default_factory=list)
    outbound_bytes: list[int]  = field(default_factory=list)
    flow_count:     int        = 0
    timestamp_seen: bool       = False
    total_count:    int        = 0
    alert_flag:     bool       = False

    # ── last stats timestamp seen — deduplicates repeated events ────────────
    last_stats_timestamp: str = ""

    def record_flow(self, src_ip: str, host_ip: str, log: dict) -> None:
        flow = log.get("flow", {})
        bytes_in  = flow.get("bytes_toclient", 0)
        bytes_out = flow.get("bytes_toserver", 0)

        if src_ip == host_ip:
            self.outbound_count += 1
        else:
            self.inbound_count  += 1

        self.inbound_bytes.append(bytes_in)
        self.outbound_bytes.append(bytes_out)
        self.flow_count += 1

        if not self.timestamp_seen:
            self.last_time    = log.get("timestamp", "")
            self.timestamp_seen = True

    def reset(self) -> None:
        last_ts = self.last_stats_timestamp   
        self.__init__()                       
        self.last_stats_timestamp = last_ts
