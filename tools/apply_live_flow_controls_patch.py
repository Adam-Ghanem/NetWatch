from __future__ import annotations

from pathlib import Path

MAIN = Path("backend/main.py")
WORKFLOW = Path(".github/workflows/branch-patch-live-flow-controls.yml")
SELF = Path(__file__)

text = MAIN.read_text(encoding="utf-8")

old_import = """from traffic_capture import (\n    CAPTURE_PROTOCOLS,\n    CapturePermissionError,\n    CaptureUnavailableError,\n    build_capture_filter,\n    capture_interfaces,\n    capture_traffic,\n)\n"""
new_import = old_import + "from traffic_flow_controls import TrafficFlowControls, apply_traffic_flow_controls\n"
if old_import not in text:
    raise SystemExit("traffic capture import anchor not found")
text = text.replace(old_import, new_import, 1)

old_model = """class TrafficCaptureRequest(BaseModel):\n    interface: str = Field(default=\"auto\", min_length=1, max_length=64)\n    duration_seconds: int = Field(default=5, ge=1, le=MAX_CAPTURE_SECONDS)\n    max_packets: int = Field(default=250, ge=1, le=MAX_CAPTURE_PACKETS)\n    protocol: Literal[\"all\", \"tcp\", \"udp\", \"icmp\", \"arp\"] = \"all\"\n    ip_filter: str = Field(default=\"\", max_length=45)\n    port_filter: int | None = Field(default=None, ge=1, le=65_535)\n    authorized: bool = Field(\n        default=False,\n        description=\"Confirm explicit authorization for metadata-only traffic capture.\",\n    )\n"""
new_model = """class TrafficFlowControlsRequest(BaseModel):\n    display_filter: str = Field(default=\"\", max_length=1024)\n    ip_address: str = Field(default=\"\", max_length=45)\n    protocol: str = Field(default=\"\", max_length=16)\n    service: str = Field(default=\"\", max_length=64)\n    state: str = Field(default=\"\", max_length=64)\n    min_bytes: int = Field(default=0, ge=0)\n    sort_by: Literal[\"bytes\", \"packets\", \"duration\", \"recent\"] = \"bytes\"\n    limit: int = Field(default=100, ge=1, le=1_000)\n\n    def to_controls(self) -> TrafficFlowControls:\n        return TrafficFlowControls(\n            display_filter=self.display_filter,\n            ip_address=self.ip_address,\n            protocol=self.protocol,\n            service=self.service,\n            state=self.state,\n            min_bytes=self.min_bytes,\n            sort_by=self.sort_by,\n            limit=self.limit,\n        )\n\n\nclass TrafficCaptureRequest(BaseModel):\n    interface: str = Field(default=\"auto\", min_length=1, max_length=64)\n    duration_seconds: int = Field(default=5, ge=1, le=MAX_CAPTURE_SECONDS)\n    max_packets: int = Field(default=250, ge=1, le=MAX_CAPTURE_PACKETS)\n    protocol: Literal[\"all\", \"tcp\", \"udp\", \"icmp\", \"arp\"] = \"all\"\n    ip_filter: str = Field(default=\"\", max_length=45)\n    port_filter: int | None = Field(default=None, ge=1, le=65_535)\n    flow_controls: TrafficFlowControlsRequest | None = None\n    authorized: bool = Field(\n        default=False,\n        description=\"Confirm explicit authorization for metadata-only traffic capture.\",\n    )\n"""
if old_model not in text:
    raise SystemExit("traffic capture request model anchor not found")
text = text.replace(old_model, new_model, 1)

old_capture = """        with _capture_slot():\n            result = capture_traffic(\n                interface=payload.interface,\n                duration_seconds=payload.duration_seconds,\n                max_packets=payload.max_packets,\n                capture_filter=capture_filter,\n            )\n"""
new_capture = old_capture + """        if payload.flow_controls is not None:\n            result = apply_traffic_flow_controls(\n                result,\n                payload.flow_controls.to_controls(),\n            )\n"""
if old_capture not in text:
    raise SystemExit("live capture endpoint anchor not found")
text = text.replace(old_capture, new_capture, 1)

MAIN.write_text(text, encoding="utf-8")
SELF.unlink()
if WORKFLOW.exists():
    WORKFLOW.unlink()
