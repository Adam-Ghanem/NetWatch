# NetWatch Architecture Notes

NetWatch is intentionally simple and local-first. The app is built around small Python modules so each part can be understood and improved separately.

## Main flow

```text
User input
   ↓
Streamlit UI (`app.py`)
   ↓
Validation (`security.py`)
   ↓
Network logic (`ping_checker.py`, `network_scanner.py`, `port_scanner.py`)
   ↓
Risk summary (`risk_engine.py`)
   ↓
Local storage (`history_store.py`, `inventory_store.py`)
   ↓
Reports (`report_builder.py`)
```

## Modules

- `app.py`: Streamlit pages and layout.
- `security.py`: IP/CIDR validation and safe local-only restrictions.
- `ping_checker.py`: single host availability check.
- `network_scanner.py`: local CIDR ping sweep.
- `port_scanner.py`: common service check for one local host.
- `risk_engine.py`: exposure score, level and recommendation priority.
- `network_tools.py`: CIDR profile helper.
- `history_store.py`: CSV history for simple scan logs.
- `inventory_store.py`: SQLite asset inventory.
- `report_builder.py`: Markdown and HTML reports.

## Storage

The app creates local files while running:

```text
data/netwatch.db
data/scan_history.csv
logs/netwatch.log
```

These files are ignored by Git because they are generated on the user's machine.

## Safety design

NetWatch keeps the project focused on defensive/local practice:

- Private/local IP validation.
- Maximum local scan size.
- Short common-port list.
- Explicit permission checkbox in the UI.
- No exploitation, brute force, evasion, or credential logic.
