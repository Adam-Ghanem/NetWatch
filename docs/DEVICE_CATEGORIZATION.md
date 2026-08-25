# Device categorization

NetWatch now provides a conservative coarse category for inventory assets: `mobile`, `network`, `printer`, `camera`, `smart-tv`, `server`, `workstation`, or `unknown`.

Classification is evidence-driven from supplied hostname, manufacturer, device type, and platform fields. It does not perform external lookups and never treats an unknown device as a confirmed category.

This layer is intentionally separate from OS fingerprinting so future vendor/device rules can be added without changing the platform classifier.
