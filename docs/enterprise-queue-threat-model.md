# Enterprise queue threat model

Queue workers must not cross tenant boundaries. Claims and acknowledgements require a tenant scope and a fenced claim generation. This document tracks controls pending implementation; this branch is not ready to merge.
