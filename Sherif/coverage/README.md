# Coverage Module

## Description

This module keeps track of completed security tests and stores scan history for future comparison.

## Files

* `coverage.py` - Main module.
* `schema.sql` - SQLite database schema.
* `coverage.db` - SQLite database.

## Database Tables

### coverage

Canonical tool-aware coverage table.

Fields:

* endpoint
* parameter
* vulnerability_class
* tool_used - JSON list of reporting tools
* tested_status
* tested_at

Rows are unique by `(endpoint, parameter, vulnerability_class)`.

### tracking

Backward-compatible target-aware table used by existing integration code.

Fields:

* target
* endpoint
* parameter
* vulnerability_class
* tool_used - JSON list of reporting tools
* tested (0 = Not Tested, 1 = Tested)
* tested_at

### scan_history

Stores a snapshot of each scan.

Fields:

* target
* scan_time
* subdomains
* open_ports
* js_hashes

## Functions

* `initialize_database()` - Creates or migrates the database and tables.
* `mark_tested()` - Marks a test as completed and appends unique tool names.
* `get_untested()` - Returns tests that have not been completed.
* `add_scan_snapshot()` - Saves a scan snapshot.

## Tool Deduplication

`mark_tested(target, endpoint, parameter, vulnerability_class, tool_used)` appends tools without overwriting previous values.

Example:

```python
mark_tested("example.com", "/login", "username", "xss", "ffuf")
mark_tested("example.com", "/login", "username", "xss", "ffuf")
mark_tested("example.com", "/login", "username", "xss", "feroxbuster")
```

The stored `tool_used` value becomes:

```json
["ffuf", "feroxbuster"]
```
