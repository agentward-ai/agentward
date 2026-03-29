# Chain Analysis Results — MCP Server Audit (March 29, 2026)

## Method

Chain detection uses `agentward.scan.chains.detect_chains()`, which:

1. Builds "capability units" from the scan — typically one unit per server, or per-tool for servers with heterogeneous capabilities
2. Checks all ordered pairs (A→B ≠ B→A) against 9 source→sink patterns
3. Deduplicates by (source_name, target_name, description)

## Patterns Implemented

The 9 patterns in the current code (`agentward/scan/chains.py`):

| # | Source Type | Sink Type | Risk | Description |
|---|-----------|----------|------|-------------|
| 1 | email | browser | HIGH | Email content could leak via browsing |
| 2 | email | shell | CRITICAL | Email content could trigger code execution |
| 3 | browser | shell | CRITICAL | Web content could trigger code execution |
| 4 | browser | email | HIGH | Web content could trigger email actions |
| 5 | messaging | shell | CRITICAL | Chat messages could trigger code execution |
| 6 | messaging | browser | HIGH | Chat messages could leak via browsing |
| 7 | filesystem | shell | CRITICAL | File content could trigger code execution |
| 8 | database | shell | CRITICAL | Database content could trigger code execution |
| 9 | network | shell | CRITICAL | Network responses could trigger code execution |

Note: these are all source→sink patterns (data source to execution/action sink). The broader exfiltration and credential-leakage patterns described in some security literature are not implemented in this version of the analyzer.

## Results

**84 unit-to-unit capability pairings** (82 unique, 2 duplicates from units with multiple data-access types).

The chain analyzer breaks heterogeneous servers into per-tool "capability units" and keeps homogeneous or single-tool servers as a single server-name unit. Pairings are between units, not raw tools or raw servers.

- **75 cross-server** (source unit on one server, sink unit on another)
- **9 same-server** (both units on desktop-commander)

### Sink Distribution

The 84 pairings target two distinct sinks:

| Sink Tool | Sink Server | Count | Pattern |
|-----------|------------|------:|---------|
| `start_process` | desktop-commander | 62 | *→shell (patterns 2,3,5,7,8,9) |
| `browser_*` (22 tools) | playwright | 22 | messaging→browser (pattern 6) |

### Server-Level Summary

| Source Server | Sink Server | Pattern | Unit-Level Pairings |
|--------------|-------------|---------|--------------------:|
| playwright → | desktop-commander | browser/network→shell | 24 |
| slack → | playwright | messaging→browser | 22 |
| git → | desktop-commander | filesystem→shell | 12 |
| desktop-commander → | desktop-commander | filesystem→shell (same-server) | 9 |
| filesystem → | desktop-commander | filesystem→shell | 6 |
| sqlite → | desktop-commander | database→shell | 4 |
| github → | desktop-commander | filesystem/database→shell | 3 |
| fetch → | desktop-commander | network→shell | 1 |
| postgres → | desktop-commander | database→shell | 1 |
| slack → | desktop-commander | messaging→shell | 1 |
| memory → | desktop-commander | database→shell | 1 |
| | | **Total** | **84** |

Note: Some counts are higher than might be expected because one server pair can produce multiple unit-level pairings. The chain analyzer breaks heterogeneous servers into per-tool units, so a server with 22 browser-typed tools produces 22 pairings against a single shell sink. Servers with one tool or a single capability type (like slack, fetch, postgres) remain as a single server-name unit.

### Full Unit-to-Unit Pairings (84 lines, 82 unique)

Source unit → Sink unit. Same-server pairings annotated. Duplicates from multiple data-access types annotated. Unit names are tool names for heterogeneous servers, or server names for single-tool/homogeneous servers (e.g., `slack`, `fetch`, `postgres`).

```
browser_click → start_process                    (playwright → desktop-commander)
browser_close → start_process                    (playwright → desktop-commander)
browser_console_messages → start_process         (playwright → desktop-commander)
browser_drag → start_process                     (playwright → desktop-commander)
browser_evaluate → start_process                 (playwright → desktop-commander)
browser_file_upload → start_process              (playwright → desktop-commander) [via browser type]
browser_file_upload → start_process              (playwright → desktop-commander) [via filesystem type]
browser_fill_form → start_process                (playwright → desktop-commander)
browser_handle_dialog → start_process            (playwright → desktop-commander)
browser_hover → start_process                    (playwright → desktop-commander)
browser_install → start_process                  (playwright → desktop-commander)
browser_navigate → start_process                 (playwright → desktop-commander) [via browser type]
browser_navigate → start_process                 (playwright → desktop-commander) [via network type]
browser_navigate_back → start_process            (playwright → desktop-commander)
browser_network_requests → start_process         (playwright → desktop-commander)
browser_press_key → start_process                (playwright → desktop-commander)
browser_resize → start_process                   (playwright → desktop-commander)
browser_run_code → start_process                 (playwright → desktop-commander)
browser_select_option → start_process            (playwright → desktop-commander)
browser_snapshot → start_process                 (playwright → desktop-commander)
browser_tabs → start_process                     (playwright → desktop-commander)
browser_take_screenshot → start_process          (playwright → desktop-commander)
browser_type → start_process                     (playwright → desktop-commander)
browser_wait_for → start_process                 (playwright → desktop-commander)
create_directory → start_process                 (desktop-commander → desktop-commander) [same-server]
create_or_update_file → start_process            (github → desktop-commander)
create_table → start_process                     (sqlite → desktop-commander)
describe_table → start_process                   (sqlite → desktop-commander)
directory_tree → start_process                   (filesystem → desktop-commander)
edit_block → start_process                       (desktop-commander → desktop-commander) [same-server]
edit_file → start_process                        (filesystem → desktop-commander)
fetch → start_process                            (fetch → desktop-commander)
get_file_contents → start_process                (github → desktop-commander)
get_file_info → start_process                    (desktop-commander → desktop-commander) [same-server]
git_add → start_process                          (git → desktop-commander)
git_branch → start_process                       (git → desktop-commander)
git_checkout → start_process                     (git → desktop-commander)
git_commit → start_process                       (git → desktop-commander)
git_create_branch → start_process                (git → desktop-commander)
git_diff → start_process                         (git → desktop-commander)
git_diff_staged → start_process                  (git → desktop-commander)
git_diff_unstaged → start_process                (git → desktop-commander)
git_log → start_process                          (git → desktop-commander)
git_reset → start_process                        (git → desktop-commander)
git_show → start_process                         (git → desktop-commander)
git_status → start_process                       (git → desktop-commander)
list_directory → start_process                   (desktop-commander → desktop-commander) [same-server]
list_directory_with_sizes → start_process        (filesystem → desktop-commander)
move_file → start_process                        (desktop-commander → desktop-commander) [same-server]
postgres → start_process                         (postgres → desktop-commander)
read_file → start_process                        (desktop-commander → desktop-commander) [same-server]
read_media_file → start_process                  (filesystem → desktop-commander)
read_query → start_process                       (sqlite → desktop-commander)
read_text_file → start_process                   (filesystem → desktop-commander)
search_files → start_process                     (filesystem → desktop-commander)
search_nodes → start_process                     (memory → desktop-commander)
search_repositories → start_process              (github → desktop-commander)
slack → browser_click                            (slack → playwright)
slack → browser_close                            (slack → playwright)
slack → browser_console_messages                 (slack → playwright)
slack → browser_drag                             (slack → playwright)
slack → browser_evaluate                         (slack → playwright)
slack → browser_file_upload                      (slack → playwright)
slack → browser_fill_form                        (slack → playwright)
slack → browser_handle_dialog                    (slack → playwright)
slack → browser_hover                            (slack → playwright)
slack → browser_install                          (slack → playwright)
slack → browser_navigate                         (slack → playwright)
slack → browser_navigate_back                    (slack → playwright)
slack → browser_network_requests                 (slack → playwright)
slack → browser_press_key                        (slack → playwright)
slack → browser_resize                           (slack → playwright)
slack → browser_run_code                         (slack → playwright)
slack → browser_select_option                    (slack → playwright)
slack → browser_snapshot                         (slack → playwright)
slack → browser_tabs                             (slack → playwright)
slack → browser_take_screenshot                  (slack → playwright)
slack → browser_type                             (slack → playwright)
slack → browser_wait_for                         (slack → playwright)
slack → start_process                            (slack → desktop-commander)
start_search → start_process                     (desktop-commander → desktop-commander) [same-server]
write_file → start_process                       (desktop-commander → desktop-commander) [same-server]
write_pdf → start_process                        (desktop-commander → desktop-commander) [same-server]
write_query → start_process                      (sqlite → desktop-commander)
```

## Interpretation

The 84 pairings cluster around two sinks: desktop-commander's `start_process` (shell execution, 62 pairings) and playwright's browser tools (22 pairings from slack's messaging capability). This concentration is expected — desktop-commander is the only shell-execution server, and playwright is the only browser-automation server in this configuration.

Playwright's `browser_evaluate` and `browser_run_code` execute JavaScript in the browser context but are classified as `browser` data-access type, not `shell`. If the pattern set were expanded to treat browser JS execution as a shell-equivalent sink, additional pairings would appear. The current implementation is conservative.

These pairings represent *structural capability overlaps*, not demonstrated exploits. See the Limitations section in the main post.
