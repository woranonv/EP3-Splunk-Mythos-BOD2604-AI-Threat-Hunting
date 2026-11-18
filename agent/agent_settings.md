# Hunting agent - AI Toolkit Agent Launchpad 6.1 settings

| Setting | Value | Why |
|---|---|---|
| Agent name | `Hunting` | The dashboard calls `\| aiagent agent_name="Hunting"` |
| Description | Hypothesis-driven, MITRE ATT&CK aligned hunt and forensic triage for BOD 26-04 P1 + forensic hosts | |
| System prompt | [`system_prompt.txt`](system_prompt.txt) | Role, rules, workflow |
| LLM connection | OpenAI GPT (tested with gpt-5.2) | Best verdict accuracy and tool discipline in testing |
| Temperature | 0 | Repeatable verdicts |
| Max tokens | 50000 | A full hunt is ~12 tool steps plus the report |
| Reasoning | NONE (or LOW) | Reasoning-heavy settings tend to batch tool calls in parallel |
| Agent timeout | 600 s | A hunt takes 1-4 minutes |
| Max invocations per command | 10 | One row (one host) per dashboard run |

LLM connection (Connections > LLM):

| Setting | Value |
|---|---|
| Request timeout | 600 |
| Maximum result rows | 50 (the toolbox returns <= 10 rows per call) |
| Max tokens | 50000 or more |

## MCP connection

Connection `Splunk_cloud` (type MCP - Splunk) to the Splunk MCP Server 2.0 on the same stack, with a dedicated MCP token.
Add it to the agent with **only these read-only tools**:

- `splunk_run_query`
- `splunk_get_indexes`
- `splunk_get_metadata`
- `splunk_get_sourcetypes`
- `splunk_get_index_info`

## Skills (Agents > Agent skills)

Create each skill with its `description.txt` and `instructions.txt`, then add all four to the agent.

| Skill | Role |
|---|---|
| [VulnIntelProfile](skills/VulnIntelProfile/) | Reads CISA KEV + Vulnrichment + scanner data and builds the ATT&CK attack-path hypothesis |
| [ExploitationHunt](skills/ExploitationHunt/) | Coverage first, then tests each hypothesis step in attack order, chaining attacker IPs and new accounts |
| [HuntToolbox](skills/HuntToolbox/) | The call line for each saved-search template plus the guarded-pivot rules |
| [BOD2604TriageReport](skills/BOD2604TriageReport/) | Report format, verdict rules and audit trail |

Skills are plain-text instructions, not tools. The only tool that runs searches is `splunk_run_query`.
