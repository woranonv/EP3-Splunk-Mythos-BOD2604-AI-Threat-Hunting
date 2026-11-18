# Hunt telemetry and CIM mapping

The hunt templates only use accelerated CIM data models (`tstats summariesonly=t`), plus one raw-log template for sudo activity.
Any source that is CIM-compliant for these data models works; the lab used the sources below.

| Data model | Lab source (sourcetype) | Add-on / mapping | Used by |
|---|---|---|---|
| Web | Apache access logs (`access_combined`) | Eventtype + field aliases below | COV-1, IA-1, EXE-1, PER-1 |
| Authentication | Linux auth logs (`linux_secure`) | Splunk Add-on for Unix and Linux | COV-1, IA-2, PER-3, LM-1 |
| Change (accounts) | Linux auth logs (`linux_secure`: useradd, groupadd, usermod) | Splunk Add-on for Unix and Linux | COV-1, PER-2 |
| Network_Traffic | AWS VPC Flow Logs (`aws:cloudwatchlogs:vpcflow`) | Splunk Add-on for AWS | COV-1, LM-1, C2-1/EXF-1 |
| Endpoint.Processes | EDR (any CIM-mapped EDR) | Vendor add-on | COV-1, EXE-2 (a gap when the host has no EDR) |
| raw `linux_secure` | sudo lines | - | PE-1, pivot |

Hunt index in this lab: `bod_hunt`. In production, replace `index=bod_hunt` in `saved_searches/templates.py` with your indexes or a macro.

## Web mapping for `access_combined` (Settings > Event types / Fields)

Event type `bod_hunt_web_access`:

```
search = sourcetype=access_combined
tags   = web
```

Field alias `FIELDALIAS-access_combined_cim_web` on sourcetype `access_combined`:

```
clientip ASNEW src
host ASNEW dest
method ASNEW http_method
referer ASNEW http_referrer
uri ASNEW url
useragent ASNEW http_user_agent
```

`linux_secure` events need a standard syslog header (`Mon dd HH:MM:SS host process[pid]: ...`) so the Unix add-on extracts `dest`.

## Check the data models

```
| tstats summariesonly=t count from datamodel=Web where index=bod_hunt by sourcetype | eval dm="Web"
| append [| tstats summariesonly=t count from datamodel=Authentication where index=bod_hunt by sourcetype | eval dm="Authentication"]
| append [| tstats summariesonly=t count from datamodel=Change where index=bod_hunt by sourcetype | eval dm="Change"]
| append [| tstats summariesonly=t count from datamodel=Network_Traffic where index=bod_hunt by sourcetype | eval dm="Network_Traffic"]
```

Make sure the Web, Authentication, Change and Network_Traffic data models are accelerated and that their index allow-list includes the hunt index.
