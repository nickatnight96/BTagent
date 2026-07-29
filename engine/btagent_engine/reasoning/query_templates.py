"""Curated per-(technique, backend) hunt-query template library (#99).

Split out of :mod:`btagent_engine.reasoning.query_synth` so the node stays
readable while the library grows. Everything here is *data* — no imports
beyond the ``Backend`` enum, no I/O, no LLM.

Editing rules (enforced by ``engine/tests/test_query_synth_coverage.py``):

1. **Every executable query is count-capped.** SPL/CQL end in ``| head N``,
   KQL in ``| take N``, ES|QL in ``| LIMIT N``. Sigma is a rule, not a
   query, so it carries no cap. A clumsy execution must not be able to DoS
   the SIEM (NightWing EPIC-1 / EPIC-4).
2. **Dialects.** splunk = SPL, sentinel = KQL (Sentinel / Defender advanced
   hunting tables), elastic = ES|QL, crowdstrike = Falcon Event Search
   (``event_simpleName`` + SPL-ish pipeline), sigma = Sigma YAML.
3. **Honest gaps.** A technique only lists the backends whose telemetry can
   plausibly see it — e.g. email techniques carry no CrowdStrike template
   because Falcon has no mail-flow telemetry. An omitted backend falls back
   to the generic placeholder in ``query_synth._generic_query``, which is
   an honest "TODO" the analyst refines, not a fake detection.
4. **Field names are defaults, not gospel.** These are starting points for
   an analyst to edit against the org's real schema; the notes on every
   emitted :class:`~btagent_shared.types.hunt.Query` say so.
5. ``TECHNIQUE_NAMES`` must stay key-for-key in sync with ``QUERY_LIBRARY``
   (drift-locked by test).

Technique selection is driven by what the rest of the product actually
references: ``agents/btagent_agents/mitre/data/mitre_keywords.yaml`` (the
keyword mapper's technique universe) and the shipped hunt packs under
``engine/btagent_engine/hunting/packs/``.
"""

from __future__ import annotations

from btagent_shared.types.hunt import Backend

# ---------------------------------------------------------------------------
# Human-readable technique names (used in the notes on each emitted Query).
# ---------------------------------------------------------------------------

TECHNIQUE_NAMES: dict[str, str] = {
    # Initial access
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1133": "External Remote Services",
    "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    # Execution
    "T1047": "Windows Management Instrumentation",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1204.002": "User Execution: Malicious File",
    "T1648": "Serverless Execution",
    # Persistence
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1136": "Create Account",
    "T1505.003": "Server Software Component: Web Shell",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1556": "Modify Authentication Process",
    # Privilege escalation
    "T1068": "Exploitation for Privilege Escalation",
    "T1134": "Access Token Manipulation",
    "T1484.002": "Domain Policy Modification: Trust Modification",
    "T1548.002": "Abuse Elevation Control Mechanism: Bypass UAC",
    # Defense evasion
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1055": "Process Injection",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    # Credential access
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.003": "OS Credential Dumping: NTDS",
    "T1110": "Brute Force",
    "T1110.003": "Brute Force: Password Spraying",
    "T1528": "Steal Application Access Token",
    "T1550.001": "Use Alternate Authentication Material: Application Access Token",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
    "T1552": "Unsecured Credentials",
    "T1555": "Credentials from Password Stores",
    "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1606": "Forge Web Credentials",
    "T1621": "Multi-Factor Authentication Request Generation",
    # Discovery
    "T1046": "Network Service Discovery",
    "T1082": "System Information Discovery",
    "T1087.002": "Account Discovery: Domain Account",
    "T1580": "Cloud Infrastructure Discovery",
    # Lateral movement
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.004": "Remote Services: SSH",
    # Collection
    "T1114": "Email Collection",
    "T1530": "Data from Cloud Storage",
    "T1560": "Archive Collected Data",
    # Command and control
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1090.003": "Proxy: Multi-hop Proxy",
    "T1105": "Ingress Tool Transfer",
    # Exfiltration
    "T1041": "Exfiltration Over C2 Channel",
    "T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
    "T1537": "Transfer Data to Cloud Account",
    "T1567.002": "Exfiltration to Cloud Storage",
    # Impact
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1561": "Disk Wipe",
    # Containers
    "T1609": "Container Administration Command",
    "T1610": "Deploy Container",
    "T1611": "Escape to Host",
}


# ---------------------------------------------------------------------------
# The library itself.
# ---------------------------------------------------------------------------

QUERY_LIBRARY: dict[str, dict[Backend, str]] = {
    # ======================================================================
    # Initial access
    # ======================================================================
    "T1078": {
        Backend.SPLUNK: (
            "index=auth action=success | stats dc(src_ip) AS ips, count BY user "
            "| where ips > 3 | sort - ips | head 1000"
        ),
        Backend.SENTINEL: (
            "SigninLogs | where ResultType == 0 "
            "| summarize Ips=dcount(IPAddress), Countries=dcount(LocationDetails.countryOrRegion) "
            "by UserPrincipalName | where Ips > 3 or Countries > 1 | take 1000"
        ),
        Backend.ELASTIC: (
            'FROM logs-*.auth-* | WHERE event.outcome == "success" '
            "| STATS ips = COUNT_DISTINCT(source.ip) BY user.name "
            "| WHERE ips > 3 | SORT ips DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=UserLogon LogonType_decimal IN (2,10) "
            "| stats dc(RemoteAddressIP4) AS ips BY UserName | where ips > 3 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Valid Account Used From Unusual Sources\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: 4624, LogonType: [3, 10]}\n"
            "  condition: selection | count(IpAddress) by TargetUserName > 3"
        ),
    },
    "T1078.004": {  # Cloud Accounts
        Backend.SPLUNK: (
            'index=cloud sourcetype=aws:cloudtrail eventName="ConsoleLogin" '
            'errorMessage="*" | stats count by sourceIPAddress, userIdentity.userName '
            "| where count > 5 | head 1000"
        ),
        Backend.SENTINEL: (
            "SigninLogs | where ResultType != 0 | summarize FailedAttempts=count() "
            "by IPAddress, UserPrincipalName | where FailedAttempts > 5 | take 1000"
        ),
        Backend.ELASTIC: (
            'FROM logs-cloud.audit-* | WHERE event.outcome == "failure" AND cloud.provider IS NOT NULL '
            "| STATS attempts = COUNT(*) BY source.ip, user.name "
            "| WHERE attempts > 5 | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Suspicious Cloud Account Authentication\n"
            "logsource: {product: azure, service: signinlogs}\n"
            "detection:\n"
            "  selection: {ResultType: '50126'}\n"
            "  condition: selection | count() by IPAddress > 5"
        ),
    },
    "T1133": {
        Backend.SPLUNK: (
            "index=vpn OR index=auth (vendor_product=VPN OR app=rdp OR app=citrix) action=success "
            "| stats count BY user, src_ip, app | sort - count | head 1000"
        ),
        Backend.SENTINEL: (
            "SigninLogs | where AppDisplayName has_any ('VPN','Citrix','RDGateway','AnyConnect') "
            "| where ResultType == 0 | summarize count() by UserPrincipalName, IPAddress "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            'FROM logs-*.vpn-*, logs-*.auth-* | WHERE event.action == "logon" '
            'AND network.direction == "inbound" '
            "| STATS sessions = COUNT(*) BY user.name, source.ip | SORT sessions DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=UserLogon LogonType_decimal=10 RemoteAddressIP4=* "
            "| stats count BY UserName, RemoteAddressIP4, ComputerName | head 1000"
        ),
        Backend.SIGMA: (
            "title: External Remote Service Authentication\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: 4624, LogonType: 10}\n"
            "  condition: selection"
        ),
    },
    "T1189": {
        Backend.SPLUNK: (
            "index=proxy (http_user_agent=* AND url=*) status=200 "
            '(url="*.hta" OR url="*.jar" OR url="*.scr" OR url="*.iso" OR url="*.js") '
            "| stats count BY src_ip, user, url | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceNetworkEvents | where InitiatingProcessFileName in~ "
            "('chrome.exe','msedge.exe','firefox.exe') "
            "| where RemoteUrl has_any ('.hta','.jar','.scr','.iso') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.proxy-* | WHERE http.response.status_code == 200 "
            'AND url.path RLIKE ".*\\\\.(hta|jar|scr|iso|js)" '
            "| STATS hits = COUNT(*) BY source.ip, url.domain | SORT hits DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 ParentBaseFileName IN "
            "(chrome.exe, msedge.exe, firefox.exe) "
            "FileName IN (powershell.exe, cmd.exe, wscript.exe, mshta.exe) | head 1000"
        ),
        Backend.SIGMA: (
            "title: Browser Spawning Script Interpreter\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    ParentImage|endswith: ['\\chrome.exe','\\msedge.exe','\\firefox.exe']\n"
            "    Image|endswith: ['\\powershell.exe','\\cmd.exe','\\wscript.exe','\\mshta.exe']\n"
            "  condition: selection"
        ),
    },
    "T1190": {
        Backend.SPLUNK: (
            'index=web (status>=500 OR uri_path="*..*" OR uri_query="*union*select*") '
            "| stats count by src_ip, uri_path | head 1000"
        ),
        Backend.SENTINEL: (
            "W3CIISLog | where scStatus >= 500 or csUriQuery has_any ('union','select','..') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.web-* | WHERE http.response.status_code >= 500 "
            'OR url.query RLIKE "(?i).*(union.*select|\\\\.\\\\./).*" '
            "| STATS hits = COUNT(*) BY source.ip, url.path | SORT hits DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 ParentBaseFileName IN "
            "(w3wp.exe, httpd, nginx, java, tomcat9.exe) "
            "FileName IN (cmd.exe, powershell.exe, sh, bash, whoami.exe) | head 1000"
        ),
        Backend.SIGMA: (
            "title: Web Exploitation Attempt\n"
            "logsource: {category: webserver}\n"
            "detection:\n"
            "  selection: {sc_status: [500,501,502]}\n"
            "  condition: selection"
        ),
    },
    "T1195": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=1 "
            '(process_path="*\\\\AppData\\\\*" OR signature_status!="signed") '
            'parent_process_name IN ("msiexec.exe","setup.exe","update.exe") '
            "| stats count BY host, process_name, parent_process_name | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where InitiatingProcessFileName has_any "
            "('msiexec.exe','setup.exe','update.exe','updater.exe') "
            "| where ProcessCommandLine has_any ('http://','https://','-enc','Invoke-WebRequest') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.parent.name IN ("msiexec.exe","setup.exe","updater.exe") '
            "AND process.code_signature.trusted == false "
            "| KEEP @timestamp, host.name, process.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 ParentBaseFileName IN (msiexec.exe, setup.exe, updater.exe) "
            "| stats count BY ComputerName, FileName, CommandLine | head 1000"
        ),
    },
    "T1566.001": {  # Spearphishing Attachment
        Backend.SPLUNK: (
            'index=email (attachment_type="*.docm" OR attachment_type="*.xlsm" OR '
            'attachment_type="*.zip") | stats count by sender, recipient, attachment_name '
            "| head 1000"
        ),
        Backend.SENTINEL: (
            "EmailAttachmentInfo | where FileType in ('docm','xlsm','zip','iso') "
            "| join EmailEvents on NetworkMessageId | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.email-* "
            'WHERE file.extension IN ("docm","xlsm","zip","iso","img","lnk") '
            "| STATS messages = COUNT(*) BY source.user.email, file.name "
            "| SORT messages DESC | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Suspicious Email Attachment\n"
            "logsource: {category: email}\n"
            "detection:\n"
            "  selection: {attachment_extension: ['docm','xlsm','iso','zip']}\n"
            "  condition: selection"
        ),
    },
    "T1566.002": {
        Backend.SPLUNK: (
            "index=email url=* | search NOT url IN (allowlisted_domains) "
            "| stats count BY sender, recipient, url | sort - count | head 1000"
        ),
        Backend.SENTINEL: (
            "UrlClickEvents | where ActionType == 'ClickAllowed' "
            "| join kind=inner EmailEvents on NetworkMessageId "
            "| project Timestamp, AccountUpn, Url, SenderFromAddress | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.email-* | WHERE url.full IS NOT NULL "
            "| STATS clicks = COUNT(*) BY user.email, url.domain "
            "| SORT clicks DESC | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Phishing Link Click\n"
            "logsource: {category: email}\n"
            "detection:\n"
            "  selection: {action: 'url_click', verdict: ['suspicious','malicious']}\n"
            "  condition: selection"
        ),
    },
    # ======================================================================
    # Execution
    # ======================================================================
    "T1047": {
        Backend.SPLUNK: (
            'index=endpoint EventCode=4688 (process_name="wmic.exe" OR parent_process_name="WmiPrvSE.exe") '
            '(CommandLine="*process call create*" OR CommandLine="*/node:*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName =~ 'wmic.exe' "
            "or InitiatingProcessFileName =~ 'WmiPrvSE.exe' "
            "| where ProcessCommandLine has_any ('process call create','/node:') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name == "wmic.exe" OR process.parent.name == "WmiPrvSE.exe" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 (FileName=wmic.exe OR ParentBaseFileName=WmiPrvSE.exe) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: WMI Remote Process Creation\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\wmic.exe'\n"
            "    CommandLine|contains: ['process call create','/node:']\n"
            "  condition: selection"
        ),
    },
    "T1053.005": {
        Backend.SPLUNK: (
            "index=endpoint (EventCode=4698 OR EventCode=4702 OR "
            '(EventCode=4688 process_name="schtasks.exe" CommandLine="*/create*")) '
            "| stats count BY host, user, TaskName, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName =~ 'schtasks.exe' "
            "| where ProcessCommandLine has '/create' "
            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name == "schtasks.exe" AND process.command_line LIKE "*/create*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName IN (ScheduledTaskRegistered, ProcessRollup2) "
            "(FileName=schtasks.exe OR TaskName=*) CommandLine=*create* "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Scheduled Task Creation\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\schtasks.exe'\n"
            "    CommandLine|contains: '/create'\n"
            "  condition: selection"
        ),
    },
    "T1059.001": {  # PowerShell
        Backend.SPLUNK: (
            'index=endpoint EventCode=4688 (process_name="powershell.exe" OR '
            'process_name="pwsh.exe") (CommandLine="*-EncodedCommand*" OR '
            'CommandLine="*-enc*" OR CommandLine="*FromBase64String*") '
            "| head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName in~ ('powershell.exe','pwsh.exe') "
            "| where ProcessCommandLine has_any ('-EncodedCommand','-enc','FromBase64String') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name IN ("powershell.exe","pwsh.exe") '
            'AND process.command_line RLIKE "(?i).*(-enc|-encodedcommand|frombase64string).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 (FileName=powershell.exe OR FileName=pwsh.exe) "
            "CommandLine=*EncodedCommand* | head 1000"
        ),
        Backend.SIGMA: (
            "title: Encoded PowerShell Execution\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: ['\\powershell.exe','\\pwsh.exe']\n"
            "    CommandLine|contains: ['-EncodedCommand','-enc','FromBase64String']\n"
            "  condition: selection"
        ),
    },
    "T1059.003": {
        Backend.SPLUNK: (
            'index=endpoint EventCode=4688 process_name="cmd.exe" '
            '(CommandLine="*/c *" OR CommandLine="*&&*" OR CommandLine="*^*") '
            'parent_process_name!="explorer.exe" '
            "| stats count BY host, user, parent_process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName =~ 'cmd.exe' "
            "| where InitiatingProcessFileName !in~ ('explorer.exe','cmd.exe') "
            "| where ProcessCommandLine has_any ('/c ','&&','^') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name == "cmd.exe" AND process.parent.name != "explorer.exe" '
            "| KEEP @timestamp, host.name, process.parent.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 FileName=cmd.exe ParentBaseFileName!=explorer.exe "
            "| stats count BY ComputerName, ParentBaseFileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Suspicious Windows Command Shell Execution\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\cmd.exe'\n"
            "    CommandLine|contains: ['/c ','&&']\n"
            "  filter:\n"
            "    ParentImage|endswith: '\\explorer.exe'\n"
            "  condition: selection and not filter"
        ),
    },
    "T1059.004": {
        Backend.SPLUNK: (
            'index=linux (process_name="bash" OR process_name="sh" OR process_name="zsh") '
            '(CommandLine="*curl *|*sh*" OR CommandLine="*wget *|*sh*" OR CommandLine="*/dev/tcp/*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where DeviceType == 'Server' or InitiatingProcessFileName in~ "
            "('bash','sh','zsh') "
            "| where ProcessCommandLine has_any ('/dev/tcp/','curl','wget','base64 -d') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name IN ("bash","sh","zsh","dash") '
            'AND process.command_line RLIKE ".*(/dev/tcp/|curl .*\\\\| *(ba)?sh|base64 -d).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_platform=Lin event_simpleName=ProcessRollup2 FileName IN (bash, sh, zsh) "
            "CommandLine=*/dev/tcp/* | stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Suspicious Unix Shell Execution\n"
            "logsource: {category: process_creation, product: linux}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: ['/bash','/sh','/zsh']\n"
            "    CommandLine|contains: ['/dev/tcp/','base64 -d','curl ']\n"
            "  condition: selection"
        ),
    },
    "T1059.005": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(process_name="wscript.exe" OR process_name="cscript.exe") '
            '(CommandLine="*.vbs*" OR CommandLine="*.vbe*" OR CommandLine="*.wsf*") '
            "| stats count BY host, user, parent_process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName in~ ('wscript.exe','cscript.exe') "
            "| where ProcessCommandLine has_any ('.vbs','.vbe','.wsf','.js') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name IN ("wscript.exe","cscript.exe") '
            'AND process.command_line RLIKE "(?i).*\\\\.(vbs|vbe|wsf|js).*" '
            "| KEEP @timestamp, host.name, process.parent.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 FileName IN (wscript.exe, cscript.exe) "
            "| stats count BY ComputerName, ParentBaseFileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: VBScript Execution Via WScript/CScript\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: ['\\wscript.exe','\\cscript.exe']\n"
            "    CommandLine|contains: ['.vbs','.vbe','.wsf']\n"
            "  condition: selection"
        ),
    },
    "T1204.002": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            'parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe") '
            'process_name IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","rundll32.exe") '
            "| stats count BY host, user, parent_process_name, process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where InitiatingProcessFileName in~ "
            "('winword.exe','excel.exe','powerpnt.exe','outlook.exe','acrord32.exe') "
            "| where FileName in~ ('cmd.exe','powershell.exe','wscript.exe','mshta.exe','rundll32.exe') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.parent.name IN ("winword.exe","excel.exe","outlook.exe","acrord32.exe") '
            'AND process.name IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe") '
            "| KEEP @timestamp, host.name, process.parent.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "ParentBaseFileName IN (winword.exe, excel.exe, outlook.exe, acrord32.exe) "
            "FileName IN (cmd.exe, powershell.exe, wscript.exe, mshta.exe) | head 1000"
        ),
        Backend.SIGMA: (
            "title: Office Application Spawning Script Interpreter\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    ParentImage|endswith: ['\\winword.exe','\\excel.exe','\\outlook.exe']\n"
            "    Image|endswith: ['\\cmd.exe','\\powershell.exe','\\wscript.exe','\\mshta.exe']\n"
            "  condition: selection"
        ),
    },
    "T1648": {
        Backend.SPLUNK: (
            "index=cloud sourcetype=aws:cloudtrail "
            'eventName IN ("CreateFunction20150331","UpdateFunctionCode20150331v2","Invoke") '
            "| stats count BY userIdentity.arn, sourceIPAddress, requestParameters.functionName "
            "| head 1000"
        ),
        Backend.SENTINEL: (
            "AzureActivity | where OperationNameValue has_any "
            "('MICROSOFT.WEB/SITES/FUNCTIONS/WRITE','MICROSOFT.LOGIC/WORKFLOWS/WRITE') "
            "| summarize count() by Caller, CallerIpAddress, ResourceId | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-aws.cloudtrail-* "
            'WHERE event.action IN ("CreateFunction20150331","UpdateFunctionCode20150331v2") '
            "| STATS calls = COUNT(*) BY user.name, source.ip | SORT calls DESC | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Serverless Function Created Or Modified\n"
            "logsource: {product: aws, service: cloudtrail}\n"
            "detection:\n"
            "  selection:\n"
            "    eventName: ['CreateFunction20150331','UpdateFunctionCode20150331v2']\n"
            "  condition: selection"
        ),
    },
    # ======================================================================
    # Persistence
    # ======================================================================
    "T1098": {
        Backend.SPLUNK: (
            "index=auth (EventCode=4728 OR EventCode=4732 OR EventCode=4756) "
            "| stats count BY user, member, group_name, host | head 1000"
        ),
        Backend.SENTINEL: (
            "AuditLogs | where OperationName has_any "
            "('Add member to role','Update user','Add owner to application') "
            "| project TimeGenerated, OperationName, InitiatedBy, TargetResources | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.audit-* "
            'WHERE event.action IN ("added-member-to-group","user-account-modified") '
            "| STATS changes = COUNT(*) BY user.name, user.target.name "
            "| SORT changes DESC | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Privileged Group Membership Change\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: [4728, 4732, 4756]}\n"
            "  condition: selection"
        ),
    },
    "T1098.001": {
        Backend.SPLUNK: (
            "index=cloud sourcetype=aws:cloudtrail "
            'eventName IN ("CreateAccessKey","CreateLoginProfile","UpdateAccessKey") '
            "| stats count BY userIdentity.arn, requestParameters.userName, sourceIPAddress "
            "| head 1000"
        ),
        Backend.SENTINEL: (
            "AuditLogs | where OperationName has_any "
            "('Add service principal credentials','Update application - Certificates and secrets') "
            "| project TimeGenerated, InitiatedBy, TargetResources, Result | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-aws.cloudtrail-* "
            'WHERE event.action IN ("CreateAccessKey","CreateLoginProfile") '
            "| KEEP @timestamp, user.name, source.ip, aws.cloudtrail.request_parameters | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Additional Cloud Credential Added\n"
            "logsource: {product: azure, service: auditlogs}\n"
            "detection:\n"
            "  selection:\n"
            "    OperationName: ['Add service principal credentials','Update application']\n"
            "  condition: selection"
        ),
    },
    "T1136": {
        Backend.SPLUNK: (
            "index=auth (EventCode=4720 OR EventCode=4722) "
            "OR (index=endpoint EventCode=4688 "
            'CommandLine="*net user*/add*") '
            "| stats count BY host, user, TargetUserName, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "union DeviceProcessEvents, SecurityEvent "
            "| where ProcessCommandLine has 'net user' and ProcessCommandLine has '/add' "
            "or EventID == 4720 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-*, logs-system.security-* "
            'WHERE event.code == "4720" OR process.command_line LIKE "*net user*/add*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName IN (UserAccountCreated, ProcessRollup2) "
            "CommandLine=*net*user*/add* | stats count BY ComputerName, UserName, CommandLine "
            "| head 1000"
        ),
        Backend.SIGMA: (
            "title: Local Account Created\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: 4720}\n"
            "  condition: selection"
        ),
    },
    "T1505.003": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            'parent_process_name IN ("w3wp.exe","httpd.exe","nginx.exe","tomcat.exe","php-fpm") '
            'process_name IN ("cmd.exe","powershell.exe","sh","bash","whoami.exe") '
            "| stats count BY host, parent_process_name, process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where InitiatingProcessFileName in~ "
            "('w3wp.exe','httpd.exe','nginx.exe','tomcat.exe','php-fpm') "
            "| where FileName in~ ('cmd.exe','powershell.exe','sh','bash','whoami.exe') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.parent.name IN ("w3wp.exe","httpd","nginx","java") '
            'AND process.name IN ("cmd.exe","powershell.exe","sh","bash","whoami") '
            "| KEEP @timestamp, host.name, process.parent.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 ParentBaseFileName IN (w3wp.exe, httpd, nginx, java) "
            "FileName IN (cmd.exe, powershell.exe, sh, bash, whoami.exe) "
            "| stats count BY ComputerName, ParentBaseFileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Web Server Spawning Shell (Web Shell)\n"
            "logsource: {category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    ParentImage|endswith: ['\\w3wp.exe','\\httpd.exe','\\nginx.exe','/httpd','/nginx']\n"
            "    Image|endswith: ['\\cmd.exe','\\powershell.exe','/sh','/bash']\n"
            "  condition: selection"
        ),
    },
    "T1547.001": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=13 "
            '(registry_path="*\\\\CurrentVersion\\\\Run*" OR registry_path="*\\\\RunOnce*") '
            "| stats count BY host, user, registry_path, registry_value_data | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceRegistryEvents | where RegistryKey has_any "
            "(@'CurrentVersion\\Run', @'CurrentVersion\\RunOnce') "
            "| where ActionType in ('RegistryValueSet','RegistryKeyCreated') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.registry-* "
            'WHERE registry.path RLIKE "(?i).*currentversion\\\\\\\\run(once)?\\\\\\\\.*" '
            "| KEEP @timestamp, host.name, user.name, registry.path, registry.data.strings "
            "| LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=AsepValueUpdate "
            "RegObjectName=*CurrentVersion\\Run* "
            "| stats count BY ComputerName, UserName, RegValueName | head 1000"
        ),
        Backend.SIGMA: (
            "title: Run Key Persistence\n"
            "logsource: {category: registry_set, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    TargetObject|contains: ['\\CurrentVersion\\Run\\','\\CurrentVersion\\RunOnce\\']\n"
            "  condition: selection"
        ),
    },
    "T1556": {
        Backend.SPLUNK: (
            "index=auth (EventCode=4657 registry_path=*Lsa* ) OR "
            '(index=cloud eventName IN ("SetSecurityPolicy","UpdateAuthenticationMethod")) '
            "| stats count BY host, user, object | head 1000"
        ),
        Backend.SENTINEL: (
            "AuditLogs | where OperationName has_any "
            "('Update authentication methods policy','Disable Strong Authentication','Set federation settings') "
            "| project TimeGenerated, OperationName, InitiatedBy, TargetResources | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.audit-* "
            'WHERE event.action RLIKE "(?i).*(authentication.?(policy|method)|federation).*" '
            "| STATS changes = COUNT(*) BY user.name, event.action | SORT changes DESC | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Authentication Policy Modified\n"
            "logsource: {product: azure, service: auditlogs}\n"
            "detection:\n"
            "  selection:\n"
            "    OperationName|contains: ['authentication method','federation settings']\n"
            "  condition: selection"
        ),
    },
    # ======================================================================
    # Privilege escalation
    # ======================================================================
    "T1068": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            'parent_process_name IN ("services.exe","spoolsv.exe","print.exe","lsass.exe") '
            'process_name IN ("cmd.exe","powershell.exe","rundll32.exe") '
            "| stats count BY host, parent_process_name, process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where InitiatingProcessFileName in~ "
            "('spoolsv.exe','services.exe','print.exe') "
            "| where ProcessIntegrityLevel in ('High','System') "
            "| where InitiatingProcessIntegrityLevel !in ('High','System') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.parent.name IN ("spoolsv.exe","services.exe","print.exe") '
            'AND process.name IN ("cmd.exe","powershell.exe","rundll32.exe") '
            "| KEEP @timestamp, host.name, process.parent.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 ParentBaseFileName IN (spoolsv.exe, services.exe) "
            "FileName IN (cmd.exe, powershell.exe, rundll32.exe) "
            "| stats count BY ComputerName, ParentBaseFileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Privileged Service Spawning Shell\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    ParentImage|endswith: ['\\spoolsv.exe','\\services.exe']\n"
            "    Image|endswith: ['\\cmd.exe','\\powershell.exe','\\rundll32.exe']\n"
            "  condition: selection"
        ),
    },
    "T1134": {
        Backend.SPLUNK: (
            "index=endpoint (EventCode=4672 OR EventCode=4624) LogonType=9 "
            'OR (EventCode=4688 CommandLine="*runas*/netonly*") '
            "| stats count BY host, user, LogonType, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "SecurityEvent | where EventID == 4624 and LogonType == 9 "
            "| summarize count() by Computer, TargetUserName, SubjectUserName | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-system.security-* "
            'WHERE event.code == "4624" AND winlog.event_data.LogonType == "9" '
            "| KEEP @timestamp, host.name, user.name, winlog.event_data.SubjectUserName "
            "| LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 (CommandLine=*runas*/netonly* OR "
            "TokenType_decimal=2) | stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Token Manipulation Via NewCredentials Logon\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: 4624, LogonType: 9}\n"
            "  condition: selection"
        ),
    },
    "T1484.002": {
        Backend.SPLUNK: (
            'index=cloud (eventName="Set-DomainAuthentication" OR eventName="AddDomain" '
            'OR eventName="UpdateDomain") '
            "| stats count BY userIdentity.arn, sourceIPAddress, requestParameters | head 1000"
        ),
        Backend.SENTINEL: (
            "AuditLogs | where OperationName has_any "
            "('Set domain authentication','Set federation settings on domain','Add unverified domain') "
            "| project TimeGenerated, OperationName, InitiatedBy, TargetResources | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.audit-* "
            'WHERE event.action RLIKE "(?i).*(domain authentication|federation settings|add domain).*" '
            "| KEEP @timestamp, user.name, event.action, source.ip | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Federation Trust Modified\n"
            "logsource: {product: azure, service: auditlogs}\n"
            "detection:\n"
            "  selection:\n"
            "    OperationName|contains: ['Set domain authentication','Set federation settings']\n"
            "  condition: selection"
        ),
    },
    "T1548.002": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(process_name IN ("fodhelper.exe","computerdefaults.exe","sdclt.exe","eventvwr.exe")) '
            'child_process_name IN ("cmd.exe","powershell.exe") '
            "| stats count BY host, user, process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where InitiatingProcessFileName in~ "
            "('fodhelper.exe','computerdefaults.exe','sdclt.exe','eventvwr.exe') "
            "| where ProcessIntegrityLevel in ('High','System') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.parent.name IN ("fodhelper.exe","computerdefaults.exe","eventvwr.exe") '
            "| KEEP @timestamp, host.name, process.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "ParentBaseFileName IN (fodhelper.exe, computerdefaults.exe, eventvwr.exe, sdclt.exe) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: UAC Bypass Via Auto-Elevating Binary\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    ParentImage|endswith: ['\\fodhelper.exe','\\computerdefaults.exe','\\eventvwr.exe']\n"
            "  condition: selection"
        ),
    },
    # ======================================================================
    # Defense evasion
    # ======================================================================
    "T1027": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*FromBase64String*" OR CommandLine="*[Convert]::*" OR '
            'CommandLine="*-join*char*" OR CommandLine="*certutil*-decode*") '
            "| stats count BY host, user, process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('FromBase64String','[Convert]::','-join','certutil -decode','^') "
            "| where strlen(ProcessCommandLine) > 300 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(frombase64string|certutil.*-decode|\\\\[convert\\\\]::).*" '
            "| KEEP @timestamp, host.name, process.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "(CommandLine=*FromBase64String* OR CommandLine=*certutil*decode*) "
            "| stats count BY ComputerName, FileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Encoded Or Obfuscated Command Line\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['FromBase64String','certutil -decode','[Convert]::']\n"
            "  condition: selection"
        ),
    },
    "T1036": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            'process_name IN ("svchost.exe","lsass.exe","services.exe","csrss.exe") '
            'process_path!="C:\\\\Windows\\\\System32\\\\*" '
            "| stats count BY host, process_name, process_path | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName in~ "
            "('svchost.exe','lsass.exe','services.exe','csrss.exe') "
            "| where not (FolderPath startswith @'C:\\Windows\\System32') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name IN ("svchost.exe","lsass.exe","services.exe") '
            'AND NOT process.executable RLIKE "(?i)c:\\\\\\\\windows\\\\\\\\system32\\\\\\\\.*" '
            "| KEEP @timestamp, host.name, process.name, process.executable | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 FileName IN (svchost.exe, lsass.exe, services.exe) "
            "ImageFileName!=*\\Windows\\System32\\* "
            "| stats count BY ComputerName, FileName, ImageFileName | head 1000"
        ),
        Backend.SIGMA: (
            "title: System Binary Running From Unexpected Path\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: ['\\svchost.exe','\\lsass.exe','\\services.exe']\n"
            "  filter:\n"
            "    Image|startswith: 'C:\\Windows\\System32\\'\n"
            "  condition: selection and not filter"
        ),
    },
    "T1055": {
        Backend.SPLUNK: (
            "index=endpoint (EventCode=8 OR EventCode=10) "
            'target_process_name IN ("lsass.exe","explorer.exe","svchost.exe","winlogon.exe") '
            "| stats count BY host, source_process_name, target_process_name, GrantedAccess "
            "| head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceEvents | where ActionType in ('CreateRemoteThreadApiCall','ProcessInjection') "
            "| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, AdditionalFields "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.api-* "
            'WHERE process.Ext.api.name IN ("CreateRemoteThread","WriteProcessMemory","QueueUserAPC") '
            "| STATS calls = COUNT(*) BY host.name, process.name, process.Ext.api.name "
            "| SORT calls DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName IN (CreateRemoteThread, InjectedThread) "
            "| stats count BY ComputerName, SourceFileName, TargetFileName | head 1000"
        ),
        Backend.SIGMA: (
            "title: Remote Thread Injection\n"
            "logsource: {category: create_remote_thread, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    TargetImage|endswith: ['\\lsass.exe','\\explorer.exe','\\svchost.exe']\n"
            "  condition: selection"
        ),
    },
    "T1070.001": {
        Backend.SPLUNK: (
            "index=endpoint (EventCode=1102 OR EventCode=104) OR "
            '(EventCode=4688 CommandLine="*wevtutil*cl*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "union SecurityEvent, DeviceProcessEvents "
            "| where EventID == 1102 or ProcessCommandLine has_any ('wevtutil cl','Clear-EventLog') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-system.security-*, logs-endpoint.events.process-* "
            'WHERE event.code IN ("1102","104") OR process.command_line LIKE "*wevtutil*cl*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 (CommandLine=*wevtutil*cl* OR CommandLine=*Clear-EventLog*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Windows Event Log Cleared\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: 1102}\n"
            "  condition: selection"
        ),
    },
    "T1140": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*certutil*-decode*" OR CommandLine="*base64 -d*" OR '
            'CommandLine="*openssl*enc*-d*") '
            "| stats count BY host, user, process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('certutil -decode','base64 -d','openssl enc -d','FromBase64String') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(certutil.*-decode|base64 -d|openssl enc -d).*" '
            "| KEEP @timestamp, host.name, process.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 (CommandLine=*certutil*decode* OR CommandLine=*base64*-d*) "
            "| stats count BY ComputerName, FileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Local Payload Decoding\n"
            "logsource: {category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['certutil -decode','base64 -d','openssl enc -d']\n"
            "  condition: selection"
        ),
    },
    "T1218.005": {
        Backend.SPLUNK: (
            'index=endpoint EventCode=4688 process_name="mshta.exe" '
            '(CommandLine="*http*" OR CommandLine="*javascript:*" OR CommandLine="*vbscript:*") '
            "| stats count BY host, user, parent_process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName =~ 'mshta.exe' "
            "| where ProcessCommandLine has_any ('http','javascript:','vbscript:') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name == "mshta.exe" '
            'AND process.command_line RLIKE "(?i).*(http|javascript:|vbscript:).*" '
            "| KEEP @timestamp, host.name, process.parent.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 FileName=mshta.exe "
            "(CommandLine=*http* OR CommandLine=*script:*) "
            "| stats count BY ComputerName, ParentBaseFileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Mshta Remote Payload Execution\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\mshta.exe'\n"
            "    CommandLine|contains: ['http','javascript:','vbscript:']\n"
            "  condition: selection"
        ),
    },
    "T1218.010": {
        Backend.SPLUNK: (
            'index=endpoint EventCode=4688 process_name="regsvr32.exe" '
            '(CommandLine="*/i:*" OR CommandLine="*scrobj.dll*" OR CommandLine="*http*") '
            "| stats count BY host, user, parent_process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName =~ 'regsvr32.exe' "
            "| where ProcessCommandLine has_any ('/i:','scrobj.dll','http') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name == "regsvr32.exe" '
            'AND process.command_line RLIKE "(?i).*(/i:|scrobj\\\\.dll|http).*" '
            "| KEEP @timestamp, host.name, process.parent.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 FileName=regsvr32.exe "
            "(CommandLine=*scrobj.dll* OR CommandLine=*/i:*) "
            "| stats count BY ComputerName, ParentBaseFileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Regsvr32 Squiblydoo Execution\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\regsvr32.exe'\n"
            "    CommandLine|contains: ['/i:','scrobj.dll']\n"
            "  condition: selection"
        ),
    },
    "T1218.011": {
        Backend.SPLUNK: (
            'index=endpoint EventCode=4688 process_name="rundll32.exe" '
            '(CommandLine="*javascript:*" OR CommandLine="*,#1*" OR CommandLine="*AppData*") '
            "| stats count BY host, user, parent_process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName =~ 'rundll32.exe' "
            "| where ProcessCommandLine has_any ('javascript:',',#1','AppData','Temp') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name == "rundll32.exe" '
            'AND process.command_line RLIKE "(?i).*(javascript:|,#[0-9]|appdata|\\\\\\\\temp\\\\\\\\).*" '
            "| KEEP @timestamp, host.name, process.parent.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 FileName=rundll32.exe "
            "(CommandLine=*javascript:* OR CommandLine=*,#1* OR CommandLine=*AppData*) "
            "| stats count BY ComputerName, ParentBaseFileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Suspicious Rundll32 Execution\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\rundll32.exe'\n"
            "    CommandLine|contains: ['javascript:',',#1','\\AppData\\']\n"
            "  condition: selection"
        ),
    },
    "T1562.001": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*Set-MpPreference*Disable*" OR CommandLine="*sc*stop*Sense*" OR '
            'CommandLine="*netsh*advfirewall*off*" OR CommandLine="*wmic*shadowcopy*delete*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('Set-MpPreference -Disable','sc stop Sense','sc stop WinDefend','advfirewall set') "
            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(set-mppreference .*disable|sc stop (sense|windefend)|advfirewall set).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "(CommandLine=*Set-MpPreference*Disable* OR CommandLine=*sc*stop*Sense* "
            "OR CommandLine=*advfirewall*off*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Security Tooling Disabled\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['Set-MpPreference -Disable','sc stop WinDefend','advfirewall set']\n"
            "  condition: selection"
        ),
    },
    # ======================================================================
    # Credential access
    # ======================================================================
    "T1003.001": {
        Backend.SPLUNK: (
            'index=endpoint EventCode=10 target_process_name="lsass.exe" '
            '(GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1fffff") '
            "| stats count BY host, source_process_name, GrantedAccess | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceEvents | where ActionType == 'OpenProcessApiCall' "
            "| where FileName =~ 'lsass.exe' "
            "| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.api-* "
            'WHERE process.Ext.api.name == "OpenProcess" AND Target.process.name == "lsass.exe" '
            "| STATS opens = COUNT(*) BY host.name, process.name | SORT opens DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName IN (ProcessRollup2, SuspiciousDumpOfLsass) "
            "(TargetFileName=*lsass* OR CommandLine=*lsass*) "
            "| stats count BY ComputerName, FileName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: LSASS Memory Access\n"
            "logsource: {category: process_access, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    TargetImage|endswith: '\\lsass.exe'\n"
            "    GrantedAccess: ['0x1010','0x1410','0x1FFFFF']\n"
            "  condition: selection"
        ),
    },
    "T1003.003": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*ntdsutil*ifm*" OR CommandLine="*vssadmin*create*shadow*" OR '
            'CommandLine="*ntds.dit*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('ntdsutil','ntds.dit','vssadmin create shadow','diskshadow') "
            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(ntdsutil|ntds\\\\.dit|vssadmin create shadow).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "(CommandLine=*ntdsutil* OR CommandLine=*ntds.dit* OR CommandLine=*vssadmin*shadow*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: NTDS.dit Extraction\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['ntdsutil','ntds.dit','vssadmin create shadow']\n"
            "  condition: selection"
        ),
    },
    "T1110": {  # Brute Force
        Backend.SPLUNK: (
            "index=auth action=failure | stats count by src_ip, user | where count > 10 | head 1000"
        ),
        Backend.SENTINEL: (
            "SecurityEvent | where EventID == 4625 | summarize Failures=count() "
            "by IpAddress, Account | where Failures > 10 | take 1000"
        ),
        Backend.ELASTIC: (
            'FROM logs-*.auth-* | WHERE event.outcome == "failure" '
            "| STATS failures = COUNT(*) BY source.ip, user.name "
            "| WHERE failures > 10 | SORT failures DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=UserLogonFailed | stats count by RemoteAddressIP4, UserName "
            "| where count > 10 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Brute Force Authentication\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: 4625}\n"
            "  condition: selection | count() by IpAddress > 10"
        ),
    },
    "T1110.003": {
        Backend.SPLUNK: (
            "index=auth action=failure | stats dc(user) AS users, count BY src_ip "
            "| where users > 20 AND count < users * 3 | sort - users | head 1000"
        ),
        Backend.SENTINEL: (
            "SigninLogs | where ResultType in ('50126','50053') "
            "| summarize Users=dcount(UserPrincipalName), Attempts=count() by IPAddress "
            "| where Users > 20 | take 1000"
        ),
        Backend.ELASTIC: (
            'FROM logs-*.auth-* | WHERE event.outcome == "failure" '
            "| STATS users = COUNT_DISTINCT(user.name), attempts = COUNT(*) BY source.ip "
            "| WHERE users > 20 | SORT users DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=UserLogonFailed | stats dc(UserName) AS users BY RemoteAddressIP4 "
            "| where users > 20 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Password Spraying\n"
            "logsource: {product: azure, service: signinlogs}\n"
            "detection:\n"
            "  selection: {ResultType: ['50126','50053']}\n"
            "  condition: selection | count(UserPrincipalName) by IPAddress > 20"
        ),
    },
    "T1528": {
        Backend.SPLUNK: (
            'index=cloud (eventName="Consent to application" OR eventName="Add OAuth2PermissionGrant") '
            "| stats count BY user, app_display_name, scope, sourceIPAddress | head 1000"
        ),
        Backend.SENTINEL: (
            "AuditLogs | where OperationName has_any "
            "('Consent to application','Add delegated permission grant','Add app role assignment') "
            "| project TimeGenerated, InitiatedBy, TargetResources, Result | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.audit-* "
            'WHERE event.action RLIKE "(?i).*(consent to application|permission grant).*" '
            "| KEEP @timestamp, user.name, event.action, source.ip | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: OAuth Application Consent Granted\n"
            "logsource: {product: azure, service: auditlogs}\n"
            "detection:\n"
            "  selection:\n"
            "    OperationName: ['Consent to application','Add delegated permission grant']\n"
            "  condition: selection"
        ),
    },
    "T1550.001": {
        Backend.SPLUNK: (
            "index=cloud (auth_type=token OR eventType=app.oauth2.token.grant) "
            "| stats dc(sourceIPAddress) AS ips, count BY app_display_name, user "
            "| where ips > 2 | head 1000"
        ),
        Backend.SENTINEL: (
            "AADNonInteractiveUserSignInLogs | where ResultType == 0 "
            "| summarize Ips=dcount(IPAddress), Apps=make_set(AppDisplayName, 10) "
            "by UserPrincipalName | where Ips > 2 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.audit-* "
            'WHERE event.action RLIKE "(?i).*(token|oauth).*" AND event.outcome == "success" '
            "| STATS ips = COUNT_DISTINCT(source.ip) BY user.name, service.name "
            "| WHERE ips > 2 | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Application Access Token Replay\n"
            "logsource: {product: azure, service: signinlogs}\n"
            "detection:\n"
            "  selection: {AuthenticationRequirement: 'singleFactorAuthentication', ResultType: 0}\n"
            "  condition: selection | count(IPAddress) by UserPrincipalName > 2"
        ),
    },
    "T1550.002": {
        Backend.SPLUNK: (
            "index=auth EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM "
            'TargetUserName!="ANONYMOUS LOGON" '
            "| stats count BY host, TargetUserName, IpAddress | head 1000"
        ),
        Backend.SENTINEL: (
            "SecurityEvent | where EventID == 4624 and LogonType == 3 "
            "and AuthenticationPackageName == 'NTLM' and TargetUserName !endswith '$' "
            "| summarize count() by Computer, TargetUserName, IpAddress | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-system.security-* "
            'WHERE event.code == "4624" AND winlog.event_data.LogonType == "3" '
            'AND winlog.event_data.AuthenticationPackageName == "NTLM" '
            "| STATS logons = COUNT(*) BY host.name, user.name, source.ip | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=UserLogon LogonType_decimal=3 "
            "| stats count BY ComputerName, UserName, RemoteAddressIP4 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Pass-The-Hash NTLM Network Logon\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4624\n"
            "    LogonType: 3\n"
            "    AuthenticationPackageName: 'NTLM'\n"
            "  condition: selection"
        ),
    },
    "T1552": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*findstr*password*" OR CommandLine="*grep*-r*password*" OR '
            'CommandLine="*cat*.aws/credentials*" OR CommandLine="*unattend.xml*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('findstr password','.aws/credentials','unattend.xml','id_rsa','.git-credentials') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(findstr .*password|\\\\.aws/credentials|unattend\\\\.xml|id_rsa).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "(CommandLine=*findstr*password* OR CommandLine=*.aws/credentials* OR CommandLine=*id_rsa*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Credential Search In Files\n"
            "logsource: {category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['findstr password','.aws/credentials','unattend.xml','id_rsa']\n"
            "  condition: selection"
        ),
    },
    "T1555": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=11 OR EventCode=4663 "
            '(file_path="*\\\\Login Data*" OR file_path="*logins.json*" OR '
            'file_path="*\\\\Vault\\\\*" OR file_path="*Keychain*") '
            "| stats count BY host, process_name, file_path | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceFileEvents | where FileName in~ ('Login Data','logins.json','key4.db','cookies.sqlite') "
            "| where InitiatingProcessFileName !in~ ('chrome.exe','msedge.exe','firefox.exe') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.file-* "
            'WHERE file.name IN ("Login Data","logins.json","key4.db","cookies.sqlite") '
            'AND NOT process.name IN ("chrome.exe","msedge.exe","firefox.exe") '
            "| KEEP @timestamp, host.name, process.name, file.path | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName IN (FileOpenInfo, ProcessRollup2) "
            "(TargetFileName=*Login?Data* OR TargetFileName=*logins.json* OR TargetFileName=*key4.db*) "
            "| stats count BY ComputerName, FileName, TargetFileName | head 1000"
        ),
        Backend.SIGMA: (
            "title: Browser Credential Store Access\n"
            "logsource: {category: file_access, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    TargetFilename|contains: ['\\Login Data','\\logins.json','\\key4.db']\n"
            "  filter:\n"
            "    Image|endswith: ['\\chrome.exe','\\msedge.exe','\\firefox.exe']\n"
            "  condition: selection and not filter"
        ),
    },
    "T1558.003": {
        Backend.SPLUNK: (
            "index=auth EventCode=4769 ticket_encryption_type=0x17 "
            'service_name!="krbtgt" service_name!="*$" '
            "| stats dc(service_name) AS services BY user, src_ip "
            "| where services > 5 | head 1000"
        ),
        Backend.SENTINEL: (
            "SecurityEvent | where EventID == 4769 and TicketEncryptionType == '0x17' "
            "| where ServiceName !endswith '$' and ServiceName != 'krbtgt' "
            "| summarize Services=dcount(ServiceName) by Account, IpAddress "
            "| where Services > 5 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-system.security-* "
            'WHERE event.code == "4769" AND winlog.event_data.TicketEncryptionType == "0x17" '
            "| STATS services = COUNT_DISTINCT(winlog.event_data.ServiceName) BY user.name, source.ip "
            "| WHERE services > 5 | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Kerberoasting Via RC4 Service Ticket Requests\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4769\n"
            "    TicketEncryptionType: '0x17'\n"
            "  filter:\n"
            "    ServiceName|endswith: '$'\n"
            "  condition: selection and not filter"
        ),
    },
    "T1606": {
        Backend.SPLUNK: (
            'index=cloud (eventName="Set-DomainAuthentication" OR eventName="UpdateSAMLProvider" '
            'OR eventName="AddServicePrincipalCredentials") '
            "| stats count BY userIdentity.arn, sourceIPAddress, eventName | head 1000"
        ),
        Backend.SENTINEL: (
            "union AuditLogs, SigninLogs "
            "| where OperationName has_any ('Set federation settings','Update application certificate') "
            "or AuthenticationDetails has 'SAML' and ResultType == 0 "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.audit-* "
            'WHERE event.action RLIKE "(?i).*(saml|federation|token signing certificate).*" '
            "| KEEP @timestamp, user.name, event.action, source.ip | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: SAML Token Forgery Precursor\n"
            "logsource: {product: azure, service: auditlogs}\n"
            "detection:\n"
            "  selection:\n"
            "    OperationName|contains: ['Set federation settings','token signing certificate']\n"
            "  condition: selection"
        ),
    },
    "T1621": {
        Backend.SPLUNK: (
            "index=auth mfa_result=denied OR eventType=user.mfa.attempt.fail "
            "| stats count BY user, src_ip | where count > 5 | sort - count | head 1000"
        ),
        Backend.SENTINEL: (
            "SigninLogs | where ResultType in ('500121','50074') "
            "| summarize Denials=count() by UserPrincipalName, IPAddress "
            "| where Denials > 5 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.auth-* "
            'WHERE event.action RLIKE "(?i).*mfa.*" AND event.outcome == "failure" '
            "| STATS denials = COUNT(*) BY user.name, source.ip | WHERE denials > 5 | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: MFA Fatigue / Push Bombing\n"
            "logsource: {product: azure, service: signinlogs}\n"
            "detection:\n"
            "  selection: {ResultType: ['500121','50074']}\n"
            "  condition: selection | count() by UserPrincipalName > 5"
        ),
    },
    # ======================================================================
    # Discovery
    # ======================================================================
    "T1046": {
        Backend.SPLUNK: (
            "index=network | stats dc(dest_port) AS ports, dc(dest_ip) AS hosts BY src_ip "
            "| where ports > 50 OR hosts > 100 | sort - ports | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceNetworkEvents | where ActionType == 'ConnectionFailed' "
            "| summarize Ports=dcount(RemotePort), Hosts=dcount(RemoteIP) by DeviceName, InitiatingProcessFileName "
            "| where Ports > 50 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.network-* "
            "| STATS ports = COUNT_DISTINCT(destination.port), hosts = COUNT_DISTINCT(destination.ip) "
            "BY host.name, source.ip | WHERE ports > 50 | SORT ports DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=NetworkConnectIP4 "
            "| stats dc(RemotePort) AS ports, dc(RemoteAddressIP4) AS hosts BY ComputerName, FileName "
            "| where ports > 50 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Network Service Scanning\n"
            "logsource: {category: network_connection}\n"
            "detection:\n"
            "  selection: {Initiated: 'true'}\n"
            "  condition: selection | count(DestinationPort) by SourceIp > 50"
        ),
    },
    "T1082": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            'process_name IN ("systeminfo.exe","hostname.exe","wmic.exe","reg.exe","uname") '
            "| stats dc(process_name) AS tools BY host, user, parent_process_name "
            "| where tools > 2 | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName in~ "
            "('systeminfo.exe','hostname.exe','wmic.exe','reg.exe','uname') "
            "| summarize Tools=dcount(FileName) by DeviceName, AccountName, InitiatingProcessFileName "
            "| where Tools > 2 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name IN ("systeminfo.exe","hostname.exe","wmic.exe","uname","reg.exe") '
            "| STATS tools = COUNT_DISTINCT(process.name) BY host.name, user.name "
            "| WHERE tools > 2 | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "FileName IN (systeminfo.exe, hostname.exe, wmic.exe, reg.exe) "
            "| stats dc(FileName) AS tools BY ComputerName, ParentBaseFileName "
            "| where tools > 2 | head 1000"
        ),
        Backend.SIGMA: (
            "title: System Information Discovery Burst\n"
            "logsource: {category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: ['\\systeminfo.exe','\\hostname.exe','\\wmic.exe']\n"
            "  condition: selection | count(Image) by ParentImage > 2"
        ),
    },
    "T1087.002": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*net group*/domain*" OR CommandLine="*Get-ADUser*" OR '
            'CommandLine="*dsquery*user*" OR CommandLine="*net user*/domain*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('net group /domain','net user /domain','Get-ADUser','Get-ADGroupMember','dsquery user') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(net (group|user).*/domain|get-aduser|dsquery user).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "(CommandLine=*net*group*/domain* OR CommandLine=*Get-ADUser* OR CommandLine=*dsquery*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Domain Account Enumeration\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['net group /domain','Get-ADUser','dsquery user']\n"
            "  condition: selection"
        ),
    },
    "T1580": {
        Backend.SPLUNK: (
            "index=cloud sourcetype=aws:cloudtrail "
            '(eventName="Describe*" OR eventName="List*" OR eventName="Get*") '
            "| stats dc(eventName) AS calls BY userIdentity.arn, sourceIPAddress "
            "| where calls > 25 | sort - calls | head 1000"
        ),
        Backend.SENTINEL: (
            "AzureActivity | where OperationNameValue endswith '/READ' "
            "| summarize Ops=dcount(OperationNameValue) by Caller, CallerIpAddress "
            "| where Ops > 25 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-aws.cloudtrail-* "
            'WHERE event.action RLIKE "(Describe|List|Get).*" '
            "| STATS calls = COUNT_DISTINCT(event.action) BY user.name, source.ip "
            "| WHERE calls > 25 | SORT calls DESC | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Cloud Infrastructure Enumeration Burst\n"
            "logsource: {product: aws, service: cloudtrail}\n"
            "detection:\n"
            "  selection:\n"
            "    eventName|startswith: ['Describe','List']\n"
            "  condition: selection | count(eventName) by userIdentity.arn > 25"
        ),
    },
    # ======================================================================
    # Lateral movement
    # ======================================================================
    "T1021.001": {
        Backend.SPLUNK: (
            "index=auth EventCode=4624 LogonType=10 "
            "| stats dc(dest) AS hosts, count BY user, src_ip "
            "| where hosts > 3 | sort - hosts | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceLogonEvents | where LogonType == 'RemoteInteractive' "
            "| summarize Hosts=dcount(DeviceName), Logons=count() by AccountName, RemoteIP "
            "| where Hosts > 3 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-system.security-* "
            'WHERE event.code == "4624" AND winlog.event_data.LogonType == "10" '
            "| STATS hosts = COUNT_DISTINCT(host.name) BY user.name, source.ip "
            "| WHERE hosts > 3 | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=UserLogon LogonType_decimal=10 "
            "| stats dc(ComputerName) AS hosts BY UserName, RemoteAddressIP4 "
            "| where hosts > 3 | head 1000"
        ),
        Backend.SIGMA: (
            "title: RDP Lateral Movement Fan-Out\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection: {EventID: 4624, LogonType: 10}\n"
            "  condition: selection | count(Computer) by TargetUserName > 3"
        ),
    },
    "T1021.002": {
        Backend.SPLUNK: (
            "index=endpoint (EventCode=5140 OR EventCode=5145) "
            'share_name IN ("ADMIN$","C$","IPC$") '
            "| stats dc(dest) AS hosts, count BY user, src_ip | where hosts > 2 | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceEvents | where ActionType == 'SmbShareAccess' "
            "or AdditionalFields has_any ('ADMIN$','C$') "
            "| summarize Hosts=dcount(DeviceName) by AccountName, RemoteIP | where Hosts > 2 "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-system.security-* "
            'WHERE event.code IN ("5140","5145") AND winlog.event_data.ShareName RLIKE ".*\\\\$" '
            "| STATS hosts = COUNT_DISTINCT(host.name) BY user.name, source.ip "
            "| WHERE hosts > 2 | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName IN (ProcessRollup2, NetworkConnectIP4) RemotePort=445 "
            "| stats dc(RemoteAddressIP4) AS hosts BY ComputerName, UserName "
            "| where hosts > 2 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Admin Share Access\n"
            "logsource: {product: windows, service: security}\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: [5140, 5145]\n"
            "    ShareName|contains: ['ADMIN$','C$']\n"
            "  condition: selection"
        ),
    },
    "T1021.004": {
        Backend.SPLUNK: (
            'index=linux sourcetype=linux_secure "Accepted publickey" OR "Accepted password" '
            "| stats dc(host) AS hosts, count BY user, src_ip | where hosts > 3 | head 1000"
        ),
        Backend.SENTINEL: (
            "Syslog | where SyslogMessage has 'Accepted' and ProcessName == 'sshd' "
            "| summarize Hosts=dcount(Computer) by SyslogMessage | where Hosts > 3 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-system.auth-* "
            'WHERE process.name == "sshd" AND event.outcome == "success" '
            "| STATS hosts = COUNT_DISTINCT(host.name) BY user.name, source.ip "
            "| WHERE hosts > 3 | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_platform=Lin event_simpleName=UserLogon RemoteAddressIP4=* "
            "| stats dc(ComputerName) AS hosts BY UserName, RemoteAddressIP4 "
            "| where hosts > 3 | head 1000"
        ),
        Backend.SIGMA: (
            "title: SSH Lateral Movement Fan-Out\n"
            "logsource: {product: linux, service: sshd}\n"
            "detection:\n"
            "  selection: {message|contains: 'Accepted'}\n"
            "  condition: selection | count(host) by user > 3"
        ),
    },
    # ======================================================================
    # Collection
    # ======================================================================
    "T1114": {
        Backend.SPLUNK: (
            "index=email (operation=New-InboxRule OR operation=Set-InboxRule OR "
            "operation=Add-MailboxPermission) "
            "| stats count BY user, operation, parameters | head 1000"
        ),
        Backend.SENTINEL: (
            "OfficeActivity | where Operation in "
            "('New-InboxRule','Set-InboxRule','Add-MailboxPermission','New-TransportRule') "
            "| project TimeGenerated, UserId, Operation, Parameters, ClientIP | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-o365.audit-* "
            'WHERE event.action IN ("New-InboxRule","Set-InboxRule","Add-MailboxPermission") '
            "| KEEP @timestamp, user.name, event.action, source.ip | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Suspicious Mailbox Rule Or Delegation\n"
            "logsource: {product: m365, service: exchange}\n"
            "detection:\n"
            "  selection:\n"
            "    Operation: ['New-InboxRule','Set-InboxRule','Add-MailboxPermission']\n"
            "  condition: selection"
        ),
    },
    "T1530": {
        Backend.SPLUNK: (
            "index=cloud sourcetype=aws:cloudtrail "
            'eventName IN ("GetObject","ListObjects","CopyObject") '
            "| stats count AS calls BY userIdentity.arn, requestParameters.bucketName, sourceIPAddress "
            "| where calls > 500 | sort - calls | head 1000"
        ),
        Backend.SENTINEL: (
            "StorageBlobLogs | where OperationName in ('GetBlob','ListBlobs') "
            "| summarize Calls=count(), Bytes=sum(ResponseBodySize) by CallerIpAddress, AccountName "
            "| where Calls > 500 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-aws.cloudtrail-* "
            'WHERE event.action IN ("GetObject","ListObjects","CopyObject") '
            "| STATS calls = COUNT(*) BY user.name, source.ip | WHERE calls > 500 | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Bulk Cloud Storage Read\n"
            "logsource: {product: aws, service: cloudtrail}\n"
            "detection:\n"
            "  selection: {eventName: ['GetObject','ListObjects']}\n"
            "  condition: selection | count() by userIdentity.arn > 500"
        ),
    },
    "T1560": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(process_name IN ("7z.exe","rar.exe","winrar.exe","tar.exe") OR '
            'CommandLine="*Compress-Archive*") (CommandLine="*-p*" OR CommandLine="*-hp*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where FileName in~ ('7z.exe','rar.exe','winrar.exe','tar.exe') "
            "or ProcessCommandLine has 'Compress-Archive' | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.name IN ("7z.exe","rar.exe","winrar.exe","tar.exe","zip") '
            'OR process.command_line LIKE "*Compress-Archive*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 FileName IN (7z.exe, rar.exe, winrar.exe, tar.exe) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Data Staged Into Archive\n"
            "logsource: {category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: ['\\7z.exe','\\rar.exe','\\winrar.exe']\n"
            "    CommandLine|contains: ['-p','-hp','a ']\n"
            "  condition: selection"
        ),
    },
    # ======================================================================
    # Command and control
    # ======================================================================
    "T1071.001": {
        Backend.SPLUNK: (
            "index=proxy | stats count, avg(bytes_out) AS avg_out, dc(uri_path) AS paths "
            "BY src_ip, dest_host | where count > 100 AND paths < 3 | sort - count | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceNetworkEvents | where RemotePort in (80, 443) "
            "| summarize Beacons=count(), Paths=dcount(RemoteUrl) by DeviceName, RemoteIP "
            "| where Beacons > 100 and Paths < 3 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.http-* "
            "| STATS requests = COUNT(*), paths = COUNT_DISTINCT(url.path) BY source.ip, destination.domain "
            "| WHERE requests > 100 AND paths < 3 | SORT requests DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=NetworkConnectIP4 RemotePort IN (80, 443) "
            "| stats count AS conns BY ComputerName, FileName, RemoteAddressIP4 "
            "| where conns > 100 | head 1000"
        ),
        Backend.SIGMA: (
            "title: HTTP Beaconing Pattern\n"
            "logsource: {category: proxy}\n"
            "detection:\n"
            "  selection: {c-uri|contains: '/'}\n"
            "  condition: selection | count() by src_ip, dst_host > 100"
        ),
    },
    "T1071.004": {
        Backend.SPLUNK: (
            "index=dns | eval qlen=len(query) | where qlen > 50 "
            "| stats count, dc(query) AS uniq BY src_ip, parent_domain "
            "| where uniq > 50 | sort - uniq | head 1000"
        ),
        Backend.SENTINEL: (
            "DnsEvents | extend QLen = strlen(Name) | where QLen > 50 "
            "| summarize Queries=dcount(Name) by ClientIP, tostring(split(Name, '.')[-2]) "
            "| where Queries > 50 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.dns-* | EVAL qlen = LENGTH(dns.question.name) | WHERE qlen > 50 "
            "| STATS queries = COUNT_DISTINCT(dns.question.name) BY source.ip, dns.question.registered_domain "
            "| WHERE queries > 50 | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=DnsRequest "
            "| stats dc(DomainName) AS uniq BY ComputerName, FileName "
            "| where uniq > 50 | head 1000"
        ),
        Backend.SIGMA: (
            "title: DNS Tunnelling Indicators\n"
            "logsource: {category: dns}\n"
            "detection:\n"
            "  selection: {query|re: '.{50,}'}\n"
            "  condition: selection | count(query) by src_ip > 50"
        ),
    },
    "T1090.003": {
        Backend.SPLUNK: (
            "index=network (dest_port IN (9001, 9030, 9050, 9150) OR "
            'dest_host="*.onion" OR app="tor") '
            "| stats count BY src_ip, dest_ip, dest_port | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceNetworkEvents | where RemotePort in (9001, 9030, 9050, 9150) "
            "or RemoteUrl endswith '.onion' "
            "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.network-* "
            "| WHERE destination.port IN (9001, 9030, 9050, 9150) "
            "| STATS conns = COUNT(*) BY host.name, process.name, destination.ip "
            "| SORT conns DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=NetworkConnectIP4 RemotePort IN (9001, 9030, 9050, 9150) "
            "| stats count BY ComputerName, FileName, RemoteAddressIP4 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Tor Or Anonymising Proxy Connection\n"
            "logsource: {category: network_connection}\n"
            "detection:\n"
            "  selection: {DestinationPort: [9001, 9030, 9050, 9150]}\n"
            "  condition: selection"
        ),
    },
    "T1105": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*certutil*urlcache*" OR CommandLine="*bitsadmin*/transfer*" OR '
            'CommandLine="*Invoke-WebRequest*" OR CommandLine="*curl*-o*" OR CommandLine="*wget*") '
            "| stats count BY host, user, process_name, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('certutil -urlcache','bitsadmin /transfer','Invoke-WebRequest','curl -o','wget ') "
            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(certutil.*urlcache|bitsadmin.*/transfer|invoke-webrequest|curl .*-o |wget ).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "(CommandLine=*certutil*urlcache* OR CommandLine=*bitsadmin*transfer* "
            "OR CommandLine=*Invoke-WebRequest*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Living-Off-The-Land Download Utility\n"
            "logsource: {category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['certutil -urlcache','bitsadmin /transfer','Invoke-WebRequest']\n"
            "  condition: selection"
        ),
    },
    # ======================================================================
    # Exfiltration
    # ======================================================================
    "T1041": {
        Backend.SPLUNK: (
            "index=network | stats sum(bytes_out) AS out, sum(bytes_in) AS inb BY src_ip, dest_ip "
            "| where out > 100000000 AND out > inb * 10 | sort - out | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceNetworkEvents | summarize Sent=sum(toreal(BytesSent)) "
            "by DeviceName, RemoteIP, InitiatingProcessFileName "
            "| where Sent > 100000000 | order by Sent desc | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.network-* "
            "| STATS sent = SUM(source.bytes), recv = SUM(destination.bytes) BY source.ip, destination.ip "
            "| WHERE sent > 100000000 | SORT sent DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=NetworkConnectIP4 "
            "| stats sum(BytesSent) AS sent BY ComputerName, FileName, RemoteAddressIP4 "
            "| where sent > 100000000 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Large Outbound Transfer Over C2 Channel\n"
            "logsource: {category: network_connection}\n"
            "detection:\n"
            "  selection: {Initiated: 'true'}\n"
            "  condition: selection | sum(bytes_out) by DestinationIp > 100000000"
        ),
    },
    "T1048.003": {
        Backend.SPLUNK: (
            "index=network dest_port IN (21, 23, 69, 25, 53) "
            "| stats sum(bytes_out) AS out BY src_ip, dest_ip, dest_port "
            "| where out > 10000000 | sort - out | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceNetworkEvents | where RemotePort in (21, 23, 69, 25) "
            "| summarize Sent=sum(toreal(BytesSent)) by DeviceName, RemoteIP, RemotePort "
            "| where Sent > 10000000 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.network-* | WHERE destination.port IN (21, 23, 69, 25) "
            "| STATS sent = SUM(source.bytes) BY source.ip, destination.ip, destination.port "
            "| WHERE sent > 10000000 | SORT sent DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=NetworkConnectIP4 RemotePort IN (21, 23, 69, 25) "
            "| stats sum(BytesSent) AS sent BY ComputerName, RemoteAddressIP4, RemotePort "
            "| where sent > 10000000 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Exfiltration Over Cleartext Protocol\n"
            "logsource: {category: network_connection}\n"
            "detection:\n"
            "  selection: {DestinationPort: [21, 23, 69, 25]}\n"
            "  condition: selection | sum(bytes_out) by DestinationIp > 10000000"
        ),
    },
    "T1537": {
        Backend.SPLUNK: (
            "index=cloud sourcetype=aws:cloudtrail "
            'eventName IN ("ModifySnapshotAttribute","SharedSnapshotCopyInitiated","CopySnapshot",'
            '"ModifyImageAttribute") '
            "| stats count BY userIdentity.arn, requestParameters, sourceIPAddress | head 1000"
        ),
        Backend.SENTINEL: (
            "AzureActivity | where OperationNameValue has_any "
            "('MICROSOFT.COMPUTE/SNAPSHOTS/WRITE','MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION') "
            "| summarize count() by Caller, CallerIpAddress, ResourceId | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-aws.cloudtrail-* "
            'WHERE event.action IN ("ModifySnapshotAttribute","CopySnapshot","ModifyImageAttribute") '
            "| KEEP @timestamp, user.name, source.ip, event.action | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Snapshot Shared To External Account\n"
            "logsource: {product: aws, service: cloudtrail}\n"
            "detection:\n"
            "  selection:\n"
            "    eventName: ['ModifySnapshotAttribute','SharedSnapshotCopyInitiated']\n"
            "  condition: selection"
        ),
    },
    "T1567.002": {
        Backend.SPLUNK: (
            "index=proxy "
            'dest_host IN ("*.dropbox.com","*.mega.nz","*.box.com","*drive.google.com","*wetransfer.com") '
            "| stats sum(bytes_out) AS out BY src_ip, user, dest_host "
            "| where out > 50000000 | sort - out | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceNetworkEvents | where RemoteUrl has_any "
            "('dropbox.com','mega.nz','box.com','drive.google.com','wetransfer.com') "
            "| summarize Sent=sum(toreal(BytesSent)) by DeviceName, InitiatingProcessAccountName, RemoteUrl "
            "| where Sent > 50000000 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-*.proxy-* "
            'WHERE destination.domain RLIKE "(?i).*(dropbox|mega\\\\.nz|box\\\\.com|wetransfer).*" '
            "| STATS sent = SUM(source.bytes) BY user.name, destination.domain "
            "| WHERE sent > 50000000 | SORT sent DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=DnsRequest "
            "(DomainName=*dropbox* OR DomainName=*mega.nz* OR DomainName=*wetransfer*) "
            "| stats count BY ComputerName, FileName, DomainName | head 1000"
        ),
        Backend.SIGMA: (
            "title: Upload To Personal Cloud Storage\n"
            "logsource: {category: proxy}\n"
            "detection:\n"
            "  selection:\n"
            "    c-uri|contains: ['dropbox.com','mega.nz','wetransfer.com']\n"
            "  condition: selection | sum(bytes_out) by src_ip > 50000000"
        ),
    },
    # ======================================================================
    # Impact
    # ======================================================================
    "T1485": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=23 OR EventCode=26 "
            "| stats count AS deletions BY host, process_name, user "
            "| where deletions > 500 | sort - deletions | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceFileEvents | where ActionType == 'FileDeleted' "
            "| summarize Deletions=count() by DeviceName, InitiatingProcessFileName "
            "| where Deletions > 500 | take 1000"
        ),
        Backend.ELASTIC: (
            'FROM logs-endpoint.events.file-* | WHERE event.action == "deletion" '
            "| STATS deletions = COUNT(*) BY host.name, process.name "
            "| WHERE deletions > 500 | SORT deletions DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=FileDeleted "
            "| stats count AS deletions BY ComputerName, FileName "
            "| where deletions > 500 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Mass File Deletion\n"
            "logsource: {category: file_delete, product: windows}\n"
            "detection:\n"
            "  selection: {EventID: 23}\n"
            "  condition: selection | count() by Image > 500"
        ),
    },
    "T1486": {  # Data Encrypted for Impact (ransomware)
        Backend.SPLUNK: (
            'index=endpoint EventCode=11 (file_name="*.encrypted" OR file_name="*.locked" '
            'OR file_name="*READ*ME*ransom*") | stats count by host, process_name | head 1000'
        ),
        Backend.SENTINEL: (
            "DeviceFileEvents | where FileName endswith '.encrypted' or FileName endswith '.locked' "
            "| summarize count() by DeviceName, InitiatingProcessFileName | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.file-* "
            'WHERE file.extension IN ("encrypted","locked","crypt") '
            'OR file.name RLIKE "(?i).*(read.?me|how.?to.?decrypt).*" '
            "| STATS files = COUNT(*) BY host.name, process.name "
            "| SORT files DESC | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName IN (NewScriptWritten, FileRenameInfo) "
            "(TargetFileName=*.encrypted OR TargetFileName=*.locked) "
            "| stats count BY ComputerName, FileName | head 1000"
        ),
        Backend.SIGMA: (
            "title: Ransomware File Encryption\n"
            "logsource: {category: file_event, product: windows}\n"
            "detection:\n"
            "  selection: {TargetFilename|endswith: ['.encrypted','.locked']}\n"
            "  condition: selection"
        ),
    },
    "T1489": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*net stop*" OR CommandLine="*sc*stop*" OR CommandLine="*Stop-Service*") '
            "| stats dc(CommandLine) AS stops BY host, user | where stops > 3 | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any ('net stop','sc stop','Stop-Service') "
            "| summarize Stops=dcount(ProcessCommandLine) by DeviceName, AccountName "
            "| where Stops > 3 | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(net stop|sc stop|stop-service).*" '
            "| STATS stops = COUNT_DISTINCT(process.command_line) BY host.name, user.name "
            "| WHERE stops > 3 | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 (CommandLine=*net*stop* OR CommandLine=*sc*stop*) "
            "| stats dc(CommandLine) AS stops BY ComputerName, UserName | where stops > 3 | head 1000"
        ),
        Backend.SIGMA: (
            "title: Bulk Service Stop\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['net stop','sc stop','Stop-Service']\n"
            "  condition: selection | count() by Computer > 3"
        ),
    },
    "T1490": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wbadmin*delete*catalog*" OR '
            'CommandLine="*bcdedit*recoveryenabled*no*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('vssadmin delete shadows','wbadmin delete catalog','bcdedit /set','recoveryenabled no') "
            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(vssadmin.*delete shadows|wbadmin.*delete catalog|bcdedit.*recoveryenabled).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "(CommandLine=*vssadmin*delete*shadows* OR CommandLine=*wbadmin*delete* "
            "OR CommandLine=*bcdedit*recoveryenabled*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Shadow Copy Deletion\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['vssadmin delete shadows','wbadmin delete catalog']\n"
            "  condition: selection"
        ),
    },
    "T1561": {
        Backend.SPLUNK: (
            "index=endpoint EventCode=4688 "
            '(CommandLine="*format*/fs*" OR CommandLine="*diskpart*clean*" OR '
            'CommandLine="*cipher*/w*" OR CommandLine="*dd*of=/dev/*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "DeviceProcessEvents | where ProcessCommandLine has_any "
            "('diskpart','cipher /w','format /fs','dd of=/dev/') | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-* "
            'WHERE process.command_line RLIKE "(?i).*(diskpart.*clean|cipher /w|dd .*of=/dev/).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_simpleName=ProcessRollup2 "
            "(CommandLine=*diskpart*clean* OR CommandLine=*cipher*/w* OR CommandLine=*dd*of=/dev/*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Disk Wipe Utility Execution\n"
            "logsource: {category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['diskpart','cipher /w','of=/dev/']\n"
            "  condition: selection"
        ),
    },
    # ======================================================================
    # Containers
    # ======================================================================
    "T1609": {
        Backend.SPLUNK: (
            "index=k8s (verb=create objectRef.subresource=exec) OR "
            '(sourcetype=docker CommandLine="*docker exec*") '
            "| stats count BY user.username, objectRef.namespace, objectRef.name | head 1000"
        ),
        Backend.SENTINEL: (
            "AKSAudit | where Verb == 'create' and ObjectRef has 'pods/exec' "
            "| project TimeGenerated, User, ObjectRef, SourceIps | take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-kubernetes.audit-* "
            'WHERE kubernetes.audit.objectRef.subresource == "exec" '
            "| STATS execs = COUNT(*) BY kubernetes.audit.user.username, kubernetes.audit.objectRef.namespace "
            "| SORT execs DESC | LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Container Exec Session\n"
            "logsource: {product: kubernetes, service: audit}\n"
            "detection:\n"
            "  selection: {objectRef.subresource: 'exec', verb: 'create'}\n"
            "  condition: selection"
        ),
    },
    "T1610": {
        Backend.SPLUNK: (
            "index=k8s verb=create objectRef.resource=pods "
            '(requestObject.spec.hostNetwork=true OR requestObject.spec.containers{}.image="*:latest") '
            "| stats count BY user.username, objectRef.namespace | head 1000"
        ),
        Backend.SENTINEL: (
            "AKSAudit | where Verb == 'create' and ObjectRef has 'pods' "
            "| where RequestObject has_any ('hostNetwork\":true','privileged\":true') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-kubernetes.audit-* "
            'WHERE kubernetes.audit.verb == "create" '
            'AND kubernetes.audit.objectRef.resource == "pods" '
            "| KEEP @timestamp, kubernetes.audit.user.username, kubernetes.audit.objectRef.namespace "
            "| LIMIT 1000"
        ),
        Backend.SIGMA: (
            "title: Suspicious Pod Deployment\n"
            "logsource: {product: kubernetes, service: audit}\n"
            "detection:\n"
            "  selection: {verb: 'create', objectRef.resource: 'pods'}\n"
            "  condition: selection"
        ),
    },
    "T1611": {
        Backend.SPLUNK: (
            "index=k8s OR index=linux "
            "(requestObject.spec.containers{}.securityContext.privileged=true OR "
            'CommandLine="*nsenter*--target*1*" OR CommandLine="*mount*/host*") '
            "| stats count BY host, user, CommandLine | head 1000"
        ),
        Backend.SENTINEL: (
            "union AKSAudit, DeviceProcessEvents "
            "| where RequestObject has 'privileged\":true' "
            "or ProcessCommandLine has_any ('nsenter --target 1','mount /host') "
            "| take 1000"
        ),
        Backend.ELASTIC: (
            "FROM logs-endpoint.events.process-*, logs-kubernetes.audit-* "
            'WHERE process.command_line RLIKE "(?i).*(nsenter .*--target 1|mount .*/host).*" '
            "| KEEP @timestamp, host.name, user.name, process.command_line | LIMIT 1000"
        ),
        Backend.CROWDSTRIKE: (
            "event_platform=Lin event_simpleName=ProcessRollup2 "
            "(CommandLine=*nsenter*--target*1* OR CommandLine=*mount*/host*) "
            "| stats count BY ComputerName, UserName, CommandLine | head 1000"
        ),
        Backend.SIGMA: (
            "title: Container Escape To Host\n"
            "logsource: {category: process_creation, product: linux}\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: ['nsenter --target 1','mount /host']\n"
            "  condition: selection"
        ),
    },
}


def curated_technique_ids(backend: Backend | None = None) -> set[str]:
    """Technique ids with a curated (non-generic) template.

    ``backend=None`` -> every technique with at least one curated backend.
    """
    if backend is None:
        return set(QUERY_LIBRARY)
    return {ttp for ttp, per_backend in QUERY_LIBRARY.items() if backend in per_backend}


def curated_counts() -> dict[Backend, int]:
    """Per-backend curated technique counts (the golden-test subject)."""
    return {backend: len(curated_technique_ids(backend)) for backend in Backend}


def parent_technique(ttp_id: str) -> str | None:
    """``"T1059.001" -> "T1059"``; ``None`` when already a base technique."""
    base, _, sub = ttp_id.partition(".")
    return base if sub else None


def lookup_template(ttp_id: str, backend: Backend) -> tuple[str, str] | None:
    """Resolve a curated template for ``(ttp_id, backend)``.

    Returns ``(query, source_ttp_id)`` or ``None`` when nothing is curated.
    A sub-technique with no entry of its own inherits its parent technique's
    template (``T1110.001`` -> ``T1110``) — the parent's behaviour is a
    strict superset, so the query stays truthful, and ``source_ttp_id``
    tells the caller (and the analyst) where it came from.
    """
    exact = QUERY_LIBRARY.get(ttp_id, {}).get(backend)
    if exact is not None:
        return exact, ttp_id
    parent = parent_technique(ttp_id)
    if parent is not None:
        inherited = QUERY_LIBRARY.get(parent, {}).get(backend)
        if inherited is not None:
            return inherited, parent
    return None


__all__ = [
    "QUERY_LIBRARY",
    "TECHNIQUE_NAMES",
    "curated_counts",
    "curated_technique_ids",
    "lookup_template",
    "parent_technique",
]
