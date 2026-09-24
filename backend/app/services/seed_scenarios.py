"""Seed content: MITRE techniques and the six training scenarios.

Everything here is FICTIONAL: RFC-5737 TEST-NET IPs, dummy users/devices/files.
No real systems, credentials, or malware are involved — events are rows in a DB.
"""

MITRE_TECHNIQUES = [
    ("T1110", "Brute Force",
     "Adversaries repeatedly attempt to guess credentials. Simulated here as repeated LOGIN_FAILURE events followed by a success."),
    ("T1078", "Valid Accounts",
     "Adversaries obtain and abuse credentials of existing accounts. Simulated as logins from unusual sources after compromise."),
    ("T1041", "Exfiltration Over C2 Channel",
     "Adversaries steal data over an existing command-and-control channel. Simulated as large DATA_TRANSFER events to external test IPs."),
    ("T1566", "Phishing",
     "Adversaries send malicious emails to gain access. Simulated as EMAIL_RECEIVED + link-click chains with no real email sent."),
    ("T1204", "User Execution",
     "Adversaries rely on users running attacker-controlled content. Simulated as a user clicking a simulated phishing link."),
    ("T1068", "Exploitation for Privilege Escalation",
     "Adversaries exploit a flaw to gain higher privileges. Simulated as a PRIVILEGE_CHANGE event with no real escalation."),
    ("T1136", "Create Account",
     "Adversaries create accounts to maintain access. Simulated as an ACCOUNT_CREATED event in the fake directory."),
    ("T1003", "OS Credential Dumping",
     "Adversaries dump credentials from the OS. Simulated as a PROCESS_START of a fake dumping tool; nothing is actually dumped."),
    ("T1486", "Data Encrypted for Impact",
     "Adversaries encrypt data to disrupt availability. Simulated as FILE_MODIFY events renaming dummy files to *.locked-sim; no real files are touched."),
    ("T1059", "Command and Scripting Interpreter",
     "Adversaries abuse command-line interpreters. Simulated as PROCESS_START events only."),
    ("T1071", "Application Layer Protocol",
     "Adversaries communicate over common protocols. Simulated as NETWORK_CONNECTION rows to test-net IPs."),
    ("T1039", "Data from Network Shared Drive",
     "Adversaries search shared drives for data. Simulated as bulk FILE_ACCESS events on a fake file share."),
    ("T1083", "File and Directory Discovery",
     "Adversaries enumerate files. Simulated as bursts of FILE_ACCESS events."),
    ("T1190", "Exploit Public-Facing Application",
     "Adversaries exploit internet-facing apps. Simulated as WEB_ATTACK events with inert payload strings."),
]


def _e(offset, event_type, severity, message, **kw):
    d = {"offset_sec": offset, "event_type": event_type, "severity": severity, "message": message}
    d.update(kw)
    return d


def _brute_force_events():
    evs = []
    for i in range(12):
        evs.append(_e(5 + i * 5, "LOGIN_FAILURE", "LOW" if i < 8 else "MEDIUM",
                      f"Failed login attempt {i + 1}/12 for employee_42",
                      source="198.51.100.23", destination="10.10.4.21",
                      username="employee_42", device="WS-1042",
                      meta={"attempt": i + 1, "auth_method": "password"}))
    evs += [
        _e(75, "LOGIN_SUCCESS", "HIGH", "Successful login for employee_42 after 12 failures — from an unusual external IP",
           source="198.51.100.23", destination="10.10.4.21", username="employee_42", device="WS-1042",
           meta={"unusual_ip": True, "prior_failures": 12}),
        _e(100, "NETWORK_CONNECTION", "HIGH", "Outbound connection from WS-1042 to attacker IP on port 4444",
           source="10.10.4.21", destination="198.51.100.23:4444", username="employee_42", device="WS-1042",
           meta={"port": 4444, "direction": "outbound"}),
        _e(140, "FILE_ACCESS", "HIGH", "Access to sensitive share \\\\fileserver\\finance\\q3_reports (simulated)",
           source="10.10.4.21", username="employee_42", device="WS-1042",
           meta={"path": "\\\\fileserver\\finance\\q3_reports", "sensitive": True}),
        _e(200, "DATA_TRANSFER", "CRITICAL", "Large outbound transfer: 2.4 GB to external IP (simulated)",
           source="10.10.4.21", destination="198.51.100.23", username="employee_42", device="WS-1042",
           meta={"bytes": 2576980377, "direction": "outbound"}),
    ]
    return evs


def _phishing_events():
    return [
        _e(10, "EMAIL_RECEIVED", "LOW", "Email to employee_17: 'Urgent: Invoice #INV-8821 overdue' from invoice@trusted-billing.example (simulated inbox)",
           destination="employee_17@corp-sim.example", username="employee_17", device="WS-1017",
           meta={"subject": "Urgent: Invoice #INV-8821 overdue", "sender": "invoice@trusted-billing.example", "is_phishing_sim": True}),
        _e(45, "NETWORK_CONNECTION", "MEDIUM", "employee_17 clicked the invoice link: HTTPS to 203.0.113.44 (simulated phishing site)",
           source="10.10.5.17", destination="203.0.113.44:443", username="employee_17", device="WS-1017",
           meta={"url": "https://203.0.113.44/login", "user_click": True}),
        _e(70, "LOGIN_FAILURE", "MEDIUM", "First login attempt on phishing page failed (victim typo) — credential harvesting in progress (simulated)",
           source="203.0.113.44", username="employee_17", device="WS-1017", meta={"phishing_site": True}),
        _e(95, "LOGIN_SUCCESS", "HIGH", "Attacker logged in as employee_17 from 203.0.113.44 using harvested credentials (simulated)",
           source="203.0.113.44", destination="10.10.4.10", username="employee_17", device="UNKNOWN",
           meta={"unusual_ip": True, "stolen_credentials": True}),
        _e(130, "PASSWORD_RESET", "HIGH", "Password reset for employee_17 initiated from attacker IP (simulated)",
           source="203.0.113.44", username="employee_17", meta={"initiated_by_attacker": True}),
        _e(170, "CONFIG_CHANGE", "MEDIUM", "Suspicious mailbox rule created: forward all mail to external address (simulated)",
           username="employee_17", device="EXCH-SIM-01", meta={"rule": "forward-all-to-external", "suspicious": True}),
        _e(210, "DATA_TRANSFER", "CRITICAL", "Mailbox export: 890 MB outbound to 203.0.113.44 (simulated)",
           source="10.10.4.10", destination="203.0.113.44", username="employee_17",
           meta={"bytes": 933232640, "direction": "outbound"}),
    ]


def _privesc_events():
    return [
        _e(10, "LOGIN_SUCCESS", "LOW", "Service account svc_backup logged in normally from 10.10.6.12",
           source="10.10.6.12", destination="10.10.4.5", username="svc_backup", device="SRV-BKP-01"),
        _e(60, "PRIVILEGE_CHANGE", "CRITICAL", "svc_backup role changed: Employee -> Administrator (simulated directory change)",
           username="svc_backup", device="DC-SIM-01",
           meta={"old_role": "Employee", "new_role": "Administrator"}),
        _e(90, "PROCESS_START", "HIGH", "Suspicious process started: cred_dump_sim.exe on SRV-DB-01 (simulated; nothing is dumped)",
           username="svc_backup", device="SRV-DB-01",
           meta={"process": "cred_dump_sim.exe", "suspicious": True}),
        _e(130, "FILE_ACCESS", "CRITICAL", "Access to simulated credential store: C:\\Windows\\NTDS\\sim_ntds.dit",
           username="svc_backup", device="SRV-DB-01",
           meta={"path": "C:\\Windows\\NTDS\\sim_ntds.dit", "sensitive": True}),
        _e(170, "ACCOUNT_CREATED", "HIGH", "New account created: svc_backup_admin with admin rights (simulated backdoor account)",
           username="svc_backup", device="DC-SIM-01",
           meta={"new_account": "svc_backup_admin", "suspicious": True}),
    ]


def _ransomware_events():
    evs = [
        _e(10, "PROCESS_START", "MEDIUM", "employee_55 launched invoice_2026.exe (simulated malicious dropper; inert)",
           username="employee_55", device="WS-1055", meta={"process": "invoice_2026.exe", "suspicious": True}),
    ]
    for i in range(8):
        evs.append(_e(30 + i * 12, "FILE_MODIFY", "HIGH",
                      f"Rapid file modification {i + 1}/8: report_q{i}.docx -> report_q{i}.docx.locked-sim (simulated)",
                      username="employee_55", device="WS-1055",
                      meta={"path": f"C:\\Users\\employee_55\\Documents\\report_q{i}.docx.locked-sim", "ransomware_like": True}))
    evs += [
        _e(60, "ENDPOINT_ALERT", "CRITICAL", "EDR-style alert: ransomware-like behavior — rapid file modification on WS-1055 (simulated)",
           device="WS-1055", username="employee_55", meta={"detector": "behavioral-sim"}),
        _e(90, "FILE_CREATE", "CRITICAL", "Ransom note created: C:\\Users\\employee_55\\Desktop\\READ_ME_SIM.txt (simulated)",
           username="employee_55", device="WS-1055", meta={"path": "C:\\Users\\employee_55\\Desktop\\READ_ME_SIM.txt"}),
        _e(120, "NETWORK_CONNECTION", "HIGH", "WS-1055 contacting 192.0.2.10:443 — suspected C2 (simulated)",
           source="10.10.7.55", destination="192.0.2.10:443", device="WS-1055",
           meta={"direction": "outbound", "suspected_c2": True}),
        _e(150, "FILE_ACCESS", "HIGH", "Volume shadow copy deletion attempted via vss_delete_sim (simulated; nothing deleted)",
           username="employee_55", device="WS-1055", meta={"suspicious": True}),
    ]
    return evs


def _insider_events():
    evs = [
        _e(20, "LOGIN_SUCCESS", "MEDIUM", "employee_08 logged in at 02:14 local — outside normal working hours (simulated)",
           source="10.10.8.8", destination="10.10.4.21", username="employee_08", device="WS-1008",
           meta={"off_hours": True, "hour": 2}),
    ]
    for i in range(10):
        evs.append(_e(40 + i * 13, "FILE_ACCESS", "MEDIUM",
                      f"Bulk access {i + 1}/10: \\\\fileserver\\rd\\project_nova_{i}.zip (simulated)",
                      username="employee_08", device="WS-1008",
                      meta={"path": f"\\\\fileserver\\rd\\project_nova_{i}.zip", "bulk": True}))
    evs += [
        _e(180, "DEVICE_CONNECT", "MEDIUM", "Removable media connected: USB_SIM_04 on WS-1008 (simulated)",
           username="employee_08", device="WS-1008", meta={"device_id": "USB_SIM_04"}),
        _e(220, "DATA_TRANSFER", "CRITICAL", "Large transfer: 4.8 GB from WS-1008 to external 192.0.2.55 (simulated exfiltration)",
           source="10.10.8.8", destination="192.0.2.55", username="employee_08", device="WS-1008",
           meta={"bytes": 5153960755, "direction": "outbound"}),
    ]
    return evs


def _webattack_events():
    evs = []
    for i in range(10):
        evs.append(_e(10 + i * 6, "WEB_REQUEST", "LOW",
                      f"HTTP GET /login attempt {i + 1}/10 from 203.0.113.77 (simulated WAF log)",
                      source="203.0.113.77", destination="10.10.9.1", device="WEB-SRV-01",
                      meta={"method": "GET", "path": "/login", "user_agent": "sqlmap-sim/1.0"}))
    evs += [
        _e(80, "WEB_ATTACK", "HIGH", "SQL injection attempt blocked/logged: GET /products?id=' OR '1'='1 (inert payload string, simulated)",
           source="203.0.113.77", destination="10.10.9.1", device="WEB-SRV-01",
           meta={"payload": "' OR '1'='1", "path": "/products", "waf_action": "logged"}),
        _e(110, "LOGIN_SUCCESS", "CRITICAL", "Admin login to web console from attacker IP 203.0.113.77 (simulated takeover)",
           source="203.0.113.77", destination="10.10.9.1", username="admin", device="WEB-SRV-01",
           meta={"unusual_ip": True, "via_web": True}),
        _e(150, "DATABASE_QUERY", "CRITICAL", "Suspicious query: SELECT * FROM sim_customers (simulated full-table dump)",
           username="admin", device="WEB-SRV-01", meta={"query": "SELECT * FROM sim_customers", "dump_like": True}),
        _e(190, "DATA_TRANSFER", "CRITICAL", "Outbound 1.2 GB from WEB-SRV-01 to 203.0.113.77 (simulated exfiltration)",
           source="10.10.9.1", destination="203.0.113.77", username="admin", device="WEB-SRV-01",
           meta={"bytes": 1288490188, "direction": "outbound"}),
    ]
    return evs


SCENARIOS = [
    {
        "name": "Brute Force — Account Compromise",
        "description": "An external attacker brute-forces employee_42's password, gains access, and exfiltrates data. Detect the attack chain and contain it.",
        "attack_type": "Credential Access",
        "difficulty": "Easy",
        "initial_state": {"network": "10.10.0.0/16", "users": ["employee_42"], "devices": ["WS-1042"]},
        "definition": {
            "story": "Overnight, an external IP begins hammering the VPN login for employee_42. After a dozen failures the password gives way — the attacker logs in, touches the finance share, and starts pulling data out.",
            "environment": {"network": "10.10.0.0/16", "attacker_ip": "198.51.100.23", "victim": "employee_42"},
            "event_sequence": _brute_force_events(),
            "alert_rules": [
                {"id": "bf-fails", "type": "count", "event_type": "LOGIN_FAILURE", "window_sec": 120, "threshold": 5,
                 "severity": "MEDIUM", "category": "Authentication", "title": "Multiple failed logins",
                 "description": "5+ failed logins for the same user within 2 minutes — possible brute force."},
                {"id": "bf-success", "type": "sequence", "first_type": "LOGIN_FAILURE", "second_type": "LOGIN_SUCCESS",
                 "window_sec": 300, "match_field": "username",
                 "severity": "HIGH", "category": "Authentication", "title": "Possible brute-force account compromise",
                 "description": "Successful login shortly after repeated failures for the same user."},
                {"id": "bf-exfil", "type": "field_threshold", "event_type": "DATA_TRANSFER", "field": "bytes",
                 "op": ">", "value": 1000000000,
                 "severity": "CRITICAL", "category": "Exfiltration", "title": "Large outbound data transfer",
                 "description": "Outbound transfer larger than 1 GB detected."},
            ],
            "attack_chain": [
                {"phase": "Initial Access", "description": "Attacker guesses the password via repeated login attempts.", "technique_ids": ["T1110"]},
                {"phase": "Persistence", "description": "Attacker authenticates as employee_42 and holds a valid session.", "technique_ids": ["T1078"]},
                {"phase": "Exfiltration", "description": "2.4 GB is pushed to the external attacker IP.", "technique_ids": ["T1041"]},
            ],
            "expected_actions": [
                {"action_type": "DISABLE_USER", "target": "employee_42", "points": 10, "why": "Stops the attacker using the compromised account."},
                {"action_type": "BLOCK_IP", "target": "198.51.100.23", "points": 8, "why": "Cuts off the attacker's access path."},
                {"action_type": "RESET_CREDENTIAL", "target": "employee_42", "points": 4, "why": "Invalidates the guessed password."},
                {"action_type": "REVOKE_SESSION", "target": "employee_42", "points": 3, "why": "Kills the attacker's active session."},
            ],
            "wrong_actions": [
                {"action_type": "MARK_FALSE_POSITIVE", "target": "*", "penalty": 10,
                 "reason": "The brute-force alerts were genuine — marking them false positive blinds you."},
                {"action_type": "ISOLATE_ENDPOINT", "target": "WS-0001", "penalty": 5,
                 "reason": "WS-0001 was not involved; isolating the wrong host wastes response capacity."},
            ],
            "mitre_technique_ids": ["T1110", "T1078", "T1041"],
            "expected_severity": "HIGH",
            "estimated_duration_sec": 240,
        },
    },
    {
        "name": "Phishing — Credential Theft & Account Takeover",
        "description": "employee_17 receives a fake invoice email, clicks the link, and loses credentials. The attacker takes over the mailbox and exfiltrates data.",
        "attack_type": "Initial Access",
        "difficulty": "Easy",
        "initial_state": {"network": "10.10.0.0/16", "users": ["employee_17"], "devices": ["WS-1017"]},
        "definition": {
            "story": "A convincing invoice email lands in employee_17's inbox. One click later the credentials are gone; the attacker resets the password, plants a forwarding rule, and exports the mailbox.",
            "environment": {"network": "10.10.0.0/16", "attacker_ip": "203.0.113.44", "victim": "employee_17"},
            "event_sequence": _phishing_events(),
            "alert_rules": [
                {"id": "ph-unusual-login", "type": "single", "event_type": "LOGIN_SUCCESS", "meta_flag": "unusual_ip",
                 "severity": "HIGH", "category": "Authentication", "title": "Login from unusual source",
                 "description": "Successful login from an IP never seen for this user."},
                {"id": "ph-pwreset", "type": "single", "event_type": "PASSWORD_RESET", "meta_flag": "initiated_by_attacker",
                 "severity": "HIGH", "category": "Account", "title": "Attacker-initiated password reset",
                 "description": "Password reset requested from a suspicious external IP."},
                {"id": "ph-mailrule", "type": "single", "event_type": "CONFIG_CHANGE", "meta_flag": "suspicious",
                 "severity": "MEDIUM", "category": "Persistence", "title": "Suspicious mailbox rule",
                 "description": "Auto-forward rule created — classic attacker persistence."},
                {"id": "ph-exfil", "type": "field_threshold", "event_type": "DATA_TRANSFER", "field": "bytes",
                 "op": ">", "value": 500000000,
                 "severity": "CRITICAL", "category": "Exfiltration", "title": "Large outbound data transfer",
                 "description": "Outbound transfer larger than 500 MB detected."},
            ],
            "attack_chain": [
                {"phase": "Initial Access", "description": "Phishing email with a malicious link.", "technique_ids": ["T1566"]},
                {"phase": "Execution", "description": "Victim clicks and submits credentials.", "technique_ids": ["T1204"]},
                {"phase": "Persistence", "description": "Attacker logs in with valid credentials and plants a mail rule.", "technique_ids": ["T1078"]},
                {"phase": "Exfiltration", "description": "Mailbox contents exported externally.", "technique_ids": ["T1041"]},
            ],
            "expected_actions": [
                {"action_type": "DISABLE_USER", "target": "employee_17", "points": 10, "why": "Stops further attacker use of the mailbox."},
                {"action_type": "RESET_CREDENTIAL", "target": "employee_17", "points": 6, "why": "The password is compromised and must be rotated."},
                {"action_type": "REVOKE_SESSION", "target": "employee_17", "points": 4, "why": "Kills attacker sessions."},
                {"action_type": "BLOCK_IP", "target": "203.0.113.44", "points": 5, "why": "Blocks the phishing infrastructure."},
            ],
            "wrong_actions": [
                {"action_type": "MARK_FALSE_POSITIVE", "target": "*", "penalty": 10,
                 "reason": "The phishing chain was real — dismissing it lets the attacker persist."},
            ],
            "mitre_technique_ids": ["T1566", "T1204", "T1078", "T1041"],
            "expected_severity": "HIGH",
            "estimated_duration_sec": 240,
        },
    },
    {
        "name": "Privilege Escalation",
        "description": "A low-privilege service account is escalated to administrator, dumps credentials (simulated), and creates a backdoor account.",
        "attack_type": "Privilege Escalation",
        "difficulty": "Medium",
        "initial_state": {"network": "10.10.0.0/16", "users": ["svc_backup"], "devices": ["SRV-DB-01", "DC-SIM-01"]},
        "definition": {
            "story": "svc_backup is a quiet service account — until its role flips to Administrator overnight. Minutes later a credential-dumping tool runs and a new admin account appears.",
            "environment": {"network": "10.10.0.0/16", "victim": "svc_backup"},
            "event_sequence": _privesc_events(),
            "alert_rules": [
                {"id": "pe-privesc", "type": "single", "event_type": "PRIVILEGE_CHANGE",
                 "severity": "CRITICAL", "category": "Privilege", "title": "Privilege escalation detected",
                 "description": "Account role changed to Administrator outside a change window."},
                {"id": "pe-proc", "type": "single", "event_type": "PROCESS_START", "meta_flag": "suspicious",
                 "severity": "HIGH", "category": "Execution", "title": "Suspicious process started",
                 "description": "Known credential-dumping tool name observed (simulated)."},
                {"id": "pe-account", "type": "single", "event_type": "ACCOUNT_CREATED", "meta_flag": "suspicious",
                 "severity": "MEDIUM", "category": "Persistence", "title": "Suspicious account created",
                 "description": "New privileged account may be attacker persistence."},
            ],
            "attack_chain": [
                {"phase": "Privilege Escalation", "description": "Service account elevated to Administrator.", "technique_ids": ["T1068"]},
                {"phase": "Credential Access", "description": "Simulated dumping of the credential store.", "technique_ids": ["T1003"]},
                {"phase": "Persistence", "description": "Backdoor admin account created.", "technique_ids": ["T1136", "T1078"]},
            ],
            "expected_actions": [
                {"action_type": "DISABLE_USER", "target": "svc_backup", "points": 10, "why": "The escalated account must be frozen."},
                {"action_type": "DISABLE_USER", "target": "svc_backup_admin", "points": 8, "why": "Remove the attacker's backdoor account."},
                {"action_type": "REVOKE_SESSION", "target": "svc_backup", "points": 4, "why": "Kill active sessions of the compromised account."},
                {"action_type": "RESET_CREDENTIAL", "target": "svc_backup", "points": 3, "why": "Rotate the compromised credential."},
            ],
            "wrong_actions": [
                {"action_type": "MARK_FALSE_POSITIVE", "target": "*", "penalty": 12,
                 "reason": "A real privilege escalation was in progress."},
                {"action_type": "BLOCK_IP", "target": "8.8.8.8", "penalty": 5,
                 "reason": "Blocking a public DNS resolver does nothing against this attack."},
            ],
            "mitre_technique_ids": ["T1068", "T1003", "T1136", "T1078"],
            "expected_severity": "CRITICAL",
            "estimated_duration_sec": 210,
        },
    },
    {
        "name": "Ransomware Outbreak (Simulated)",
        "description": "A trojanized invoice attachment starts mass-encrypting files (simulated). Speed of isolation decides the outcome.",
        "attack_type": "Impact",
        "difficulty": "Hard",
        "initial_state": {"network": "10.10.0.0/16", "users": ["employee_55"], "devices": ["WS-1055"]},
        "definition": {
            "story": "employee_55 opens invoice_2026.exe. Within a minute, documents start flipping to .locked-sim and a ransom note appears. This is a race: isolate the endpoint before the simulated encryption spreads.",
            "environment": {"network": "10.10.0.0/16", "victim": "employee_55", "endpoint": "WS-1055"},
            "event_sequence": _ransomware_events(),
            "alert_rules": [
                {"id": "rw-edr", "type": "single", "event_type": "ENDPOINT_ALERT",
                 "severity": "CRITICAL", "category": "Impact", "title": "Ransomware-like behavior detected",
                 "description": "Endpoint reports mass file modification consistent with ransomware (simulated)."},
                {"id": "rw-massmod", "type": "count", "event_type": "FILE_MODIFY", "window_sec": 120, "threshold": 5,
                 "severity": "HIGH", "category": "Impact", "title": "Mass file modification",
                 "description": "5+ file modifications in 2 minutes on one endpoint."},
                {"id": "rw-note", "type": "single", "event_type": "FILE_CREATE", "meta_flag": "ransomware_like",
                 "severity": "CRITICAL", "category": "Impact", "title": "Ransom note created",
                 "description": "READ_ME_SIM.txt appeared on the desktop (simulated)."},
            ],
            "attack_chain": [
                {"phase": "Execution", "description": "User runs the trojanized attachment.", "technique_ids": ["T1204", "T1059"]},
                {"phase": "Impact", "description": "Simulated mass encryption of dummy documents.", "technique_ids": ["T1486"]},
                {"phase": "Command & Control", "description": "Callback to external test-net IP.", "technique_ids": ["T1071"]},
            ],
            "expected_actions": [
                {"action_type": "ISOLATE_ENDPOINT", "target": "WS-1055", "points": 12, "why": "Isolation is the #1 priority — it stops simulated spread immediately."},
                {"action_type": "DISABLE_USER", "target": "employee_55", "points": 6, "why": "Prevents re-execution / lateral movement."},
                {"action_type": "BLOCK_IP", "target": "192.0.2.10", "points": 5, "why": "Cuts the C2 callback."},
            ],
            "wrong_actions": [
                {"action_type": "MARK_FALSE_POSITIVE", "target": "*", "penalty": 15,
                 "reason": "Dismissing a ransomware outbreak is the worst possible call."},
                {"action_type": "RESET_CREDENTIAL", "target": "employee_55", "penalty": 4,
                 "reason": "Password rotation does not stop running ransomware; isolation comes first."},
            ],
            "mitre_technique_ids": ["T1204", "T1059", "T1486", "T1071"],
            "expected_severity": "CRITICAL",
            "estimated_duration_sec": 200,
        },
    },
    {
        "name": "Insider Threat — Data Exfiltration",
        "description": "employee_08 logs in at 2 AM, bulk-accesses the R&D share, plugs in USB media (simulated), and exfiltrates 4.8 GB.",
        "attack_type": "Exfiltration",
        "difficulty": "Medium",
        "initial_state": {"network": "10.10.0.0/16", "users": ["employee_08"], "devices": ["WS-1008"]},
        "definition": {
            "story": "Nobody should be in the R&D share at 2 AM. employee_08 opens dozens of project archives, mounts removable media, and pushes gigabytes out to an external IP.",
            "environment": {"network": "10.10.0.0/16", "insider": "employee_08"},
            "event_sequence": _insider_events(),
            "alert_rules": [
                {"id": "in-offhours", "type": "single", "event_type": "LOGIN_SUCCESS", "meta_flag": "off_hours",
                 "severity": "MEDIUM", "category": "Anomaly", "title": "Off-hours login",
                 "description": "Login outside the user's normal working hours."},
                {"id": "in-bulk", "type": "count", "event_type": "FILE_ACCESS", "window_sec": 300, "threshold": 8,
                 "severity": "HIGH", "category": "Collection", "title": "Unusual bulk file access",
                 "description": "8+ file accesses in 5 minutes — possible collection for exfiltration."},
                {"id": "in-exfil", "type": "field_threshold", "event_type": "DATA_TRANSFER", "field": "bytes",
                 "op": ">", "value": 2000000000,
                 "severity": "CRITICAL", "category": "Exfiltration", "title": "Large outbound data transfer",
                 "description": "Outbound transfer larger than 2 GB detected."},
            ],
            "attack_chain": [
                {"phase": "Discovery", "description": "Bulk enumeration of the R&D share.", "technique_ids": ["T1083"]},
                {"phase": "Collection", "description": "Dozens of archives staged from the network share.", "technique_ids": ["T1039"]},
                {"phase": "Exfiltration", "description": "4.8 GB pushed to an external IP; USB media also mounted.", "technique_ids": ["T1041"]},
            ],
            "expected_actions": [
                {"action_type": "DISABLE_USER", "target": "employee_08", "points": 10, "why": "Immediately stops the insider's access."},
                {"action_type": "REVOKE_SESSION", "target": "employee_08", "points": 5, "why": "Kills active sessions."},
                {"action_type": "BLOCK_IP", "target": "192.0.2.55", "points": 5, "why": "Blocks the exfiltration destination."},
                {"action_type": "RESET_CREDENTIAL", "target": "employee_08", "points": 3, "why": "Rotate credentials during investigation."},
            ],
            "wrong_actions": [
                {"action_type": "ISOLATE_ENDPOINT", "target": "FILESERVER-01", "penalty": 8,
                 "reason": "Isolating the file server disrupts the whole company; target the user's workstation instead."},
                {"action_type": "MARK_FALSE_POSITIVE", "target": "*", "penalty": 10,
                 "reason": "The exfiltration pattern was unmistakable."},
            ],
            "mitre_technique_ids": ["T1083", "T1039", "T1041", "T1078"],
            "expected_severity": "HIGH",
            "estimated_duration_sec": 260,
        },
    },
    {
        "name": "Web Application Attack",
        "description": "Attackers probe the public web portal, inject SQL (simulated), hijack the admin session, and dump the customer database (simulated).",
        "attack_type": "Web Attack",
        "difficulty": "Medium",
        "initial_state": {"network": "10.10.0.0/16", "users": ["admin"], "devices": ["WEB-SRV-01"]},
        "definition": {
            "story": "The WAF log shows a burst of /login probes from one IP, then a classic SQL injection string. Minutes later the admin console is accessed from that same IP and the customer table is dumped.",
            "environment": {"network": "10.10.0.0/16", "attacker_ip": "203.0.113.77", "server": "WEB-SRV-01"},
            "event_sequence": _webattack_events(),
            "alert_rules": [
                {"id": "wa-flood", "type": "count", "event_type": "WEB_REQUEST", "window_sec": 120, "threshold": 8,
                 "severity": "MEDIUM", "category": "Reconnaissance", "title": "Web request flood",
                 "description": "8+ rapid requests to /login from one IP — possible brute force or scanning."},
                {"id": "wa-sqli", "type": "single", "event_type": "WEB_ATTACK",
                 "severity": "HIGH", "category": "Injection", "title": "SQL injection attempt",
                 "description": "Inert SQLi payload string observed in WAF logs (simulated)."},
                {"id": "wa-dump", "type": "single", "event_type": "DATABASE_QUERY", "meta_flag": "dump_like",
                 "severity": "CRITICAL", "category": "Exfiltration", "title": "Suspicious database dump",
                 "description": "Full-table SELECT consistent with data theft (simulated)."},
                {"id": "wa-exfil", "type": "field_threshold", "event_type": "DATA_TRANSFER", "field": "bytes",
                 "op": ">", "value": 1000000000,
                 "severity": "CRITICAL", "category": "Exfiltration", "title": "Large outbound data transfer",
                 "description": "Outbound transfer larger than 1 GB detected."},
            ],
            "attack_chain": [
                {"phase": "Initial Access", "description": "Public web app probed and injected.", "technique_ids": ["T1190"]},
                {"phase": "Persistence", "description": "Attacker operates with hijacked admin credentials.", "technique_ids": ["T1078"]},
                {"phase": "Exfiltration", "description": "Customer database dumped and exfiltrated (simulated).", "technique_ids": ["T1041"]},
            ],
            "expected_actions": [
                {"action_type": "BLOCK_IP", "target": "203.0.113.77", "points": 10, "why": "Stops the attacker at the perimeter."},
                {"action_type": "ISOLATE_ENDPOINT", "target": "WEB-SRV-01", "points": 8, "why": "Take the compromised web server out of rotation."},
                {"action_type": "RESET_CREDENTIAL", "target": "admin", "points": 5, "why": "The admin credential is compromised."},
                {"action_type": "REVOKE_SESSION", "target": "admin", "points": 2, "why": "Kill the hijacked session."},
            ],
            "wrong_actions": [
                {"action_type": "DISABLE_USER", "target": "employee_01", "penalty": 6,
                 "reason": "employee_01 had nothing to do with this attack."},
                {"action_type": "MARK_FALSE_POSITIVE", "target": "*", "penalty": 10,
                 "reason": "The injection and dump were genuine attack indicators."},
            ],
            "mitre_technique_ids": ["T1190", "T1078", "T1041"],
            "expected_severity": "CRITICAL",
            "estimated_duration_sec": 230,
        },
    },
]
