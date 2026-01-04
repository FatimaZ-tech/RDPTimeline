import datetime


class DFIRRuleEngine:

    def __init__(self, sessions):
        self.sessions = sessions
        self.results = []


    def _fmt(self, t):
        """Format timestamps safely for reporting."""
        if not t:
            return "Unknown Time"
        return str(t)


    def _correlation_note(self, e):
        """Explain how an event was correlated to the session."""
        c = e.get("_correlation")
        if c == "in_session":
            return "Correlation: in-session activity"
        elif c == "grace_before":
            return "Correlation: pre-session (grace window)"
        elif c == "grace_after":
            return "Correlation: post-session (grace window)"
        return "Correlation: unknown"


    def _add_finding(self, session, severity, rule_name, description):
        """Add a structured DFIR finding linked to a session."""
        self.results.append({
            "user": session.get("user"),
            "ip": session.get("source_ip"),
            "start": session.get("start_time"),
            "end": session.get("end_time"),
            "severity": severity,
            "rule": rule_name,
            "description": description
        })

# Rule categories:
# * Authentication abuse
# * Session anomalies
# * Persistence
# * Privilege escalation
# * Anti-forensics

    def run_rules(self):

        # Collect failed authentication attempts across all sessions
        global_failed = []
        for s in self.sessions:
            for e in s.get("events", []):
                if e["event_id"] == "4625" and e.get("parsed_time"):
                    global_failed.append(e)

        # Global brute-force indicator (cross-session behavior)
        if len(global_failed) >= 2:

            ips = set()
            users = set()
            timestamps = []

            for f in global_failed:
                ips.add(f["details"].get("IpAddress") or "UNKNOWN_IP")
                users.add(f["details"].get("TargetUserName") or "UNKNOWN_USER")
                timestamps.append(self._fmt(f.get("parsed_time") or f.get("timestamp")))

            self.results.append({
                "user": ", ".join(u for u in users if u != "UNKNOWN_USER") or None,
                "ip": ", ".join(i for i in ips if i != "UNKNOWN_IP") or None,
                "start": None,
                "end": None,
                "severity": "High",
                "rule": "Strong Brute Force Indicator",
                "description":
                    f"{len(global_failed)} failed RDP authentication attempts detected\n"
                    f"Users: {', '.join(users)}\n"
                    f"IPs: {', '.join(ips)}\n"
                    f"Timestamps:\n  " + "\n  ".join(timestamps)
            })

        # Process rules per reconstructed session
        for session in self.sessions:
            events = session.get("events", [])

            session_seen = {
                "tasks": set(),
                "services": set(),
                "user_created": False,
                "admin_add": False,
                "log_clear": False
            }

            # Flag unusually short or long sessions
            if session.get("start_time") and session.get("end_time"):
                duration = (session["end_time"] - session["start_time"]).total_seconds()

                if duration < 10:
                    self._add_finding(
                        session,
                        "Medium",
                        "Very Short RDP Session",
                        f"Duration: {duration} seconds | "
                        f"Start: {self._fmt(session['start_time'])} | "
                        f"End: {self._fmt(session['end_time'])}"
                    )

                if duration > 1800:
                    self._add_finding(
                        session,
                        "Medium",
                        "Very Long RDP Session",
                        f"Duration: {duration/60:.1f} minutes | "
                        f"Start: {self._fmt(session['start_time'])} | "
                        f"End: {self._fmt(session['end_time'])}"
                    )

            # Detect sessions without clean termination
            if session.get("end_time") is None:
                self._add_finding(
                    session,
                    "Low",
                    "Unclosed RDP Session",
                    f"No clean logoff detected | "
                    f"Session Start: {self._fmt(session['start_time'])}"
                )

            # Analyze DFIR-relevant events within the session
            for e in events:
                eid = e["event_id"]
                ts = self._fmt(e.get("parsed_time") or e.get("timestamp"))
                corr = self._correlation_note(e)

                # Local account creation
                if eid == "4720" and not session_seen["user_created"]:
                    session_seen["user_created"] = True
                    self._add_finding(
                        session,
                        "High",
                        "User Account Created",
                        f"Local account creation detected\n"
                        f"Event Time: {ts}\n{corr}"
                    )

                # Privilege escalation via group membership
                elif eid == "4732" and not session_seen["admin_add"]:
                    session_seen["admin_add"] = True
                    self._add_finding(
                        session,
                        "Critical",
                        "User Added To Administrators",
                        f"Privilege escalation detected\n"
                        f"Event Time: {ts}\n{corr}"
                    )

                # Scheduled task persistence
                elif eid in ("4698", "129"):

                    task_name = (
                        e["details"].get("TaskName")
                        or e["details"].get("Task")
                        or e["details"].get("TaskPath")
                        or e["details"].get("Name")
                        or "UnknownTask"
                    )

                    if task_name in session_seen["tasks"]:
                        continue
                    session_seen["tasks"].add(task_name)

                    KNOWN_SAFE = [
                        "\\Microsoft\\Windows\\", "Office", "Defrag",
                        "Idle Maintenance", "WindowsUpdate",
                        "Time Synchronization", "Customer Experience",
                        "Servicing", "Telemetry"
                    ]

                    if any(k.lower() in task_name.lower() for k in KNOWN_SAFE):
                        continue

                    self._add_finding(
                        session,
                        "High",
                        "Scheduled Task Persistence",
                        f"Task Created: {task_name}\n"
                        f"Event Time: {ts}\n{corr}"
                    )

                # Service-based persistence
                elif eid == "7045":

                    service = (
                        e["details"].get("ServiceName")
                        or e["details"].get("Service")
                        or "Unknown Service"
                    )

                    if service in session_seen["services"]:
                        continue
                    session_seen["services"].add(service)

                    binary = (
                        e["details"].get("ImagePath")
                        or e["details"].get("BinaryPath")
                        or "Unknown Binary"
                    )

                    self._add_finding(
                        session,
                        "Critical",
                        "Service Installed",
                        f"Service: {service}\n"
                        f"Binary: {binary}\n"
                        f"Event Time: {ts}\n{corr}"
                    )

                # Log clearing as anti-forensics
                elif eid == "1102" and not session_seen["log_clear"]:
                    session_seen["log_clear"] = True
                    self._add_finding(
                        session,
                        "Critical",
                        "Security Logs Cleared",
                        f"Log wipe detected\n"
                        f"Event Time: {ts}\n{corr}"
                    )

        print(f"[+] DFIR analysis completed. Findings: {len(self.results)}")
        return self.results
