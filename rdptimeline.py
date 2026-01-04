import argparse
import os

# Core pipeline components
from loader import LogLoader
from parser import RDPEventParser
from timeline import RDPTimelineBuilder
from rules import DFIRRuleEngine
from ml_anomaly import MLAnomalyDetector
from AI_report import AIForensicReporter


def main():
    # CLI argument parser for DFIR workflow
    parser = argparse.ArgumentParser(
        description="RDP DFIR Timeline Tool"
    )

    # Optional EVTX log inputs (at least one must be provided)
    parser.add_argument("--security", help="Path to Security.evtx log")
    parser.add_argument("--ts", help="Path to RemoteConnectionManager.evtx")
    parser.add_argument("--lsm", help="Path to LocalSessionManager.evtx")
    parser.add_argument("--system", help="Path to System.evtx (Service Install Logs)")
    parser.add_argument("--tasks", help="Path to TaskScheduler.evtx (Optional)")

    # Optional ML analysis (disabled by default)
    parser.add_argument(
        "--enable-ml",
        action="store_true",
        help="Enable optional ML-based session anomaly detection (experimental)"
    )

    # Optional AI-assisted reporting (disabled by default)
    parser.add_argument(
        "--enable-ai-report",
        action="store_true",
        help="Enable optional AI-assisted forensic reporting"
    )

    args = parser.parse_args()

    print("\n[+] Initializing Log Loader...\n")

    # Validate provided EVTX paths without parsing
    loader = LogLoader(
        security=args.security,
        ts=args.ts,
        lsm=args.lsm,
        system=args.system,
        tasks=args.tasks
    )

    logs = loader.load_logs()
    print("\n[+] Logs validated successfully")

    # Parse EVTX logs into normalized event structures
    print("\n[+] Starting EVTX Parsing...\n")
    parser_engine = RDPEventParser()

    if logs.get("security"):
        parser_engine.parse_evtx(logs["security"], "Security")

    if logs.get("ts"):
        parser_engine.parse_evtx(logs["ts"], "RemoteConnectionManager")

    if logs.get("lsm"):
        parser_engine.parse_evtx(logs["lsm"], "LocalSessionManager")

    # System and TaskScheduler logs support persistence detection
    if logs.get("system"):
        parser_engine.parse_evtx(logs["system"], "System")

    if logs.get("tasks"):
        parser_engine.parse_evtx(logs["tasks"], "TaskScheduler")

    events = parser_engine.get_events()

    

    print(f"\n[+] TOTAL DFIR Events Extracted: {len(events)}")

    # Build a global time-ordered event timeline
    print("\n[+] Building Timeline...")
    timeline_builder = RDPTimelineBuilder(events)
    timeline_builder.build_timeline()

    # Reconstruct RDP sessions using DFIR semantics
    print("\n[+] Building RDP Sessions...")
    sessions = timeline_builder.build_sessions()

    print(f"\n[+] FINAL SESSIONS COUNT: {len(sessions)}")

    # Apply DFIR rule-based analysis to reconstructed sessions
    print("\n[+] Running DFIR Rule Engine...")
    rule_engine = DFIRRuleEngine(sessions)
    findings = rule_engine.run_rules()

    # Human-readable session-centric output
    print("\n========== RDP SESSIONS REPORT ==========")

    for i, s in enumerate(sessions, 1):
        print(f"\n================ SESSION {i} ================")
        print("User:", s["user"])
        print("IP:", s["source_ip"])
        print("Start:", s["start_time"])
        print("End:", s["end_time"])
        print("Events in Session:", len(s["events"]))

        # Match findings to sessions by session start time
        related = [f for f in findings if f["start"] == s["start_time"]]

        if not related:
            print("\nStatus: CLEAN ✔️ (No suspicious behavior detected)")
        else:
            print("\nStatus: SUSPICIOUS ⚠️")
            for f in related:
                print("\n Rule:", f["rule"])
                print(" Severity:", f["severity"])
                print(" Description:", f["description"])

    # Global overview of all detected findings
    print("\n========== GLOBAL DFIR SUMMARY ==========")
    if not findings:
        print("No suspicious activity detected across all sessions.")
    else:
        print(f"Total Findings: {len(findings)}")
        for f in findings:
            print(f"- {f['rule']} ({f['severity']})")

    # Optional ML-based anomaly detection
    if args.enable_ml:
        print("\n[+] Running Machine Learning Anomaly Detection (optional)...")
        ml_engine = MLAnomalyDetector(sessions)
        ml_findings = ml_engine.run()
        findings.extend(ml_findings)
    else:
        print("\n[+] ML anomaly detection skipped (disabled by default)")

    # Optional AI-assisted forensic reporting
    if args.enable_ai_report:
        print("\n[+] AI-assisted forensic reporting enabled")

        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            try:
                api_key = input("Enter OpenAI API key (leave empty to skip AI report): ").strip()
            except KeyboardInterrupt:
                api_key = None

        if not api_key:
            print("[+] AI report skipped (no API key provided)")
        else:
            ai_reporter = AIForensicReporter(api_key=api_key)

            print("\n========== AI FORENSIC EXPLANATIONS ==========")

            for i, s in enumerate(sessions, 1):
                related = [f for f in findings if f["start"] == s["start_time"]]
                if not related:
                    continue

                session_summary = {
                    "session_id": i,
                    "user": s.get("user"),
                    "ip": s.get("source_ip"),
                    "start_time": str(s.get("start_time")),
                    "end_time": str(s.get("end_time")),
                    "findings": related
                }

                print(f"\n--- AI Report for Session {i} ---")
                report = ai_reporter.generate_report(session_summary)
                print(report)
    else:
        print("\n[+] AI-assisted reporting skipped (disabled by default)")


if __name__ == "__main__":
    main()
