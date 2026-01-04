import os
import json
from typing import Dict

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


def _json_safe(obj):
    # Convert datetime and other non-JSON types into safe string form
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


class AIForensicReporter:
    """
    Optional AI-assisted forensic reporting component.

    This module does NOT detect attacks.
    It only explains already-validated DFIR findings.
    """

    def __init__(self, api_key: str = None, model: str = "gpt-4o-mini"):
        # API key can be passed explicitly or via environment variable
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model

        # Enable AI only if dependency and key are available
        self.enabled = bool(self.api_key and OpenAI)
        self.client = OpenAI(api_key=self.api_key) if self.enabled else None


    def _build_prompt(self, session_summary: Dict) -> str:
        """Build a constrained, evidence-only DFIR explanation prompt."""

        return f"""
You are a senior Digital Forensics & Incident Response (DFIR) analyst.

Below is a reconstructed RDP session and validated DFIR findings.
Your task is to explain the activity using a professional incident-response tone.

Rules:
- Do NOT speculate beyond the evidence.
- Do NOT invent indicators or assumptions.
- Base your explanation strictly on timestamps and events provided.

SESSION SUMMARY:
{json.dumps(session_summary, indent=2, default=_json_safe)}

Your response must include:
- Attack narrative (chronological sequence)
- Likely attacker intent
- Why this activity is suspicious
- Confidence level (Low / Medium / High)

Keep the explanation concise and technical.
"""


    def generate_report(self, session_summary: Dict) -> str:
        """Generate an AI-assisted explanation for a single session."""

        if not self.enabled:
            return (
                "[AI REPORT NOT GENERATED]\n"
                "Reason: AI reporting disabled (no API key or dependency).\n"
                "DFIR findings above remain authoritative."
            )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a DFIR expert."},
                    {"role": "user", "content": self._build_prompt(session_summary)}
                ],
                temperature=0.2
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            return (
                "[AI REPORT ERROR]\n"
                f"{str(e)}\n"
                "DFIR findings above remain authoritative."
            )
