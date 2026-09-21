import pytest
import sys
from pathlib import Path

# Add engine directory to path
current_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(current_dir))

from postmortem_generator import PostMortemGenerator

def test_generate_report_data():
    data = PostMortemGenerator.generate_report_data(
        incident_id="TEST-INC-001",
        prefix="208.67.222.0/24",
        hijacked_subprefix="208.67.222.0/25",
        rogue_asn=4761
    )
    assert data["incident_id"] == "TEST-INC-001"
    assert data["severity"] == "CRITICAL"
    assert data["target_prefix"] == "208.67.222.0/24"
    assert data["rogue_asn"] == 4761
    assert len(data["timeline"]) == 5
    assert "junos_flowspec" in data["mitigation_playbooks"]
    assert len(data["preventive_actions"]) >= 3

def test_markdown_formatting():
    data = PostMortemGenerator.generate_report_data(incident_id="TEST-INC-002")
    md = PostMortemGenerator.to_markdown(data)
    assert "# Security Incident Post-Mortem" in md
    assert "Executive Summary" in md
    assert "Technical Root Cause Analysis" in md
    assert "Incident Timeline" in md
    assert "Juniper Junos" in md

def test_html_formatting():
    data = PostMortemGenerator.generate_report_data(incident_id="TEST-INC-003")
    html = PostMortemGenerator.to_html(data)
    assert "<!DOCTYPE html>" in html
    assert "TEST-INC-003" in html
    assert "window.print()" in html
    assert "timeline-entry" in html
