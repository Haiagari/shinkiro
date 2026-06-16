"""Tests for DiffEngine and DiffReport."""
import pytest
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.storage.diff import DiffEngine, DiffReport
from src.storage.models import Base, Target, Scan, Subdomain, Port, Vulnerability


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


class TestDiffReport:
    def test_empty_report_has_no_changes(self):
        report = DiffReport(target="example.com")
        assert not report.has_changes()

    def test_report_with_new_subdomains_has_changes(self):
        report = DiffReport(target="example.com", new_subdomains=["api.example.com"])
        assert report.has_changes()

    def test_report_with_new_ports_has_changes(self):
        report = DiffReport(target="example.com", new_ports=[{"host": "x", "port": 443}])
        assert report.has_changes()

    def test_report_with_new_findings_has_changes(self):
        report = DiffReport(target="example.com", new_findings=["SQLi"])
        assert report.has_changes()

    def test_empty_summary_returns_no_changes(self):
        report = DiffReport(target="example.com")
        assert report.summary() == "No changes detected"

    def test_summary_includes_new_subdomains(self):
        report = DiffReport(target="example.com", new_subdomains=["api.example.com"])
        assert "+1 subdomains" in report.summary()

    def test_summary_includes_removed_subdomains(self):
        report = DiffReport(target="example.com", removed_subdomains=["old.example.com"])
        assert "-1 subdomains" in report.summary()

    def test_summary_includes_metadata_changes(self):
        report = DiffReport(target="example.com", changed_subdomains=[{"domain": "x", "changes": {"ip": {}}}])
        assert "*1 metadata changes" in report.summary()

    def test_summary_includes_new_ports(self):
        report = DiffReport(target="example.com", new_ports=[{"host": "x", "port": 443}])
        assert "+1 ports" in report.summary()

    def test_summary_includes_closed_ports(self):
        report = DiffReport(target="example.com", closed_ports=[{"host": "x", "port": 80}])
        assert "-1 ports" in report.summary()

    def test_summary_includes_changed_services(self):
        report = DiffReport(target="example.com", changed_services=[{"host": "x", "port": 443}])
        assert "*1 services" in report.summary()

    def test_summary_includes_findings(self):
        report = DiffReport(target="example.com", new_findings=["XSS"])
        assert "!1 findings" in report.summary()

    def test_summary_combined_changes(self):
        report = DiffReport(
            target="example.com",
            new_subdomains=["a.example.com"],
            new_ports=[{"host": "x", "port": 443}],
            new_findings=["SQL Injection"],
        )
        summary = report.summary()
        assert "+1 subdomains" in summary
        assert "+1 ports" in summary
        assert "!1 findings" in summary

    def test_to_dict_returns_all_fields(self):
        report = DiffReport(
            target="example.com",
            new_subdomains=["api.example.com"],
            removed_subdomains=["old.example.com"],
        )
        d = report.to_dict()
        assert d["target"] == "example.com"
        assert "api.example.com" in d["new_subdomains"]
        assert "old.example.com" in d["removed_subdomains"]


class TestDiffEngine:
    def _setup_two_scans(self, session):
        target = Target(domain="diff.example.com")
        session.add(target)
        session.flush()

        prev_scan = Scan(
            target_id=target.id,
            session_id="prev-scan",
            status="completed",
            mode="hunt",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
        )
        session.add(prev_scan)
        session.flush()

        curr_scan = Scan(
            target_id=target.id,
            session_id="curr-scan",
            status="completed",
            mode="hunt",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
        )
        session.add(curr_scan)
        session.flush()

        return target, prev_scan, curr_scan

    def test_get_diff_no_previous_scan_returns_empty(self):
        session = _make_session()
        target = Target(domain="first-run.example.com")
        session.add(target)
        session.flush()
        curr_scan = Scan(
            target_id=target.id,
            session_id="first-scan",
            status="completed",
            mode="hunt",
        )
        session.add(curr_scan)
        session.commit()

        engine = DiffEngine(session)
        report = engine.get_diff("first-run.example.com", curr_scan.id)
        assert not report.has_changes()
        session.close()

    def test_get_diff_auto_finds_previous_scan(self):
        session = _make_session()
        target, prev_scan, curr_scan = self._setup_two_scans(session)
        session.add(Subdomain(scan_id=prev_scan.id, domain="old.example.com", is_live=0))
        session.add(Subdomain(scan_id=curr_scan.id, domain="new.example.com", is_live=1))
        session.commit()

        engine = DiffEngine(session)
        report = engine.get_diff("diff.example.com", curr_scan.id)
        assert report.has_changes()
        assert "new.example.com" in report.new_subdomains
        assert "old.example.com" in report.removed_subdomains
        session.close()

    def test_diff_subdomains_detects_new_removed_changed(self):
        session = _make_session()
        _, prev_scan, curr_scan = self._setup_two_scans(session)
        session.add(Subdomain(scan_id=prev_scan.id, domain="old.example.com", ip="1.1.1.1", is_live=0))
        session.add(Subdomain(scan_id=prev_scan.id, domain="common.example.com", ip="2.2.2.2", title="Old Title", is_live=1))
        session.commit()
        session.add(Subdomain(scan_id=curr_scan.id, domain="common.example.com", ip="3.3.3.3", title="New Title", is_live=1))
        session.add(Subdomain(scan_id=curr_scan.id, domain="new.example.com", ip="4.4.4.4", is_live=1))
        session.commit()

        engine = DiffEngine(session)
        report = DiffReport(target="diff.example.com")
        engine._diff_subdomains(curr_scan.id, prev_scan.id, report)

        assert "new.example.com" in report.new_subdomains
        assert "old.example.com" in report.removed_subdomains
        assert len(report.changed_subdomains) == 1
        assert report.changed_subdomains[0]["domain"] == "common.example.com"
        session.close()

    def test_diff_ports_detects_new_closed_changed(self):
        session = _make_session()
        _, prev_scan, curr_scan = self._setup_two_scans(session)
        session.add(Port(scan_id=prev_scan.id, host="x.example.com", port=80, service="http", version="1.0", product="nginx", state="open"))
        session.add(Port(scan_id=prev_scan.id, host="x.example.com", port=443, service="https", version="1.0", product="nginx", state="open"))
        session.commit()
        session.add(Port(scan_id=curr_scan.id, host="x.example.com", port=443, service="https", version="2.0", product="nginx", state="open"))
        session.add(Port(scan_id=curr_scan.id, host="x.example.com", port=8080, service="http", version="1.0", product="apache", state="open"))
        session.commit()

        engine = DiffEngine(session)
        report = DiffReport(target="diff.example.com")
        engine._diff_ports(curr_scan.id, prev_scan.id, report)

        assert len(report.new_ports) == 1
        assert report.new_ports[0]["port"] == 8080
        assert len(report.closed_ports) == 1
        assert report.closed_ports[0]["port"] == 80
        assert len(report.changed_services) == 1
        assert report.changed_services[0]["port"] == 443
        session.close()

    def test_diff_findings_detects_new(self):
        session = _make_session()
        _, prev_scan, curr_scan = self._setup_two_scans(session)
        session.add(Vulnerability(scan_id=prev_scan.id, name="Old Finding", host="x.example.com", path="/old", severity="medium"))
        session.commit()
        session.add(Vulnerability(scan_id=curr_scan.id, name="New Finding", host="x.example.com", path="/new", severity="high"))
        session.commit()

        engine = DiffEngine(session)
        report = DiffReport(target="diff.example.com")
        engine._diff_findings(curr_scan.id, prev_scan.id, report)

        assert len(report.new_findings) == 1
        assert "New Finding" in list(report.new_findings)[0]
        session.close()

    def test_detect_version_shifts_finds_changes(self):
        engine = DiffEngine(None)
        old_techs = ["WordPress:6.9", "PHP:8.0"]
        new_techs = ["WordPress:7.0", "PHP:8.0"]
        shifts = engine._detect_version_shifts(old_techs, new_techs)
        assert len(shifts) == 1
        assert shifts[0]["technology"] == "WordPress"
        assert shifts[0]["from"] == "6.9"
        assert shifts[0]["to"] == "7.0"

    def test_detect_version_shifts_returns_empty_when_no_changes(self):
        engine = DiffEngine(None)
        shifts = engine._detect_version_shifts(["WordPress:6.9"], ["WordPress:6.9"])
        assert shifts == []

    def test_tech_list_to_map_parses_versioned_and_unversioned(self):
        result = DiffEngine._tech_list_to_map(["WordPress:6.9", "PHP", "nginx:1.21"])
        assert result == {"WordPress": "6.9", "PHP": None, "nginx": "1.21"}

    def test_tech_list_to_map_handles_empty_list(self):
        result = DiffEngine._tech_list_to_map([])
        assert result == {}
