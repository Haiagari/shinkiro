from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.modes.hunt import _get_scoped_ports, _get_scoped_subdomains, _get_top_critical_ports
from src.storage.models import Base, Port, Scan, Subdomain, Target


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_hunt_helpers_scope_results_to_current_scan():
    session = _session()

    target_a = Target(domain="a.example.com")
    target_b = Target(domain="b.example.com")
    session.add_all([target_a, target_b])
    session.commit()

    scan_a = Scan(target_id=target_a.id, session_id="scan-a", mode="hunt")
    scan_b = Scan(target_id=target_b.id, session_id="scan-b", mode="hunt")
    session.add_all([scan_a, scan_b])
    session.commit()

    session.add_all([
        Subdomain(scan_id=scan_a.id, domain="live-a.example.com", is_live=1),
        Subdomain(scan_id=scan_b.id, domain="live-b.example.com", is_live=1),
        Port(scan_id=scan_a.id, host="live-a.example.com", port=443, criticality_index=90),
        Port(scan_id=scan_b.id, host="live-b.example.com", port=443, criticality_index=99),
    ])
    session.commit()

    subdomains = _get_scoped_subdomains(session, scan_a.id)
    ports = _get_scoped_ports(session, scan_a.id)
    top = _get_top_critical_ports(session, scan_a.id)

    assert [sub.domain for sub in subdomains] == ["live-a.example.com"]
    assert [port.host for port in ports] == ["live-a.example.com"]
    assert [port.host for port in top] == ["live-a.example.com"]
