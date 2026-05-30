from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from src.storage.database import Base
from src.storage.models import Subdomain, Vulnerability, Target


def _make_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_export_data_normalizes_lookup_target(tmp_path):
    from cli.commands.export import export_data

    session = _make_session()
    try:
        session.add(Target(domain="example.com"))
        session.add(Subdomain(domain="api.example.com", is_live=1, business_impact="HIGH"))
        session.commit()

        with patch("cli.commands.export.SessionLocal", return_value=session):
            export_data.main(
                [
                    "https://example.com./path",
                    "--format",
                    "json",
                    "--output",
                    str(tmp_path / "out.json"),
                ],
                standalone_mode=False,
            )

        assert (tmp_path / "out.json").exists()
    finally:
        session.close()


def test_secrets_command_normalizes_lookup_target():
    from cli.commands.secrets import secrets

    session = _make_session()
    try:
        session.add(Target(domain="example.com"))
        session.add(Subdomain(domain="api.example.com", is_live=1))
        session.commit()

        with (
            patch("cli.commands.secrets.SessionLocal", return_value=session),
            patch(
                "cli.commands.secrets.tool_manager.run_capability", return_value=[]
            ) as mock_run_capability,
        ):
            secrets.main(
                ["https://example.com./path", "--limit", "5", "--threads", "1"],
                standalone_mode=False,
            )

        assert mock_run_capability.called
        assert mock_run_capability.call_args.args[0] == "spidering"
        assert mock_run_capability.call_args.args[1] == "https://api.example.com"
    finally:
        session.close()


def test_analyze_command_normalizes_lookup_target():
    from cli.commands.analyze import analyze

    session = _make_session()
    try:
        session.add(Target(domain="example.com"))
        session.add(
            Subdomain(domain="api.example.com", semantic_labels=["public"], business_impact="HIGH")
        )
        session.add(Vulnerability(host="api.example.com", name="xss", severity="high"))
        session.commit()

        with (
            patch("cli.commands.analyze.SessionLocal", return_value=session),
            patch(
                "cli.commands.analyze.ai_analyst.generate_finding_narrative",
                return_value={"analysis": "ok", "business_impact": "HIGH", "recommendations": []},
            ) as mock_ai,
            patch("cli.commands.analyze.render_panel"),
            patch("cli.commands.analyze.render_outcome"),
            patch("cli.commands.analyze.console.print"),
        ):
            analyze.main(["https://api.example.com./path"], standalone_mode=False)

        assert mock_ai.called
    finally:
        session.close()
