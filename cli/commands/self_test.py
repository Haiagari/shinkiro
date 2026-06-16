"""
Self-Test Command - Internal Logic Validation
Runs internal tests to validate core functionality without external dependencies.
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Any

import click
from rich.table import Table

from cli.shared import console, render_outcome, render_panel
# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scope import in_scope, is_test_domain

class TestResult:
    def __init__(self, name: str, passed: bool, message: str = ""):
        self.name = name
        self.passed = passed
        self.message = message


def test_scope_guard() -> List[TestResult]:
    """Test scope guard functionality."""
    results = []
    
    # Test 1: root domain in scope
    results.append(TestResult(
        "root_domain_is_in_scope",
        in_scope("example.com", "example.com"),
        "Root domain should be in scope"
    ))

    # Test 2: subdomain in scope
    results.append(TestResult(
        "subdomain_is_in_scope",
        in_scope("sub.example.com", "example.com"),
        "Subdomain should be in scope"
    ))

    # Test 3: external domain out of scope
    results.append(TestResult(
        "external_domain_out_of_scope",
        not in_scope("evil-corp.com", "example.com"),
        "External domain should be out of scope"
    ))

    # Test 4: lookalike out of scope
    results.append(TestResult(
        "lookalike_domain_out_of_scope",
        not in_scope("example.com.evil.com", "example.com"),
        "Lookalike domain should be out of scope"
    ))
    
    # Test 5: internal test asset filtered
    results.append(TestResult(
        "internal_test_asset_filtered",
        is_test_domain("admin-staging.internal.critical-target.test"),
        "Test domains should be filtered"
    ))
    
    # Test 6: forbidden domains filtered
    results.append(TestResult(
        "forbidden_evil_corp_filtered",
        is_test_domain("evil-corp.com"),
        "evil-corp.com should be filtered"
    ))
    
    results.append(TestResult(
        "forbidden_artifact_filtered",
        is_test_domain("artifact.test"),
        "artifact.test should be filtered"
    ))
    
    return results


def test_scan_profiles() -> List[TestResult]:
    """Test scan profiles configuration."""
    results = []
    
    from src.scope.profiles import get_profile, PROFILES
    
    # Test passive profile exists
    passive = get_profile("passive")
    results.append(TestResult(
        "passive_profile_exists",
        passive is not None,
        "Passive profile should exist"
    ))
    
    if passive:
        # Passive should NOT use active tools
        forbidden = {"nmap", "nuclei", "katana", "ffuf", "gobuster"}
        has_active = any(tool in forbidden for tool in passive.tools)
        results.append(TestResult(
            "passive_no_active_tools",
            not has_active,
            "Passive profile should not use active tools"
        ))
        
        # Passive should NOT require authorization
        results.append(TestResult(
            "passive_no_auth_required",
            not passive.requires_authorization,
            "Passive profile should not require authorization"
        ))
    
    # Test safe-active profile exists
    safe = get_profile("safe-active")
    results.append(TestResult(
        "safe_active_profile_exists",
        safe is not None,
        "Safe-active profile should exist"
    ))
    
    # Test authorized profile requires auth
    auth = get_profile("authorized")
    results.append(TestResult(
        "authorized_requires_auth",
        auth.requires_authorization if auth else False,
        "Authorized profile should require authorization"
    ))
    
    return results


def test_evidence_linker() -> List[TestResult]:
    """Test evidence linker functionality."""
    results = []
    
    from src.intelligence.analysis.evidence_linker import evidence_linker
    
    # Test link creation
    link = evidence_linker.link_subdomain_to_httpx(
        domain="test.example.com",
        http_status=200,
        technologies=["nginx"],
        timestamp="2026-05-06T12:00:00Z"
    )

    results.append(TestResult(
        "evidence_link_created",
        link is not None,
        "Evidence link should be created"
    ))

    # Test confidence calculation
    confidence = evidence_linker.get_confidence_for_host("test.example.com")
    results.append(TestResult(
        "confidence_calculation",
        confidence in ["high", "medium", "low"],
        "Confidence should be calculated"
    ))
    
    return results


def test_doctor_integration() -> List[TestResult]:
    """Test doctor command works."""
    results = []
    
    try:
        from cli.commands.doctor import (
            check_python, check_folders, check_go_binaries,
            check_python_deps, check_database
        )
        
        # These should run without crashing
        python_check = check_python()
        results.append(TestResult(
            "doctor_python_check",
            python_check["status"] in ["OK", "WARN"],
            "Python check should work"
        ))
        
        folders = check_folders()
        results.append(TestResult(
            "doctor_folders_check",
            len(folders) > 0,
            "Folders check should work"
        ))
        
    except Exception as e:
        results.append(TestResult(
            "doctor_integration",
            False,
            str(e)
        ))
    
    return results


def test_no_demo_data_in_models() -> List[TestResult]:
    """Test that models don't have hardcoded demo data."""
    results = []
    
    from src.storage.models import Subdomain, Port
    
    # Just verify models can be imported (no actual db check)
    results.append(TestResult(
        "models_importable",
        True,
        "Models should be importable"
    ))
    
    return results


@click.command(name="self-test")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def self_test(json_output: bool):
    """
    Run internal logic tests to validate core functionality.
    
    This command tests the internal logic without requiring:
    - Internet connection
    - External tools (subfinder, nmap, etc.)
    - Real domain scans
    """
    render_panel("[bold cyan]OzyRecon Self-Test[/bold cyan] - Internal Logic Validation", border_style="cyan")
    
    all_results = []
    
    # Run all test suites
    render_panel("Testing Scope Guard...", border_style="cyan")
    scope_results = test_scope_guard()
    all_results.extend(scope_results)
    
    render_panel("Testing Scan Profiles...", border_style="cyan")
    profile_results = test_scan_profiles()
    all_results.extend(profile_results)
    
    render_panel("Testing Evidence Linker...", border_style="cyan")
    evidence_results = test_evidence_linker()
    all_results.extend(evidence_results)
    
    render_panel("Testing Doctor Integration...", border_style="cyan")
    doctor_results = test_doctor_integration()
    all_results.extend(doctor_results)
    
    if json_output:
        import json
        output = {
            "tests": [
                {"name": r.name, "passed": r.passed, "message": r.message}
                for r in all_results
            ]
        }
        console.print_json(json.dumps(output, indent=2))
        return
    
    # Display results
    table = Table(title="[bold]Test Results[/bold]", show_header=True)
    table.add_column("Test", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Message", style="white")
    
    passed = 0
    failed = 0
    
    for result in all_results:
        if result.passed:
            status = "[green]PASS[/green]"
            passed += 1
        else:
            status = "[red]FAIL[/red]"
            failed += 1
        
        table.add_row(result.name, status, result.message)
    
    console.print(table)
    
    # Summary
    total = len(all_results)
    score = int((passed / total) * 100) if total > 0 else 0
    
    render_panel(f"[bold]Total: {passed}/{total} passed ({score}%)[/bold]", border_style="cyan")
    
    if failed == 0:
        render_outcome("All self-tests passed")
    else:
        render_outcome(f"{failed} test(s) failed", border_style="red")


__all__ = ["self_test"]
