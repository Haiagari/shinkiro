"""Test script to verify Jinja2 templates load correctly."""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.reporting.jinja_engine import Jinja2ReportEngine
from src.reporting.schemas import create_report_data

def test_template_loading():
    """Test that all templates load correctly."""
    print("Testing Jinja2 Template Infrastructure...")
    print("=" * 60)

    try:
        # Initialize engine
        engine = Jinja2ReportEngine(template_dir="resources/reports/templates")
        print("✅ Jinja2ReportEngine initialized successfully")
        print(f"   Template dir: {engine.template_dir}")

        # Test data
        report_data = create_report_data("example.com")
        report_data['scan_info']['duration'] = 120.5

        # Add sample findings
        report_data['findings']['critical'] = [
            {
                'title': 'SQL Injection in Login Form',
                'severity': 'critical',
                'description': 'The login form is vulnerable to SQL injection attacks.',
                'evidence': "Input: admin' OR 1=1--",
                'remediation': 'Use parameterized queries.',
                'cvss_score': 9.8
            }
        ]
        report_data['findings']['high'] = [
            {
                'title': 'Outdated OpenSSH Version',
                'severity': 'high',
                'description': 'OpenSSH 7.4 is vulnerable to multiple CVEs.',
                'evidence': None,
                'remediation': 'Upgrade to OpenSSH 9.0+',
                'cvss_score': 7.5
            }
        ]

        # Add scoring data
        report_data['scoring'] = [
            {'asset': 'web.example.com:443', 'criticality_index': 85.5, 'port': 443, 'service': 'https', 'reasoning': 'Public web server with sensitive data'}
        ]

        # Add attack paths
        report_data['attack_paths'] = [
            {
                'path_id': 'path-001',
                'description': 'SQL injection leading to data exfiltration',
                'steps': ['Exploit SQL injection', 'Extract admin credentials', 'Access admin panel', 'Exfiltrate data'],
                'risk_score': 88.0,
                'prerequisites': ['SQL injection vulnerability', 'Database accessible']
            }
        ]

        # Add summary
        report_data['summary'] = {
            'total_findings': 2,
            'risk_score': 82.5,
            'critical_count': 1,
            'high_count': 1,
            'medium_count': 0,
            'low_count': 0
        }

        print(f"\n✅ Test data prepared")
        print(f"   Findings: {len(report_data['findings']['critical']) + len(report_data['findings']['high'])}")
        print(f"   Scoring items: {len(report_data['scoring'])}")
        print(f"   Attack paths: {len(report_data['attack_paths'])}")

        # Render HTML
        print(f"\nRendering template: layouts/report.j2")
        html_output = engine.render_html(report_data, template='layouts/report.j2')

        if html_output:
            print(f"✅ Template rendered successfully!")
            print(f"   Output size: {len(html_output)} bytes")

            # Save output for verification
            output_path = "/home/sam/Proyectos/OzyRecon/reports/test_report_output.html"
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(html_output)
            print(f"   Saved to: {output_path}")
        else:
            print("❌ Template rendered but output is empty!")
            return False

        # Test individual templates
        print(f"\nTesting individual partials...")
        
        # Test base.j2
        try:
            base_template = engine.env.get_template('base.j2')
            print("✅ base.j2 loads correctly")
        except Exception as e:
            print(f"❌ base.j2 failed to load: {e}")
            return False

        # Test macros.j2
        try:
            macros_template = engine.env.get_template('macros.j2')
            print("✅ macros.j2 loads correctly")
        except Exception as e:
            print(f"❌ macros.j2 failed to load: {e}")
            return False

        # Test all partials
        partials_list = ['summary.j2', 'findings.j2', 'scoring.j2', 'attack_paths.j2', 'charts.j2']
        for partial in partials_list:
            try:
                partial_template = engine.env.get_template(f"partials/{partial}")
                print(f"✅ partials/{partial} loads correctly")
            except Exception as e:
                print(f"❌ partials/{partial} failed to load: {e}")
                return False

        print("\n" + "=" * 60)
        print("✅ ALL TEMPLATE TESTS PASSED!")
        return True

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_template_loading()
    sys.exit(0 if success else 1)
