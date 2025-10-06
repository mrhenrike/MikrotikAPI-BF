#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Professional Reports Module - MikrotikAPI-BF v2.1

This module generates professional pentest reports:
- Executive summary
- Technical findings
- Risk assessment
- Remediation recommendations
- Multiple output formats

Author: André Henrique (@mrhenrike)
"""

import json
import csv
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class PentestReportGenerator:
    """
    Generates professional pentest reports
    """
    
    def __init__(self, session_data: Dict):
        self.session_data = session_data
        self.report_data = self._analyze_session_data()
    
    def _analyze_session_data(self) -> Dict:
        """Analyze session data for report generation"""
        targets = self.session_data.get('targets', [])
        credentials = self.session_data.get('credentials_found', [])
        scan_results = self.session_data.get('scan_results', [])
        
        # Calculate statistics
        total_targets = len(targets)
        mikrotik_targets = len([t for t in targets if t.get('is_mikrotik')])
        compromised_targets = len(set(c.get('target', '') for c in credentials))
        total_credentials = len(credentials)
        
        # Risk assessment
        high_risk_targets = len([t for t in targets if t.get('risk_score', 0) >= 7.0])
        medium_risk_targets = len([t for t in targets if 4.0 <= t.get('risk_score', 0) < 7.0])
        low_risk_targets = len([t for t in targets if t.get('risk_score', 0) < 4.0])
        
        # Vulnerability analysis
        vulnerabilities = []
        for target in targets:
            vulnerabilities.extend(target.get('vulnerabilities', []))
        
        unique_vulnerabilities = list(set(vulnerabilities))
        
        return {
            'total_targets': total_targets,
            'mikrotik_targets': mikrotik_targets,
            'compromised_targets': compromised_targets,
            'total_credentials': total_credentials,
            'high_risk_targets': high_risk_targets,
            'medium_risk_targets': medium_risk_targets,
            'low_risk_targets': low_risk_targets,
            'unique_vulnerabilities': unique_vulnerabilities,
            'vulnerability_count': len(unique_vulnerabilities)
        }
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary"""
        data = self.report_data
        
        summary = f"""
EXECUTIVE SUMMARY - MIKROTIK SECURITY ASSESSMENT
================================================

Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Session ID: {self.session_data.get('session_id', 'Unknown')}

OVERVIEW:
---------
• Total Targets Scanned: {data['total_targets']}
• Mikrotik Devices Found: {data['mikrotik_targets']}
• Compromised Systems: {data['compromised_targets']}
• Credentials Discovered: {data['total_credentials']}

RISK ASSESSMENT:
----------------
• High Risk Targets: {data['high_risk_targets']}
• Medium Risk Targets: {data['medium_risk_targets']}
• Low Risk Targets: {data['low_risk_targets']}
• Unique Vulnerabilities: {data['vulnerability_count']}

CRITICAL FINDINGS:
------------------
"""
        
        if data['compromised_targets'] > 0:
            summary += f"• {data['compromised_targets']} systems compromised with default/weak credentials\n"
        
        if data['vulnerability_count'] > 0:
            summary += f"• {data['vulnerability_count']} unique security vulnerabilities identified\n"
        
        if data['high_risk_targets'] > 0:
            summary += f"• {data['high_risk_targets']} high-risk targets requiring immediate attention\n"
        
        summary += """
IMMEDIATE RECOMMENDATIONS:
-------------------------
• Change all default passwords immediately
• Implement strong authentication mechanisms
• Restrict administrative access to trusted networks
• Enable HTTPS for all administrative interfaces
• Implement network segmentation
• Regular security assessments and monitoring

BUSINESS IMPACT:
----------------
• Potential unauthorized access to network infrastructure
• Risk of data breach and system compromise
• Compliance violations and regulatory issues
• Reputation damage and financial losses
"""
        
        return summary
    
    def generate_technical_report(self) -> Dict:
        """Generate detailed technical report"""
        targets = self.session_data.get('targets', [])
        credentials = self.session_data.get('credentials_found', [])
        
        technical_report = {
            'assessment_metadata': {
                'session_id': self.session_data.get('session_id'),
                'start_time': self.session_data.get('start_time'),
                'end_time': datetime.now().isoformat(),
                'total_commands': len(self.session_data.get('command_history', []))
            },
            'targets_analyzed': [],
            'vulnerabilities_found': [],
            'credentials_discovered': [],
            'attack_vectors': [],
            'proof_of_concept': []
        }
        
        # Analyze each target
        for target in targets:
            target_info = {
                'ip_address': target.get('target'),
                'is_mikrotik': target.get('is_mikrotik'),
                'routeros_version': target.get('routeros_version'),
                'model': target.get('model'),
                'open_ports': target.get('open_ports', []),
                'services': target.get('services', []),
                'risk_score': target.get('risk_score', 0),
                'vulnerabilities': target.get('vulnerabilities', [])
            }
            technical_report['targets_analyzed'].append(target_info)
        
        # Analyze vulnerabilities
        all_vulnerabilities = []
        for target in targets:
            all_vulnerabilities.extend(target.get('vulnerabilities', []))
        
        unique_vulns = list(set(all_vulnerabilities))
        for vuln in unique_vulns:
            technical_report['vulnerabilities_found'].append({
                'vulnerability': vuln,
                'severity': self._assess_vulnerability_severity(vuln),
                'affected_targets': len([t for t in targets if vuln in t.get('vulnerabilities', [])])
            })
        
        # Analyze credentials
        for cred in credentials:
            technical_report['credentials_discovered'].append({
                'username': cred.get('user'),
                'password': cred.get('pass'),
                'target': cred.get('target'),
                'services': cred.get('services', []),
                'severity': 'CRITICAL' if cred.get('user') in ['admin', 'mikrotik'] else 'HIGH'
            })
        
        return technical_report
    
    def _assess_vulnerability_severity(self, vulnerability: str) -> str:
        """Assess vulnerability severity"""
        critical_keywords = ['default', 'exposed', 'unencrypted']
        high_keywords = ['weak', 'vulnerable', 'outdated']
        
        vuln_lower = vulnerability.lower()
        
        if any(keyword in vuln_lower for keyword in critical_keywords):
            return 'CRITICAL'
        elif any(keyword in vuln_lower for keyword in high_keywords):
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def generate_remediation_plan(self) -> str:
        """Generate remediation plan"""
        data = self.report_data
        
        remediation = f"""
REMEDIATION PLAN - MIKROTIK SECURITY ASSESSMENT
===============================================

PRIORITY 1 - IMMEDIATE ACTIONS (0-24 hours):
--------------------------------------------
"""
        
        if data['compromised_targets'] > 0:
            remediation += f"""
• IMMEDIATE: Change all default passwords on {data['compromised_targets']} compromised systems
• IMMEDIATE: Disable unnecessary services (Telnet, FTP, HTTP)
• IMMEDIATE: Enable HTTPS for all administrative interfaces
• IMMEDIATE: Implement network access controls
"""
        
        remediation += f"""
PRIORITY 2 - SHORT TERM (1-7 days):
-----------------------------------
• Implement strong password policies (minimum 12 characters, complexity)
• Enable two-factor authentication where possible
• Update RouterOS to latest stable version
• Implement regular security monitoring
• Create incident response procedures
• Document all administrative accounts and access
"""
        
        remediation += f"""
PRIORITY 3 - MEDIUM TERM (1-4 weeks):
-------------------------------------
• Implement network segmentation
• Deploy intrusion detection systems (IDS)
• Regular security assessments (quarterly)
• Staff security training and awareness
• Implement backup and recovery procedures
• Create security policies and procedures
"""
        
        remediation += f"""
PRIORITY 4 - LONG TERM (1-3 months):
------------------------------------
• Implement comprehensive security framework
• Regular penetration testing (annually)
• Security awareness training program
• Incident response team formation
• Compliance monitoring and reporting
• Continuous security improvement program
"""
        
        return remediation
    
    def export_report(self, format_type: str, output_dir: str = "reports") -> str:
        """Export report in specified format"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = self.session_data.get('session_id', 'unknown')
        
        if format_type.lower() == 'json':
            filename = output_path / f"pentest_report_{session_id}_{timestamp}.json"
            self._export_json_report(filename)
        elif format_type.lower() == 'csv':
            filename = output_path / f"pentest_report_{session_id}_{timestamp}.csv"
            self._export_csv_report(filename)
        elif format_type.lower() == 'html':
            filename = output_path / f"pentest_report_{session_id}_{timestamp}.html"
            self._export_html_report(filename)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        return str(filename)
    
    def _export_json_report(self, filename: Path):
        """Export JSON report"""
        report_data = {
            'executive_summary': self.generate_executive_summary(),
            'technical_report': self.generate_technical_report(),
            'remediation_plan': self.generate_remediation_plan(),
            'session_data': self.session_data,
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '2.1',
                'report_type': 'pentest_assessment'
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    def _export_csv_report(self, filename: Path):
        """Export CSV report"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write headers
            writer.writerow(['Target', 'Is Mikrotik', 'Risk Score', 'Open Ports', 'Services', 'Vulnerabilities'])
            
            # Write target data
            for target in self.session_data.get('targets', []):
                writer.writerow([
                    target.get('target', ''),
                    'YES' if target.get('is_mikrotik') else 'NO',
                    target.get('risk_score', 0),
                    ', '.join(map(str, target.get('open_ports', []))),
                    ', '.join(target.get('services', [])),
                    ', '.join(target.get('vulnerabilities', []))
                ])
    
    def _export_html_report(self, filename: Path):
        """Export HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Mikrotik Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Mikrotik Security Assessment Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Session ID: {self.session_data.get('session_id', 'Unknown')}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <pre>{self.generate_executive_summary()}</pre>
    </div>
    
    <div class="section">
        <h2>Technical Findings</h2>
        <table>
            <tr><th>Target</th><th>Mikrotik</th><th>Risk Score</th><th>Services</th></tr>
"""
        
        for target in self.session_data.get('targets', []):
            risk_class = 'critical' if target.get('risk_score', 0) >= 7 else 'high' if target.get('risk_score', 0) >= 4 else 'medium'
            html_content += f"""
            <tr>
                <td>{target.get('target', '')}</td>
                <td>{'YES' if target.get('is_mikrotik') else 'NO'}</td>
                <td class="{risk_class}">{target.get('risk_score', 0):.1f}</td>
                <td>{', '.join(target.get('services', []))}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>Remediation Plan</h2>
        <pre>"""
        html_content += self.generate_remediation_plan()
        html_content += """
        </pre>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
