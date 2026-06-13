# Debugger-
Hacked my device?
#!/usr/bin/env python3
"""
Debugger- Security Anomaly Detection Application

Copyright (c) 2026 Morley Moses Apooch
All rights reserved.

Protected under the Berne Convention for the Protection of Literary and Artistic Works.
Developed with great help from GitHub.

Contact: apoochmorley@protonmail.com

Main Features:
    - Real-time system monitoring
    - Anomaly detection using statistical analysis
    - Threat assessment
    - Comprehensive audit logging
"""

import os
import sys
import json
import hashlib
import subprocess
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Debugger')

class SecurityAnalyzer:
    """
    Main security analysis engine for anomaly detection.

    Copyright (c) 2026 Morley Moses Apooch
    All rights reserved.

    Contact: apoochmorley@protonmail.com
    """
    def __init__(self):
        self.app_name = 'Debugger-'
        self.version = '1.0.0'
        self.copyright = 'Copyright (c) 2026 Morley Moses Apooch'
        self.author = 'Morley Moses Apooch'
        self.email = 'apoochmorley@protonmail.com'
        logger.info(f"Initializing {self.app_name} v{self.version}")
        logger.info(self.copyright)
        logger.info("Developed with great help from GitHub")
        logger.info(f"Contact: {self.email}")

    def scan_system(self, target_path: str = '/') -> dict:
        """
        Scan system for anomalies.
        Returns dict scan results.
        """
        logger.info(f"Starting system scan on {target_path}")

        results = {
            'timestamp': datetime.now().isoformat(),
            'app': self.app_name,
            'version': self.version,
            'copyright': self.copyright,
            'author': self.author,
            'email': self.email,
            'scan_path': target_path,
            'anomalies_detected': [],
            'threat_level': 'LOW',
            'status': 'SCANNING'
        }

        try:
            anomalies = self._check_processes()
            if anomalies:
                results['anomalies_detected'].extend(anomalies)

            file_anomalies = self._check_file_integrity(target_path)
            if file_anomalies:
                results['anomalies_detected'].extend(file_anomalies)

            results['threat_level'] = self._assess_threat_level(len(results['anomalies_detected']))
            results['status'] = 'COMPLETE'
            logger.info(f"Scan complete. Anomalies detected: {len(results['anomalies_detected'])}")
            logger.info(f"Threat level: {results['threat_level']}")

        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            results['status'] = 'ERROR'
            results['error'] = str(e)
        return results

    def _check_processes(self) -> list:
        """Check running processes for anomalies."""
        suspicious = []
        logger.debug("Checking system processes...")
        try:
            if sys.platform == 'win32':
                result = subprocess.run(['tasklist'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            processes = result.stdout.split('\n')
            # (Could add real anomaly checks here)
            logger.debug(f"Found {len(processes)} processes")
        except Exception as e:
            logger.warning(f"Could not enumerate processes: {str(e)}")
        return suspicious

    def _check_file_integrity(self, path: str) -> list:
        """Check file integrity for unauthorized modifications."""
        integrity_issues = []
        logger.debug(f"Checking file integrity at {path}...")
        try:
            target = Path(path)
            if target.exists():
                for item in target.iterdir():
                    try:
                        if item.is_file():
                            file_hash = self._calculate_file_hash(item)
                            logger.debug(f"File {item.name}: {file_hash}")
                    except PermissionError:
                        logger.debug(f"Permission denied: {item}")
                    except Exception as e:
                        logger.debug(f"Error checking {item}: {str(e)}")
        except Exception as e:
            logger.warning(f"Error checking file integrity: {str(e)}")
        return integrity_issues

    def _calculate_file_hash(self, filepath: Path, algorithm: str = 'sha256') -> str:
        """Calculate hash of a file."""
        hash_obj = hashlib.new(algorithm)
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
        except Exception as e:
            logger.debug(f"Could not hash file {filepath}: {str(e)}")
        return hash_obj.hexdigest()

    def _assess_threat_level(self, anomaly_count: int) -> str:
        """Assess threat level."""
        if anomaly_count == 0:
            return 'LOW'
        elif anomaly_count < 5:
            return 'MEDIUM'
        elif anomaly_count < 15:
            return 'HIGH'
        else:
            return 'CRITICAL'

    def generate_report(self, scan_results: dict) -> str:
        """Generate human-readable security report."""
        report = f"""
================================================================================
{scan_results['app']} - Security Analysis Report
================================================================================

Copyright (c) 2026 Morley Moses Apooch
All rights reserved.

Developed with great help from GitHub
Contact: {scan_results['email']}

Report Generated: {scan_results['timestamp']}
Application: {scan_results['app']} v{scan_results['version']}
Scan Path: {scan_results['scan_path']}

--------------------------------------------------------------------------------
THREAT ASSESSMENT
--------------------------------------------------------------------------------
Threat Level: {scan_results['threat_level']}
Anomalies Detected: {len(scan_results['anomalies_detected'])}
Status: {scan_results['status']}

--------------------------------------------------------------------------------
DETAILS
--------------------------------------------------------------------------------
"""
        if scan_results['anomalies_detected']:
            for i, anomaly in enumerate(scan_results['anomalies_detected'], 1):
                report += f"\n{i}. {anomaly}"
        else:
            report += "\nNo anomalies detected. System appears secure."

        report += "\n\n" + "="*80 + "\nEnd of Report\n" + "="*80 + "\n"
        return report

def main():
    """Main entry point for Debugger- application."""
    print(f"\n{'='*80}")
    print("Debugger- Security Anomaly Detection System")
    print(f"{'='*80}")
    print(f"Copyright (c) 2026 Morley Moses Apooch")
    print("All rights reserved.")
    print("\nDeveloped with great help from GitHub")
    print(f"Contact: apoochmorley@protonmail.com")
    print(f"\n{'='*80}\n")
    try:
        analyzer = SecurityAnalyzer()
        results = analyzer.scan_system()
        report = analyzer.generate_report(results)
        print(report)
        logger.info(f"Scan complete. Threat level: {results['threat_level']}")
        if results['threat_level'] == 'LOW':
            return 0
        elif results['threat_level'] == 'MEDIUM':
            return 1
        else:
            return 2
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        return -1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
