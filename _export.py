#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Result Export Module - MikrotikAPI-BF v2.0

This module handles exporting brute-force results to different formats:
- JSON: Structured data with metadata
- CSV: Compatible with Excel/LibreOffice
- XML: Hierarchical format with pretty-print
- TXT: Simple user:pass format

Author: André Henrique (@mrhenrike)
"""

import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

class ResultExporter:
    def __init__(self, results, target, output_dir="results"):
        """
        Initialize the exporter with results data
        
        Args:
            results: List of dicts with 'user', 'pass', 'services'
            target: Target IP/hostname
            output_dir: Directory to save results
        """
        self.results = results
        self.target = target
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory if doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _generate_filename(self, extension):
        """Generate filename with timestamp and target"""
        safe_target = self.target.replace(".", "_").replace(":", "_")
        return self.output_dir / f"mikrotik_{safe_target}_{self.timestamp}.{extension}"
    
    def export_json(self):
        """Export results to JSON format"""
        filename = self._generate_filename("json")
        
        data = {
            "scan_info": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "total_found": len(self.results)
            },
            "credentials": self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        
        return filename
    
    def export_csv(self):
        """Export results to CSV format"""
        filename = self._generate_filename("csv")
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            if self.results:
                fieldnames = ['username', 'password', 'services']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                writer.writeheader()
                for result in self.results:
                    writer.writerow({
                        'username': result['user'],
                        'password': result['pass'],
                        'services': ', '.join(result['services'])
                    })
        
        return filename
    
    def export_xml(self):
        """Export results to XML format"""
        filename = self._generate_filename("xml")
        
        root = ET.Element("mikrotik_scan")
        
        # Scan info
        info = ET.SubElement(root, "scan_info")
        ET.SubElement(info, "target").text = self.target
        ET.SubElement(info, "timestamp").text = datetime.now().isoformat()
        ET.SubElement(info, "total_found").text = str(len(self.results))
        
        # Credentials
        credentials = ET.SubElement(root, "credentials")
        for result in self.results:
            cred = ET.SubElement(credentials, "credential")
            ET.SubElement(cred, "username").text = result['user']
            ET.SubElement(cred, "password").text = result['pass']
            
            services = ET.SubElement(cred, "services")
            for service in result['services']:
                ET.SubElement(services, "service").text = service
        
        # Pretty print
        self._indent_xml(root)
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
        
        return filename
    
    def export_txt(self):
        """Export results to simple text format (user:pass)"""
        filename = self._generate_filename("txt")
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Mikrotik API Bruteforce Results\n")
            f.write(f"# Target: {self.target}\n")
            f.write(f"# Date: {datetime.now().isoformat()}\n")
            f.write(f"# Total found: {len(self.results)}\n\n")
            
            for result in self.results:
                services = ', '.join(result['services'])
                f.write(f"{result['user']}:{result['pass']} ({services})\n")
        
        return filename
    
    def export_all(self):
        """Export to all formats"""
        files = {
            'json': self.export_json(),
            'csv': self.export_csv(),
            'xml': self.export_xml(),
            'txt': self.export_txt()
        }
        return files
    
    @staticmethod
    def _indent_xml(elem, level=0):
        """Add indentation to XML for pretty printing"""
        i = "\n" + level * "  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for child in elem:
                ResultExporter._indent_xml(child, level + 1)
            if not child.tail or not child.tail.strip():
                child.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i

