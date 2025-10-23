#!/usr/bin/env python3
"""
QRadar QID Map Entry Creator for Akamai Events
This script processes Akamai events JSON and creates QRadar QID map entries
with detailed severity mappings based on security impact and operational risk
"""

import json
import sys
import re
from datetime import datetime
import argparse

# Detailed severity mappings for each event type and specific events
# Scale: 1 (info) to 10 (critical security incident)
SEVERITY_MAPPINGS = {
    # Critical Security Events (9-10)
    "authentication_failures": {
        "pattern": r"(?i)(authentication failure|login failure|sso failure|mfa failure)",
        "base_severity": 8,
        "modifiers": {
            "blocked": +1,
            "locked": +1,
            "invalid": 0,
            "inactive": 0
        }
    },
    
    # Web Application Security (7-9)
    "Web Application Firewall": {
        "default": 7,
        "events": {
            "Expedite activate configuration": 8,
            "Expedite deactivate configuration": 8,
            "Create new custom rule": 6,
            "Delete custom rule": 7,
            "Update custom rule": 6,
            "Delete firewall configuration": 8,
            "Activate configuration": 7,
            "Deactivate security configuration": 8,
            "Update attack group action": 8,
            "Update rapid rule action": 8,
            "Update penalty box": 8,
            "Update malware protection": 8,
            "Delete malware protection": 8,
            "Update URL protection": 7,
            "Update behavioral DDoS": 9,
            "WAF AI detections turned off": 8
        }
    },
    
    "Bot Manager": {
        "default": 7,
        "events": {
            "Delete protected endpoint": 8,
            "Create protected endpoint": 6,
            "Delete policy components": 7,
            "JS injection rule -Created": 7,
            "JS injection rule -Deleted": 7,
            "Managed bot detections updated": 8,
            "MSS Alert Threshold Changed": 6
        }
    },
    
    "API Security": {
        "default": 7,
        "events": {
            "Block Traffic": 9,
            "Allow Traffic": 6,
            "Decommission API Security": 8,
            "Create Configuration": 6,
            "Update Configuration": 6
        }
    },
    
    # Authentication & Access Control (6-9)
    "All Logins": {
        "default": 5,
        "events": {
            "Direct logout": 3,
            "SSO Logout": 3,
            "Login": 4,
            "Successful SSO Login": 4
        }
    },
    
    "Authentication Service": {
        "default": 7,
        "events": {
            "Authentication failure": 8,
            "Authentication fails": 8,
            "SAML authentication failure": 8,
            "SAML logout failure": 6,
            "OTP sent to a user": 5,
            "Authentication failed. JIT provisioning error": 8
        }
    },
    
    "IDS AuthN Login": {
        "default": 7,
        "events": {
            "Authentication failure (user locked)": 9,
            "Authentication failure (IP not allowed)": 9,
            "Authentication failure": 8,
            "Authentication successful": 3,
            "Authentication valid": 3,
            "Successful password rest": 5,
            "Successful password change": 5,
            "Suspicious login notification": 9
        }
    },
    
    # Identity and Access Management (5-8)
    "IAM-Manage Users": {
        "default": 6,
        "events": {
            "Add new user": 7,
            "Delete user": 8,
            "Change authorization grants": 8,
            "Lock a user": 8,
            "Unlock a user": 7,
            "Remove Access": 8,
            "Change user email": 6,
            "Change password": 6,
            "Create Third Party Access Request": 7,
            "Update Third Party Access Request": 7
        }
    },
    
    "IAM-Role Management": {
        "default": 7,
        "events": {
            "Add new role": 7,
            "Delete role": 8,
            "Edit a role": 7,
            "Edit Permission": 7
        }
    },
    
    "IAM-Group Management": {
        "default": 6,
        "events": {
            "Add new group": 6,
            "Delete a group": 7,
            "Move a group": 6,
            "Edit a group": 5
        }
    },
    
    "IAM-Identity and Access Management (EdgeControl-Portal)": {
        "default": 7,
        "events": {
            "Enable IP ACL": 8,
            "Disable IP ACL": 8,
            "Add new IP/CIDR to IP ACL list": 7,
            "Remove IP/CIDR from IP ACL list": 7,
            "2FA reset": 8,
            "Activate 2FA": 6,
            "Deactivate 2FA": 8,
            "MFA activated for user": 6,
            "MFA deactivated for user": 8,
            "IPACL Non whitelist IP tried to access account": 9
        }
    },
    
    # Certificate Management (5-8)
    "Certificate Provisioning System (Pulsar)": {
        "default": 6,
        "events": {
            "Contract is Expired": 8,
            "Quota Exceeds for Contract": 7,
            "Engine Failure Detected": 8,
            "Open API Delete Enrollment": 7,
            "Open API Create Enrollment": 6,
            "Open API Update Enrollment": 6
        }
    },
    
    "Cloud Certificate Manager": {
        "default": 6,
        "events": {
            "Delete Certificate": 7,
            "Create Certificate": 5,
            "Upload Signed Certificate": 5,
            "Rename Certificate": 4
        }
    },
    
    # Network Security (6-8)
    "Client List": {
        "default": 6,
        "events": {
            "Activated Client List": 6,
            "Deactivated Client List": 7,
            "Created Client List": 5,
            "Deleted Client List": 7,
            "Archived Client List": 6
        }
    },
    
    "Network Lists": {
        "default": 6,
        "events": {
            "Expedite activate network list": 7,
            "Expedite deactivate network list": 7,
            "Create network list": 5,
            "Activate network list": 6,
            "Update network list": 6,
            "Deprecate network list": 6
        }
    },
    
    "Site Shield": {
        "default": 7,
        "events": {
            "Delete SiteShield map": 8,
            "Acknowledge map change": 6,
            "Update maps": 7,
            "Enable Stable CIDRs": 6,
            "Disable Stable CIDRs": 7,
            "Rollback CIDRs": 8
        }
    },
    
    # DNS and Domain Management (4-7)
    "Edge DNS": {
        "default": 5,
        "events": {
            "Delete zone": 7,
            "Add zone": 5,
            "Edit zone": 5,
            "Change zone type": 6,
            "Domain Registration Delete: Success": 7,
            "Domain Registration Lock: Success": 6,
            "Domain Registration Unlock: Success": 6,
            "Add Shield": 6,
            "Delete Shield": 7
        }
    },
    
    # Property and Configuration Management (4-7)
    "Property Manager": {
        "default": 5,
        "events": {
            "Activate configuration on production": 6,
            "Activate configuration on staging": 5,
            "Deactivate configuration on production": 7,
            "Deactivate configuration on staging": 6,
            "Delete property": 7,
            "Create property": 5,
            "Clone property": 5,
            "Move hostname to property": 6
        }
    },
    
    # Data Protection & Compliance (6-8)
    "Client-Side Protection & Compliance": {
        "default": 7,
        "events": {
            "Delete user-defined script justification": 6,
            "Set script behavior policies": 7,
            "Activate a configuration": 6,
            "Delete a configuration": 7,
            "Change Audience Hijacking Configuration": 8,
            "Delete sensitive data field(s)": 8,
            "Change alert thresholds": 6,
            "Update Script Intelligence settings": 7
        }
    },
    
    "Account Protector": {
        "default": 7,
        "events": {
            "Account Protection turned on": 6,
            "A user turned on Account Protector.": 7,  # Note: text seems inverted
            "Add - Account Protection Rule": 6,
            "Delete - Account Protection Rule": 7,
            "Modify - Account Protection Rule": 6,
            "Added - New Account Protected Endpoint": 6,
            "Deleted - Account Protected Endpoint": 7
        }
    },
    
    # Cloud Services (4-7)
    "Cloudlets": {
        "default": 5,
        "events": {
            "Delete policy": 7,
            "Recover policy": 6,
            "Delete policy version": 6,
            "Create policy": 5,
            "Activate policy on production": 6,
            "Activate policy in staging": 5
        }
    },
    
    # Content Delivery (3-6)
    "Fast Purge": {
        "default": 4,
        "events": {
            "Create purge request": 3,
            "Purge by URL": 3,
            "Purge by content-tag": 3,
            "Purge by CP code": 4,
            "Purge by ARL": 4
        }
    },
    
    "Content Control Utility": {
        "default": 4,
        "events": {
            "Purge URL": 3,
            "Purge by CP Code": 4
        }
    },
    
    # Storage and File Management (4-6)
    "NetStorage - Portal UI": {
        "default": 5,
        "events": {
            "Delete Upload Account": 6,
            "Add Upload Account": 5,
            "Edit Upload Account": 5,
            "Delete Automatic Purge": 5,
            "Add Automatic Purge": 4,
            "Provision Storage Group": 5
        }
    },
    
    # Monitoring and Analytics (2-5)
    "Alert Configurations": {
        "default": 4,
        "events": {
            "Add Alert Definition": 3,
            "Delete Alert Definition": 4,
            "Edit Alert Definition": 3,
            "Alert Configuration Suspended": 5,
            "Alert Configuration Resumed": 4
        }
    },
    
    "Alert Activity": {
        "default": 5,
        "events": {
            "Alert fired": 5,
            "Clear alert": 3
        }
    },
    
    # Operational Events (2-4)
    "Tags": {
        "default": 3,
        "events": {
            "Add Tag": 2,
            "Delete Tag": 3,
            "Enable Tag": 2,
            "Suspend Tag": 3
        }
    },
    
    # Support and Communication (2-3)
    "Issue Tracking": {
        "default": 2,
        "events": {
            "Open Ticket": 2,
            "Add Attachment": 2,
            "Add Update": 2
        }
    },
    
    "Email Notification": {
        "default": 2,
        "events": {
            "Subscribe to Incidents": 2,
            "Unsubscribe to Incidents": 2,
            "Subscribe to Upgrades/News": 2,
            "Unsubscribe to Upgrades/News": 2
        }
    }
}

# Category mappings for QRadar
# These are standard QRadar categories - verify against your installation
CATEGORY_MAPPINGS = {
    # Authentication Events
    r"(?i)(login|logout|authentication|sso|mfa|2fa)": 7001,
    
    # User Account Management
    r"(?i)(iam|user management|role|group management|access management)": 7002,
    
    # Configuration Changes
    r"(?i)(configuration|property|policy|settings)": 7003,
    
    # Network Security/Firewall
    r"(?i)(firewall|waf|bot|ddos|attack|security)": 4013,
    
    # Network Lists/Access Control
    r"(?i)(network list|client list|acl|ip)": 4015,
    
    # DNS
    r"(?i)(dns|domain|zone)": 5004,
    
    # Certificate Management
    r"(?i)(certificate|cps|ssl|tls)": 7040,
    
    # API Activity
    r"(?i)(api)": 7052,
    
    # Content Management
    r"(?i)(purge|content|cache)": 7050,
    
    # Storage
    r"(?i)(storage|netstorage|upload)": 7051,
    
    # Monitoring/Alerts
    r"(?i)(alert|monitor|analytics)": 7045,
    
    # Default
    "default": 10001
}

class QRadarQIDCreator:
    def __init__(self, json_file, output_dir="."):
        self.json_file = json_file
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.commands = []
        self.stats = {"total": 0, "processed": 0, "errors": 0}
        
    def load_events(self):
        """Load events from JSON file"""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            sys.exit(1)
    
    def get_severity(self, event_type_name, event_name, event_desc):
        """
        Determine severity based on detailed analysis of event type and name
        Returns severity from 1-10
        """
        
        # Check if we have specific mapping for this event type
        if event_type_name in SEVERITY_MAPPINGS:
            mapping = SEVERITY_MAPPINGS[event_type_name]
            
            # Check for specific event severity
            if "events" in mapping and event_name in mapping["events"]:
                return mapping["events"][event_name]
            
            # Return default for this event type
            if "default" in mapping:
                return mapping["default"]
        
        # Check authentication failures (high priority)
        if "authentication_failures" in SEVERITY_MAPPINGS:
            auth_pattern = SEVERITY_MAPPINGS["authentication_failures"]["pattern"]
            if re.search(auth_pattern, event_name, re.IGNORECASE) or \
               re.search(auth_pattern, event_desc, re.IGNORECASE):
                base = SEVERITY_MAPPINGS["authentication_failures"]["base_severity"]
                
                # Apply modifiers
                for modifier, adjustment in SEVERITY_MAPPINGS["authentication_failures"]["modifiers"].items():
                    if modifier.lower() in event_name.lower() or modifier.lower() in event_desc.lower():
                        return min(10, base + adjustment)
                
                return base
        
        # Pattern-based severity determination
        severity_patterns = [
            (r"(?i)(attack|exploit|vulnerability|malware|threat|breach|compromise)", 9),
            (r"(?i)(delete|remove|revoke|disable|deactivate|fail|error|deny|reject|block)", 7),
            (r"(?i)(authentication|security|firewall|protection)", 7),
            (r"(?i)(create|add|activate|enable)", 5),
            (r"(?i)(update|edit|modify|change)", 5),
            (r"(?i)(configuration|policy|setting)", 5),
            (r"(?i)(view|read|query|list|export)", 3),
            (r"(?i)(notification|email|subscribe)", 2)
        ]
        
        combined_text = f"{event_type_name} {event_name} {event_desc}"
        
        for pattern, severity in severity_patterns:
            if re.search(pattern, combined_text):
                return severity
        
        # Default severity
        return 4
    
    def get_category_id(self, event_type_name, event_name):
        """Determine QRadar category ID for an event"""
        
        combined_text = f"{event_type_name} {event_name}"
        
        # Check each pattern
        for pattern, category_id in CATEGORY_MAPPINGS.items():
            if pattern != "default":
                if re.search(pattern, combined_text):
                    return category_id
        
        # Return default category
        return CATEGORY_MAPPINGS["default"]
    
    def clean_text(self, text, max_length=None):
        """Clean text for shell command safety"""
        # Remove or escape problematic characters
        text = text.replace('"', '\\"').replace("'", "\\'")
        text = text.replace('$', '\\$').replace('`', '\\`')
        text = text.replace('\n', ' ').replace('\r', '').replace('\t', ' ')
        
        # Remove multiple spaces
        text = ' '.join(text.split())
        
        if max_length:
            text = text[:max_length]
        
        return text
    
    def create_qid_command(self, event_type_id, event_type_name, event):
        """Create a QRadar QID map command for an event"""
        event_id = event['eventDefinitionId']
        event_name = event['eventName']
        event_desc = event['eventDescription']
        
        # Get category and severity
        category_id = self.get_category_id(event_type_name, event_name)
        severity = self.get_severity(event_type_name, event_name, event_desc)
        
        # Create QID name (max 255 chars)
        qid_name = f"Akamai_{event_type_id}_{event_id}_{event_name}"
        qid_name = self.clean_text(qid_name, 255)
        
        # Create description (max 2048 chars)
        qid_desc = f"[{event_type_name}] {event_desc}"
        qid_desc = self.clean_text(qid_desc, 2048)
        
        # Build command
        cmd = f'/opt/qradar/bin/qidmap_cli.sh -c ' \
              f'--qname "{qid_name}" ' \
              f'--qdescription "{qid_desc}" ' \
              f'--severity {severity} ' \
              f'--lowlevelcategoryid {category_id}'
        
        return {
            "command": cmd,
            "event_name": event_name,
            "event_type": event_type_name,
            "severity": severity,
            "category_id": category_id,
            "event_id": event_id
        }
    
    def process_events(self):
        """Process all events and generate commands"""
        events_data = self.load_events()
        
        for event_type in events_data:
            type_id = event_type['eventTypeId']
            type_name = event_type['eventTypeName']
            
            print(f"Processing: {type_name} (ID: {type_id})")
            
            for event in event_type['eventDefinitions']:
                self.stats['total'] += 1
                
                try:
                    cmd_data = self.create_qid_command(type_id, type_name, event)
                    self.commands.append(cmd_data)
                    self.stats['processed'] += 1
                except Exception as e:
                    print(f"  Error processing event {event.get('eventName', 'Unknown')}: {e}")
                    self.stats['errors'] += 1
    
    def generate_shell_script(self):
        """Generate executable shell script with all commands"""
        script_file = f"{self.output_dir}/qradar_qid_commands_{self.timestamp}.sh"
        
        with open(script_file, 'w') as f:
            # Write header
            f.write("#!/bin/bash\n")
            f.write("# QRadar QID Map Commands for Akamai Events\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total commands: {len(self.commands)}\n\n")
            
            # Add utility functions
            f.write("# Colors for output\n")
            f.write("GREEN='\\033[0;32m'\n")
            f.write("RED='\\033[0;31m'\n")
            f.write("YELLOW='\\033[1;33m'\n")
            f.write("NC='\\033[0m' # No Color\n\n")
            
            f.write("# Counters\n")
            f.write("SUCCESS=0\n")
            f.write("FAIL=0\n")
            f.write("LOG_FILE=\"qid_creation_$(date +%Y%m%d_%H%M%S).log\"\n\n")
            
            f.write("# Check if running as root\n")
            f.write('if [ "$EUID" -ne 0 ]; then\n')
            f.write('  echo "Please run as root"\n')
            f.write('  exit 1\n')
            f.write('fi\n\n')
            
            f.write("# Verify qidmap_cli.sh exists\n")
            f.write('if [ ! -f "/opt/qradar/bin/qidmap_cli.sh" ]; then\n')
            f.write('  echo "QRadar qidmap_cli.sh not found!"\n')
            f.write('  exit 1\n')
            f.write('fi\n\n')
            
            f.write('echo "Starting QID creation for Akamai events..."\n')
            f.write('echo "Log file: $LOG_FILE"\n')
            f.write('echo ""\n\n')
            
            # Group commands by severity for better organization
            severity_groups = {}
            for cmd_data in self.commands:
                sev = cmd_data['severity']
                if sev not in severity_groups:
                    severity_groups[sev] = []
                severity_groups[sev].append(cmd_data)
            
            # Process high severity first
            for severity in sorted(severity_groups.keys(), reverse=True):
                f.write(f'\necho -e "${{YELLOW}}Processing Severity {severity} events...${{NC}}"\n\n')
                
                for i, cmd_data in enumerate(severity_groups[severity], 1):
                    total_idx = self.commands.index(cmd_data) + 1
                    f.write(f"# [{total_idx}/{len(self.commands)}] Severity {severity}: {cmd_data['event_type']} - {cmd_data['event_name']}\n")
                    f.write(f"echo -n '[{total_idx}/{len(self.commands)}] S{severity}: {cmd_data['event_name'][:50]}... '\n")
                    f.write(f'echo "[$(date)] Processing: {cmd_data["event_name"]} (Severity: {severity})" >> $LOG_FILE\n')
                    f.write(f"if {cmd_data['command']} 2>>$LOG_FILE; then\n")
                    f.write('  echo -e "${GREEN}✓${NC}"\n')
                    f.write('  SUCCESS=$((SUCCESS+1))\n')
                    f.write('  echo "  SUCCESS" >> $LOG_FILE\n')
                    f.write("else\n")
                    f.write('  echo -e "${RED}✗${NC}"\n')
                    f.write('  FAIL=$((FAIL+1))\n')
                    f.write('  echo "  FAILED" >> $LOG_FILE\n')
                    f.write("fi\n\n")
            
            # Write footer
            f.write('# Summary\n')
            f.write('echo ""\n')
            f.write('echo "========================================="\n')
            f.write('echo "QID Creation Complete!"\n')
            f.write('echo -e "Success: ${GREEN}$SUCCESS${NC}"\n')
            f.write('echo -e "Failed: ${RED}$FAIL${NC}"\n')
            f.write(f'echo "Total: {len(self.commands)}"\n')
            f.write('echo "Log file: $LOG_FILE"\n')
            f.write('echo "========================================="\n\n')
            
            f.write('# Optional: Restart QRadar services\n')
            f.write('read -p "Restart QRadar services? (y/n): " -n 1 -r\n')
            f.write('echo ""\n')
            f.write('if [[ $REPLY =~ ^[Yy]$ ]]; then\n')
            f.write('  echo "Restarting services..."\n')
            f.write('  systemctl restart hostcontext\n')
            f.write('  echo "Services restarted."\n')
            f.write('fi\n')
        
        return script_file
    
    def generate_csv_report(self):
        """Generate CSV report with severity analysis"""
        csv_file = f"{self.output_dir}/qradar_qid_report_{self.timestamp}.csv"
        
        with open(csv_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("Event Type,Event Name,Event ID,Severity,Category ID,Severity Reason\n")
            
            # Sort by severity for easier review
            sorted_commands = sorted(self.commands, key=lambda x: x['severity'], reverse=True)
            
            # Write data
            for cmd_data in sorted_commands:
                severity_reason = self.get_severity_reason(cmd_data['severity'])
                f.write(f'"{cmd_data["event_type"]}",')
                f.write(f'"{cmd_data["event_name"]}",')
                f.write(f'{cmd_data["event_id"]},')
                f.write(f'{cmd_data["severity"]},')
                f.write(f'{cmd_data["category_id"]},')
                f.write(f'"{severity_reason}"\n')
        
        return csv_file
    
    def get_severity_reason(self, severity):
        """Get explanation for severity level"""
        reasons = {
            10: "Critical security incident",
            9: "High security threat/breach",
            8: "Security failure/violation",
            7: "Important security change",
            6: "Significant configuration change",
            5: "Normal configuration change",
            4: "Operational event",
            3: "Informational - low impact",
            2: "Informational - minimal impact",
            1: "Debug/trace information"
        }
        return reasons.get(severity, "Standard event")
    
    def generate_severity_summary(self):
        """Generate summary of severity distribution"""
        summary_file = f"{self.output_dir}/severity_summary_{self.timestamp}.txt"
        
        # Count events by severity
        severity_counts = {}
        for cmd in self.commands:
            sev = cmd['severity']
            if sev not in severity_counts:
                severity_counts[sev] = []
            severity_counts[sev].append(cmd)
        
        with open(summary_file, 'w') as f:
            f.write("Akamai Events - Severity Distribution\n")
            f.write("=" * 50 + "\n\n")
            
            for severity in sorted(severity_counts.keys(), reverse=True):
                events = severity_counts[severity]
                f.write(f"\nSeverity {severity} ({self.get_severity_reason(severity)}): {len(events)} events\n")
                f.write("-" * 40 + "\n")
                
                # Group by event type
                by_type = {}
                for event in events:
                    event_type = event['event_type']
                    if event_type not in by_type:
                        by_type[event_type] = []
                    by_type[event_type].append(event['event_name'])
                
                for event_type, event_names in sorted(by_type.items()):
                    f.write(f"\n  {event_type}:\n")
                    for name in sorted(event_names)[:5]:  # Show first 5
                        f.write(f"    - {name}\n")
                    if len(event_names) > 5:
                        f.write(f"    ... and {len(event_names) - 5} more\n")
            
            f.write("\n" + "=" * 50 + "\n")
            f.write(f"Total events: {len(self.commands)}\n")
        
        return summary_file
    
    def generate_category_check_script(self):
        """Generate script to check available QRadar categories"""
        script_file = f"{self.output_dir}/check_qradar_categories.sh"
        
        with open(script_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# Script to check available QRadar categories\n\n")
            f.write("echo 'Fetching QRadar categories...'\n")
            f.write("echo ''\n")
            f.write("/opt/qradar/bin/qidmap_cli.sh -l > qradar_categories.txt\n")
            f.write("echo 'Categories saved to qradar_categories.txt'\n")
            f.write("echo ''\n")
            f.write("echo 'Categories used in Akamai events mapping:'\n")
            f.write("echo '7001 - Authentication'\n")
            f.write("echo '7002 - User Account Management'\n")
            f.write("echo '7003 - Configuration Change'\n")
            f.write("echo '4013 - Firewall Activity'\n")
            f.write("echo '4015 - Network Access Control'\n")
            f.write("echo '5004 - DNS Activity'\n")
            f.write("echo '7040 - Certificate Management'\n")
            f.write("echo '7052 - API Activity'\n")
            f.write("echo '9999 - Generic Application Event'\n")
            f.write("echo ''\n")
            f.write("echo 'Searching for these categories in QRadar:'\n")
            f.write("/opt/qradar/bin/qidmap_cli.sh -l | grep -E '(7001|7002|7003|4013|4015|5004|7040|7052|9999)'\n")
        
        return script_file
    
    def run(self):
        """Main execution method"""
        print("QRadar QID Creator for Akamai Events")
        print("=" * 50)
        print(f"Processing: {self.json_file}")
        print("")
        
        # Process events
        self.process_events()
        
        # Generate outputs
        shell_script = self.generate_shell_script()
        csv_report = self.generate_csv_report()
        category_script = self.generate_category_check_script()
        severity_summary = self.generate_severity_summary()
        
        # Make scripts executable
        import os
        os.chmod(shell_script, 0o755)
        os.chmod(category_script, 0o755)
        
        # Print summary
        print("\nProcessing Complete!")
        print("=" * 50)
        print(f"Total events: {self.stats['total']}")
        print(f"Processed: {self.stats['processed']}")
        print(f"Errors: {self.stats['errors']}")
        
        # Print severity distribution
        severity_counts = {}
        for cmd in self.commands:
            sev = cmd['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print("\nSeverity Distribution:")
        for sev in sorted(severity_counts.keys(), reverse=True):
            print(f"  Severity {sev}: {severity_counts[sev]} events")
        
        print("\nGenerated files:")
        print(f"  1. {shell_script} - Main QID creation script")
        print(f"  2. {csv_report} - Detailed CSV report")
        print(f"  3. {severity_summary} - Severity analysis")
        print(f"  4. {category_script} - Category checker")
        
        print("\nNext steps:")
        print("  1. Review severity assignments in CSV report")
        print("  2. Copy scripts to QRadar server")
        print("  3. Run category checker: ./check_qradar_categories.sh")
        print("  4. Adjust category IDs if needed")
        print(f"  5. Execute main script: ./{shell_script}")

def main():
    parser = argparse.ArgumentParser(description='Create QRadar QID entries from Akamai events JSON')
    parser.add_argument('json_file', help='Path to Akamai events JSON file')
    parser.add_argument('-o', '--output', default='.', help='Output directory (default: current)')
    
    args = parser.parse_args()
    
    creator = QRadarQIDCreator(args.json_file, args.output)
    creator.run()

if __name__ == "__main__":
    main()
