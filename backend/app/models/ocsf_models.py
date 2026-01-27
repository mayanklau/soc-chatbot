"""
OCSF (Open Cybersecurity Schema Framework) Data Models
Normalized schema for security events in the data lake
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class SeverityLevel(str, Enum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActivityType(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    DNS = "dns"
    HTTP = "http"
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"


class DispositionType(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    ISOLATED = "isolated"
    DELETED = "deleted"
    DROPPED = "dropped"
    UNKNOWN = "unknown"


class Actor(BaseModel):
    """Entity that performed the activity"""
    user_name: Optional[str] = None
    user_id: Optional[str] = None
    email: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    privileges: List[str] = Field(default_factory=list)
    process_name: Optional[str] = None
    process_pid: Optional[int] = None


class Device(BaseModel):
    """Device involved in the event"""
    hostname: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    type: Optional[str] = None  # server, workstation, mobile, etc.
    domain: Optional[str] = None
    region: Optional[str] = None


class NetworkEndpoint(BaseModel):
    """Network endpoint details"""
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    domain: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None
    isp: Optional[str] = None


class NetworkConnection(BaseModel):
    """Network connection details"""
    src: Optional[NetworkEndpoint] = None
    dst: Optional[NetworkEndpoint] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None  # inbound, outbound, lateral
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None


class FileInfo(BaseModel):
    """File information"""
    name: Optional[str] = None
    path: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None
    owner: Optional[str] = None


class ProcessInfo(BaseModel):
    """Process information"""
    name: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    cmd_line: Optional[str] = None
    path: Optional[str] = None
    user: Optional[str] = None
    integrity_level: Optional[str] = None


class ThreatIndicator(BaseModel):
    """Threat intelligence indicator"""
    type: str  # ip, domain, hash, url, email
    value: str
    confidence: float = 0.0
    source: Optional[str] = None
    threat_type: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)


class MitreAttack(BaseModel):
    """MITRE ATT&CK mapping"""
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None


class OCSFSecurityEvent(BaseModel):
    """
    OCSF-normalized security event
    Base class for all security events in the data lake
    """
    # Core fields
    event_id: str = Field(..., description="Unique event identifier")
    event_time: datetime = Field(default_factory=datetime.utcnow)
    event_type: str = Field(..., description="Event category/type")
    activity_type: ActivityType
    
    # Classification
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    confidence: float = Field(default=0.5, ge=0, le=1)
    disposition: DispositionType = DispositionType.UNKNOWN
    
    # Source information
    source: str = Field(..., description="Data source (e.g., crowdstrike, splunk)")
    source_type: str = Field(..., description="Source type (e.g., edr, siem, firewall)")
    raw_data: Optional[Dict[str, Any]] = None
    
    # Entities
    actor: Optional[Actor] = None
    device: Optional[Device] = None
    target_device: Optional[Device] = None
    
    # Network
    network: Optional[NetworkConnection] = None
    
    # File/Process
    file: Optional[FileInfo] = None
    process: Optional[ProcessInfo] = None
    parent_process: Optional[ProcessInfo] = None
    
    # Threat Intelligence
    threat_indicators: List[ThreatIndicator] = Field(default_factory=list)
    mitre_attack: List[MitreAttack] = Field(default_factory=list)
    
    # Additional context
    message: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Correlation
    correlation_id: Optional[str] = None
    related_events: List[str] = Field(default_factory=list)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AlertEvent(OCSFSecurityEvent):
    """Security alert event"""
    alert_id: str
    alert_name: str
    alert_description: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    status: str = "open"  # open, investigating, resolved, false_positive
    assigned_to: Optional[str] = None
    escalation_level: int = 0


class ThreatIntelReport(BaseModel):
    """Threat intelligence report"""
    ioc_type: str
    ioc_value: str
    threat_type: str
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    confidence: float
    sources: List[str]
    first_seen: datetime
    last_seen: datetime
    description: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)
    related_iocs: List[str] = Field(default_factory=list)
    mitre_mapping: List[MitreAttack] = Field(default_factory=list)
