"""
Chat and Agent Models for SOC Chatbot
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum
import uuid


class AgentType(str, Enum):
    ORCHESTRATOR = "orchestrator"
    TRIAGE = "triage"
    THREAT_INTEL = "threat_intel"
    QUERY = "query"
    INCIDENT_RESPONSE = "incident_response"
    MALWARE_ANALYSIS = "malware_analysis"
    FORENSICS = "forensics"


class AgentStatus(str, Enum):
    IDLE = "idle"
    PROCESSING = "processing"
    COMPLETED = "completed"
    ERROR = "error"
    WAITING = "waiting"


class AgentAction(BaseModel):
    """Action taken by an agent"""
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_type: AgentType
    action_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    status: AgentStatus = AgentStatus.IDLE
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    error: Optional[str] = None


class AgentThought(BaseModel):
    """Agent reasoning/thought process"""
    agent_type: AgentType
    thought: str
    confidence: float = 0.5
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ChatMessage(BaseModel):
    """Chat message"""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str  # user, assistant, system, agent
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_type: Optional[AgentType] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ChatRequest(BaseModel):
    """Incoming chat request"""
    message: str
    session_id: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    """Response from an agent"""
    agent_type: AgentType
    response: str
    confidence: float
    actions_taken: List[AgentAction] = Field(default_factory=list)
    thoughts: List[AgentThought] = Field(default_factory=list)
    data: Dict[str, Any] = Field(default_factory=dict)
    suggestions: List[str] = Field(default_factory=list)
    processing_time_ms: int = 0


class ChatResponse(BaseModel):
    """Complete chat response"""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    response: str
    agents_involved: List[AgentType] = Field(default_factory=list)
    agent_responses: List[AgentResponse] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    processing_time_ms: int = 0
    data_lake_queries: int = 0
    events_analyzed: int = 0


class DataLakeQuery(BaseModel):
    """Query to the normalized data lake"""
    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_type: str  # search, aggregate, timeline, correlation
    filters: Dict[str, Any] = Field(default_factory=dict)
    time_range: Optional[Dict[str, datetime]] = None
    limit: int = 100
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    aggregations: List[str] = Field(default_factory=list)


class DataLakeResponse(BaseModel):
    """Response from data lake query"""
    query_id: str
    total_hits: int
    events: List[Dict[str, Any]] = Field(default_factory=list)
    aggregations: Dict[str, Any] = Field(default_factory=dict)
    query_time_ms: int = 0


class ConversationSession(BaseModel):
    """Chat session/conversation"""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    messages: List[ChatMessage] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    active_investigation: Optional[str] = None
