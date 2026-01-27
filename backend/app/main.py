"""
SOC Chatbot API - Main FastAPI Application
Multi-agent security chatbot with normalized data lake integration
"""

import logging
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.models.chat_models import (
    ChatRequest, ChatResponse, DataLakeQuery, DataLakeResponse,
    AgentType
)
from app.agents.orchestrator import orchestrator
from app.services.data_lake import data_lake

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="SOC Chatbot API",
    description="Multi-agent security operations chatbot with normalized data lake integration",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============== Health & Info Endpoints ==============

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/info")
async def get_info():
    """Get API information"""
    return {
        "name": "SOC Chatbot API",
        "version": "1.0.0",
        "agents": [
            {"type": "orchestrator", "description": "Master coordinator for all agents"},
            {"type": "query", "description": "Data lake search and query"},
            {"type": "triage", "description": "Alert prioritization and assessment"},
            {"type": "threat_intel", "description": "IOC enrichment and threat context"},
            {"type": "incident_response", "description": "Response playbooks and guidance"}
        ],
        "data_lake": {
            "format": "OCSF",
            "sources": data_lake.get_statistics()['sources']
        }
    }


# ============== Chat Endpoints ==============

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint - Process user message through SOC agents
    """
    try:
        logger.info(f"Processing chat request: {request.message[:100]}...")
        
        context = {
            "session_id": request.session_id,
            **request.context
        }
        
        response = await orchestrator.process(request.message, context)
        
        logger.info(f"Chat response generated in {response.processing_time_ms}ms")
        return response
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/chat/history/{session_id}")
async def get_chat_history(session_id: str):
    """Get conversation history for a session"""
    history = orchestrator.get_session_history(session_id)
    return {
        "session_id": session_id,
        "messages": [
            {
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat(),
                "agent_type": msg.agent_type.value if msg.agent_type else None
            }
            for msg in history
        ]
    }


@app.delete("/chat/session/{session_id}")
async def clear_session(session_id: str):
    """Clear a chat session"""
    orchestrator.clear_session(session_id)
    return {"status": "cleared", "session_id": session_id}


# ============== Data Lake Endpoints ==============

@app.get("/data-lake/statistics")
async def get_data_lake_statistics():
    """Get data lake statistics"""
    return data_lake.get_statistics()


@app.post("/data-lake/query", response_model=DataLakeResponse)
async def query_data_lake(query: DataLakeQuery):
    """Execute a query against the data lake"""
    try:
        result = data_lake.query(query)
        return result
    except Exception as e:
        logger.error(f"Query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/data-lake/events/{event_id}")
async def get_event(event_id: str):
    """Get a specific event by ID"""
    event = data_lake.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get("/data-lake/timeline/{entity_type}/{entity_value}")
async def get_entity_timeline(
    entity_type: str,
    entity_value: str,
    hours: int = Query(default=24, ge=1, le=168)
):
    """Get timeline of events for an entity"""
    if entity_type not in ['ip', 'hostname', 'user']:
        raise HTTPException(status_code=400, detail="Invalid entity type")
    
    timeline = data_lake.get_timeline(entity_type, entity_value, hours)
    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "hours": hours,
        "event_count": len(timeline),
        "events": timeline
    }


# ============== Alert Endpoints ==============

@app.get("/alerts")
async def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500)
):
    """Get alerts with optional filters"""
    alerts = data_lake.get_alerts(status=status, severity=severity, limit=limit)
    return {
        "total": len(alerts),
        "alerts": alerts
    }


@app.get("/alerts/summary")
async def get_alert_summary():
    """Get alert summary"""
    stats = data_lake.get_statistics()
    alerts = data_lake.get_alerts()
    
    # Group by severity
    by_severity = {}
    for alert in alerts:
        sev = alert.get('severity', 'unknown')
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    # Group by status
    by_status = {}
    for alert in alerts:
        status = alert.get('status', 'unknown')
        by_status[status] = by_status.get(status, 0) + 1
    
    return {
        "total_alerts": stats['total_alerts'],
        "open_alerts": stats['open_alerts'],
        "by_severity": by_severity,
        "by_status": by_status
    }


# ============== Agent Endpoints ==============

@app.get("/agents")
async def list_agents():
    """List available agents"""
    from app.agents.base_agent import agent_registry
    
    return {
        "agents": [
            {
                "type": agent.agent_type.value,
                "status": agent.status.value
            }
            for agent in agent_registry.get_all_agents()
        ]
    }


@app.get("/agents/{agent_type}")
async def get_agent_info(agent_type: str):
    """Get agent information"""
    from app.agents.base_agent import agent_registry
    
    try:
        agent_enum = AgentType(agent_type)
        agent = agent_registry.get_agent(agent_enum)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return {
            "type": agent.agent_type.value,
            "status": agent.status.value,
            "actions_count": len(agent.actions),
            "thoughts_count": len(agent.thoughts)
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent type")


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    logger.info("SOC Chatbot API starting up...")
    logger.info(f"Data lake loaded with {len(data_lake.events)} events")
    logger.info(f"Registered {len(orchestrator.sessions)} sessions")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
