"""
SOC Agent Base Classes and Registry
Foundation for all specialized security agents
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
import time
import logging
from app.models.chat_models import (
    AgentType, AgentStatus, AgentAction, AgentThought, AgentResponse
)

logger = logging.getLogger(__name__)


class BaseSOCAgent(ABC):
    """Base class for all SOC agents"""
    
    def __init__(self, agent_type: AgentType):
        self.agent_type = agent_type
        self.status = AgentStatus.IDLE
        self.actions: List[AgentAction] = []
        self.thoughts: List[AgentThought] = []
    
    @abstractmethod
    def can_handle(self, query: str, context: Dict[str, Any]) -> float:
        """
        Determine if this agent can handle the query.
        Returns confidence score 0-1.
        """
        pass
    
    @abstractmethod
    async def process(self, query: str, context: Dict[str, Any]) -> AgentResponse:
        """Process the query and return response"""
        pass
    
    def add_thought(self, thought: str, confidence: float = 0.5):
        """Add a reasoning thought"""
        self.thoughts.append(AgentThought(
            agent_type=self.agent_type,
            thought=thought,
            confidence=confidence
        ))
    
    def add_action(self, action_name: str, parameters: Dict[str, Any] = None) -> AgentAction:
        """Record an action taken"""
        action = AgentAction(
            agent_type=self.agent_type,
            action_name=action_name,
            parameters=parameters or {},
            status=AgentStatus.PROCESSING,
            started_at=datetime.utcnow()
        )
        self.actions.append(action)
        return action
    
    def complete_action(self, action: AgentAction, result: Dict[str, Any] = None, error: str = None):
        """Mark action as complete"""
        action.completed_at = datetime.utcnow()
        action.duration_ms = int((action.completed_at - action.started_at).total_seconds() * 1000)
        action.result = result
        action.error = error
        action.status = AgentStatus.ERROR if error else AgentStatus.COMPLETED
    
    def reset(self):
        """Reset agent state for new query"""
        self.status = AgentStatus.IDLE
        self.actions = []
        self.thoughts = []
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract relevant keywords from text"""
        # Common security keywords for matching
        security_keywords = {
            'alert', 'alerts', 'threat', 'threats', 'malware', 'attack', 'breach',
            'incident', 'suspicious', 'blocked', 'quarantine', 'critical', 'high',
            'ip', 'domain', 'hash', 'ioc', 'indicator', 'c2', 'command', 'control',
            'exfiltration', 'lateral', 'movement', 'privilege', 'escalation',
            'network', 'process', 'file', 'dns', 'authentication', 'login',
            'user', 'host', 'device', 'endpoint', 'server', 'firewall',
            'investigate', 'analyze', 'check', 'find', 'search', 'query',
            'timeline', 'history', 'events', 'logs', 'statistics', 'summary',
            'triage', 'respond', 'contain', 'isolate', 'remediate'
        }
        
        words = text.lower().split()
        return [w for w in words if w in security_keywords]


class AgentRegistry:
    """Registry for managing SOC agents"""
    
    def __init__(self):
        self.agents: Dict[AgentType, BaseSOCAgent] = {}
    
    def register(self, agent: BaseSOCAgent):
        """Register an agent"""
        self.agents[agent.agent_type] = agent
        logger.info(f"Registered agent: {agent.agent_type.value}")
    
    def get_agent(self, agent_type: AgentType) -> Optional[BaseSOCAgent]:
        """Get agent by type"""
        return self.agents.get(agent_type)
    
    def get_all_agents(self) -> List[BaseSOCAgent]:
        """Get all registered agents"""
        return list(self.agents.values())
    
    def find_best_agents(self, query: str, context: Dict[str, Any], max_agents: int = 3) -> List[tuple]:
        """Find the best agents to handle a query"""
        scores = []
        for agent in self.agents.values():
            score = agent.can_handle(query, context)
            if score > 0.1:  # Minimum threshold
                scores.append((agent, score))
        
        # Sort by score descending
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:max_agents]


# Global registry
agent_registry = AgentRegistry()
