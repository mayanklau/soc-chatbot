"""
Orchestrator Agent - Coordinates all SOC agents
Routes queries to appropriate agents and synthesizes responses
"""

import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio
from app.agents.base_agent import BaseSOCAgent, agent_registry
from app.agents.query_agent import QueryAgent
from app.agents.triage_agent import TriageAgent, ThreatIntelAgent
from app.agents.ir_agent import IncidentResponseAgent
from app.models.chat_models import (
    AgentType, AgentResponse, ChatResponse, ChatMessage, 
    ConversationSession, AgentStatus
)
from app.services.data_lake import data_lake
import logging

logger = logging.getLogger(__name__)


class OrchestratorAgent(BaseSOCAgent):
    """
    Orchestrator Agent - The master coordinator for all SOC agents.
    Routes queries, coordinates multi-agent responses, and synthesizes results.
    """
    
    def __init__(self):
        super().__init__(AgentType.ORCHESTRATOR)
        self.sessions: Dict[str, ConversationSession] = {}
        
        # Register specialized agents
        self._register_agents()
        
        # Intent classification patterns
        self.intent_patterns = {
            'greeting': r'^(hi|hello|hey|good morning|good afternoon)\b',
            'help': r'\b(help|how do i|what can you|capabilities)\b',
            'query': r'\b(search|find|show|list|get|query|events|logs)\b',
            'triage': r'\b(triage|prioritize|alerts?|queue|urgent|pending)\b',
            'threat_intel': r'\b(threat|intel|ioc|indicator|apt|actor|enrich|reputation)\b',
            'incident_response': r'\b(respond|contain|isolate|remediate|playbook|what should)\b',
            'statistics': r'\b(statistics|stats|summary|overview|dashboard|how many)\b'
        }
    
    def _register_agents(self):
        """Register all specialized agents"""
        agent_registry.register(QueryAgent())
        agent_registry.register(TriageAgent())
        agent_registry.register(ThreatIntelAgent())
        agent_registry.register(IncidentResponseAgent())
        logger.info("All SOC agents registered")
    
    def can_handle(self, query: str, context: Dict[str, Any]) -> float:
        """Orchestrator can handle all queries"""
        return 1.0
    
    async def process(self, query: str, context: Dict[str, Any]) -> ChatResponse:
        """Process query through appropriate agents"""
        self.reset()
        start_time = datetime.utcnow()
        
        # Get or create session
        session_id = context.get('session_id', str(datetime.utcnow().timestamp()))
        session = self._get_or_create_session(session_id)
        
        # Add user message to session
        user_message = ChatMessage(role="user", content=query)
        session.messages.append(user_message)
        
        self.add_thought("Analyzing query intent and determining appropriate agents", 0.9)
        
        # Classify intent
        primary_intent = self._classify_intent(query)
        self.add_thought(f"Primary intent classified as: {primary_intent}", 0.85)
        
        # Handle special intents
        if primary_intent == 'greeting':
            return self._handle_greeting(session_id, start_time)
        elif primary_intent == 'help':
            return self._handle_help(session_id, start_time)
        
        # Find best agents for the query
        agent_scores = agent_registry.find_best_agents(query, context)
        
        if not agent_scores:
            return self._handle_unknown(session_id, query, start_time)
        
        self.add_thought(f"Selected agents: {[a[0].agent_type.value for a in agent_scores]}", 0.9)
        
        # Process through selected agents
        agent_responses = []
        agents_involved = []
        total_events = 0
        total_queries = 0
        
        for agent, score in agent_scores:
            if score < 0.2:  # Skip low confidence agents
                continue
            
            action = self.add_action(f"delegate_to_{agent.agent_type.value}", {
                "confidence": score
            })
            
            try:
                response = await agent.process(query, {**context, **session.context})
                agent_responses.append(response)
                agents_involved.append(agent.agent_type)
                
                # Track metrics
                if response.data:
                    total_events += len(response.data.get('events', []))
                    total_queries += 1 if response.data.get('query_time_ms') else 0
                
                self.complete_action(action, {
                    "confidence": response.confidence,
                    "processing_time": response.processing_time_ms
                })
            except Exception as e:
                logger.error(f"Agent {agent.agent_type.value} failed: {e}")
                self.complete_action(action, error=str(e))
        
        # Synthesize final response
        final_response = self._synthesize_responses(agent_responses, query)
        
        # Calculate processing time
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        # Add assistant message to session
        assistant_message = ChatMessage(
            role="assistant",
            content=final_response,
            agent_type=AgentType.ORCHESTRATOR
        )
        session.messages.append(assistant_message)
        session.updated_at = datetime.utcnow()
        
        return ChatResponse(
            session_id=session_id,
            response=final_response,
            agents_involved=agents_involved,
            agent_responses=agent_responses,
            processing_time_ms=processing_time,
            data_lake_queries=total_queries,
            events_analyzed=total_events
        )
    
    def _get_or_create_session(self, session_id: str) -> ConversationSession:
        """Get existing session or create new one"""
        if session_id not in self.sessions:
            self.sessions[session_id] = ConversationSession(session_id=session_id)
        return self.sessions[session_id]
    
    def _classify_intent(self, query: str) -> str:
        """Classify the primary intent of the query"""
        query_lower = query.lower().strip()
        
        for intent, pattern in self.intent_patterns.items():
            if re.search(pattern, query_lower):
                return intent
        
        return 'query'  # Default to query intent
    
    def _handle_greeting(self, session_id: str, start_time: datetime) -> ChatResponse:
        """Handle greeting messages"""
        response = """👋 **Hello! I'm your SOC Assistant.**

I'm here to help you with security operations. I can:

🔍 **Query & Search** - Search security events, logs, and alerts
🎯 **Triage** - Prioritize and assess alerts
🔐 **Threat Intel** - Enrich IOCs and provide threat context
🚨 **Incident Response** - Guide you through response playbooks

**Quick Commands:**
• "Show me open alerts" - View current alert queue
• "Triage my alerts" - Get prioritized alert list
• "Search for [IP/hostname]" - Find related events
• "What should I do about this malware?" - Get response guidance

What would you like to investigate today?"""
        
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return ChatResponse(
            session_id=session_id,
            response=response,
            agents_involved=[AgentType.ORCHESTRATOR],
            processing_time_ms=processing_time
        )
    
    def _handle_help(self, session_id: str, start_time: datetime) -> ChatResponse:
        """Handle help requests"""
        response = """📚 **SOC Chatbot Help**

I'm a multi-agent security assistant with specialized capabilities:

**🔍 Query Agent**
Search and analyze security events from the normalized data lake.
Examples:
• "Show me all critical events from today"
• "Find network connections to 185.220.101.1"
• "Get statistics on our security events"

**🎯 Triage Agent**
Prioritize and assess security alerts for efficient handling.
Examples:
• "Triage my open alerts"
• "What's the most critical alert right now?"
• "Prioritize the alert queue"

**🔐 Threat Intel Agent**
Enrich indicators and provide threat context.
Examples:
• "What do we know about IP 185.220.101.1?"
• "Enrich this hash: a1b2c3..."
• "Show me the current threat landscape"

**🚨 Incident Response Agent**
Guide response actions and playbook execution.
Examples:
• "How should I respond to this malware?"
• "What's the playbook for credential theft?"
• "Help me contain this C2 communication"

**Tips:**
• Be specific with IPs, hostnames, or hashes for better results
• I can combine multiple agents for complex queries
• Ask follow-up questions to drill deeper into investigations

What would you like to investigate?"""
        
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return ChatResponse(
            session_id=session_id,
            response=response,
            agents_involved=[AgentType.ORCHESTRATOR],
            processing_time_ms=processing_time
        )
    
    def _handle_unknown(self, session_id: str, query: str, start_time: datetime) -> ChatResponse:
        """Handle unrecognized queries"""
        response = f"""🤔 I'm not sure how to help with that specific request.

Here are some things I can help you with:

• **Search events**: "Show me critical events from the last 24 hours"
• **Triage alerts**: "Prioritize my open alerts"
• **Threat intel**: "What do we know about this IP?"
• **Incident response**: "How do I respond to malware?"

Could you rephrase your question or try one of these commands?"""
        
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return ChatResponse(
            session_id=session_id,
            response=response,
            agents_involved=[AgentType.ORCHESTRATOR],
            processing_time_ms=processing_time
        )
    
    def _synthesize_responses(self, responses: List[AgentResponse], query: str) -> str:
        """Synthesize multiple agent responses into a coherent answer"""
        if not responses:
            return "I couldn't find relevant information for your query."
        
        if len(responses) == 1:
            # Single agent response - use directly
            return responses[0].response
        
        # Multiple agent responses - synthesize
        synthesized = """🤖 **Multi-Agent Analysis**

"""
        for response in responses:
            agent_icon = {
                AgentType.QUERY: "🔍",
                AgentType.TRIAGE: "🎯",
                AgentType.THREAT_INTEL: "🔐",
                AgentType.INCIDENT_RESPONSE: "🚨"
            }.get(response.agent_type, "📋")
            
            synthesized += f"---\n\n**{agent_icon} {response.agent_type.value.replace('_', ' ').title()} Agent:**\n\n"
            synthesized += response.response
            synthesized += "\n\n"
        
        # Collect all suggestions
        all_suggestions = []
        for response in responses:
            all_suggestions.extend(response.suggestions[:2])
        
        if all_suggestions:
            synthesized += "---\n\n**💡 Suggested Next Steps:**\n"
            for suggestion in all_suggestions[:4]:
                synthesized += f"• {suggestion}\n"
        
        return synthesized
    
    def get_session_history(self, session_id: str) -> List[ChatMessage]:
        """Get conversation history for a session"""
        session = self.sessions.get(session_id)
        if session:
            return session.messages
        return []
    
    def clear_session(self, session_id: str):
        """Clear a session"""
        if session_id in self.sessions:
            del self.sessions[session_id]


# Singleton orchestrator
orchestrator = OrchestratorAgent()
