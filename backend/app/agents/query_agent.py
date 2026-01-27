"""
Query Agent - Handles data lake queries and searches
Specialized in translating natural language to data lake queries
"""

import re
from typing import Dict, Any, List
from datetime import datetime, timedelta
from app.agents.base_agent import BaseSOCAgent
from app.models.chat_models import AgentType, AgentResponse, DataLakeQuery
from app.services.data_lake import data_lake


class QueryAgent(BaseSOCAgent):
    """
    Query Agent - Translates natural language queries to data lake searches
    and returns relevant security events
    """
    
    def __init__(self):
        super().__init__(AgentType.QUERY)
        
        # Query intent patterns
        self.query_patterns = {
            'search': r'\b(search|find|look|query|get|show|list|display)\b',
            'count': r'\b(count|how many|number of|total)\b',
            'timeline': r'\b(timeline|history|over time|trend|when)\b',
            'statistics': r'\b(statistics|stats|summary|overview|dashboard)\b',
            'filter_severity': r'\b(critical|high|medium|low|informational)\b',
            'filter_type': r'\b(network|process|file|dns|authentication|alert)\b',
            'filter_time': r'\b(today|yesterday|last \d+ (hours?|days?|weeks?)|past|recent)\b',
            'entity_ip': r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            'entity_hostname': r'\b(WKS-\d+|SRV-\w+)\b',
            'entity_user': r'\b(user[:\s]+\w+|username[:\s]+\w+)\b'
        }
    
    def can_handle(self, query: str, context: Dict[str, Any]) -> float:
        """Check if this agent can handle the query"""
        query_lower = query.lower()
        score = 0.0
        
        # Check for query-related keywords
        query_keywords = ['search', 'find', 'query', 'show', 'list', 'get', 'events', 
                         'logs', 'data', 'statistics', 'count', 'how many', 'timeline']
        for keyword in query_keywords:
            if keyword in query_lower:
                score += 0.15
        
        # Check for entity references
        if re.search(self.query_patterns['entity_ip'], query):
            score += 0.2
        if re.search(self.query_patterns['entity_hostname'], query):
            score += 0.2
        
        # Check for filter terms
        if re.search(self.query_patterns['filter_severity'], query_lower):
            score += 0.1
        if re.search(self.query_patterns['filter_type'], query_lower):
            score += 0.1
        
        return min(score, 1.0)
    
    async def process(self, query: str, context: Dict[str, Any]) -> AgentResponse:
        """Process the query"""
        self.reset()
        start_time = datetime.utcnow()
        
        self.add_thought("Analyzing query to determine search parameters", 0.9)
        
        # Parse query intent
        intent = self._parse_intent(query)
        self.add_thought(f"Identified intent: {intent['type']}", 0.85)
        
        # Build and execute query
        response_data = {}
        response_text = ""
        
        if intent['type'] == 'statistics':
            response_data, response_text = await self._handle_statistics()
        elif intent['type'] == 'timeline':
            response_data, response_text = await self._handle_timeline(query, intent)
        elif intent['type'] == 'count':
            response_data, response_text = await self._handle_count(query, intent)
        else:
            response_data, response_text = await self._handle_search(query, intent)
        
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return AgentResponse(
            agent_type=self.agent_type,
            response=response_text,
            confidence=0.85,
            actions_taken=self.actions,
            thoughts=self.thoughts,
            data=response_data,
            suggestions=self._generate_suggestions(intent, response_data),
            processing_time_ms=processing_time
        )
    
    def _parse_intent(self, query: str) -> Dict[str, Any]:
        """Parse query to determine intent and parameters"""
        query_lower = query.lower()
        intent = {
            'type': 'search',
            'filters': {},
            'time_range': None,
            'entities': [],
            'aggregations': []
        }
        
        # Determine query type
        if re.search(self.query_patterns['statistics'], query_lower):
            intent['type'] = 'statistics'
        elif re.search(self.query_patterns['timeline'], query_lower):
            intent['type'] = 'timeline'
        elif re.search(self.query_patterns['count'], query_lower):
            intent['type'] = 'count'
        
        # Extract severity filter
        severity_match = re.search(self.query_patterns['filter_severity'], query_lower)
        if severity_match:
            intent['filters']['severity'] = severity_match.group(1)
        
        # Extract event type filter
        type_keywords = {
            'network': 'network_activity',
            'process': 'process_activity',
            'file': 'file_activity',
            'dns': 'dns_query',
            'authentication': 'authentication',
            'alert': 'alert'
        }
        for keyword, event_type in type_keywords.items():
            if keyword in query_lower:
                intent['filters']['event_type'] = event_type
                break
        
        # Extract IP addresses
        ip_matches = re.findall(self.query_patterns['entity_ip'], query)
        if ip_matches:
            intent['entities'].extend([('ip', ip) for ip in ip_matches])
            intent['filters']['ip'] = ip_matches[0]
        
        # Extract hostnames
        hostname_matches = re.findall(self.query_patterns['entity_hostname'], query)
        if hostname_matches:
            intent['entities'].extend([('hostname', h) for h in hostname_matches])
            intent['filters']['hostname'] = hostname_matches[0]
        
        # Extract time range
        time_match = re.search(self.query_patterns['filter_time'], query_lower)
        if time_match:
            intent['time_range'] = self._parse_time_range(time_match.group(0))
        
        # Check for suspicious/malicious filter
        if any(word in query_lower for word in ['suspicious', 'malicious', 'threat', 'attack']):
            intent['filters']['has_threat_indicators'] = True
        
        return intent
    
    def _parse_time_range(self, time_str: str) -> Dict[str, datetime]:
        """Parse time string to datetime range"""
        now = datetime.utcnow()
        
        if 'today' in time_str:
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif 'yesterday' in time_str:
            start = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            # Parse "last X hours/days"
            match = re.search(r'(\d+)\s*(hours?|days?|weeks?)', time_str)
            if match:
                num = int(match.group(1))
                unit = match.group(2)
                if 'hour' in unit:
                    start = now - timedelta(hours=num)
                elif 'day' in unit:
                    start = now - timedelta(days=num)
                elif 'week' in unit:
                    start = now - timedelta(weeks=num)
                else:
                    start = now - timedelta(hours=24)
            else:
                start = now - timedelta(hours=24)
        
        return {'start': start, 'end': now}
    
    async def _handle_statistics(self) -> tuple:
        """Handle statistics query"""
        action = self.add_action("get_statistics", {})
        
        stats = data_lake.get_statistics()
        
        self.complete_action(action, stats)
        
        response_text = f"""📊 **Data Lake Statistics**

**Event Summary:**
• Total Events: {stats['total_events']:,}
• Events (Last 24h): {stats['events_last_24h']:,}
• Data Sources: {', '.join(stats['sources'])}

**Alert Summary:**
• Total Alerts: {stats['total_alerts']:,}
• Open Alerts: {stats['open_alerts']}
• Critical: {stats['critical_alerts']} | High: {stats['high_alerts']}

**Event Types:** {', '.join(stats['event_types'])}"""
        
        return {'statistics': stats}, response_text
    
    async def _handle_timeline(self, query: str, intent: Dict) -> tuple:
        """Handle timeline query"""
        entity_type = None
        entity_value = None
        
        if intent['entities']:
            entity_type, entity_value = intent['entities'][0]
        
        if not entity_type:
            # Default to recent events
            return await self._handle_search(query, intent)
        
        action = self.add_action("get_timeline", {
            "entity_type": entity_type,
            "entity_value": entity_value
        })
        
        timeline = data_lake.get_timeline(entity_type, entity_value, hours=48)
        
        self.complete_action(action, {"event_count": len(timeline)})
        
        response_text = f"""📅 **Timeline for {entity_type}: {entity_value}**

Found **{len(timeline)}** events in the last 48 hours.

"""
        for event in timeline[:10]:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                event.get("severity"), "⚪"
            )
            response_text += f"{severity_icon} [{event['event_time'][:19]}] {event['event_type']}: {event.get('message', 'N/A')}\n"
        
        if len(timeline) > 10:
            response_text += f"\n_...and {len(timeline) - 10} more events_"
        
        return {'timeline': timeline, 'entity': {'type': entity_type, 'value': entity_value}}, response_text
    
    async def _handle_count(self, query: str, intent: Dict) -> tuple:
        """Handle count query"""
        action = self.add_action("count_events", intent['filters'])
        
        dl_query = DataLakeQuery(
            query_type="aggregate",
            filters=intent['filters'],
            time_range=intent.get('time_range'),
            aggregations=['severity', 'event_type', 'source']
        )
        
        result = data_lake.query(dl_query)
        
        self.complete_action(action, {"total": result.total_hits})
        
        response_text = f"""📈 **Event Count Summary**

**Total Matching Events:** {result.total_hits:,}

"""
        if result.aggregations:
            if 'severity' in result.aggregations:
                response_text += "**By Severity:**\n"
                for item in result.aggregations['severity']:
                    response_text += f"  • {item['key'].title()}: {item['count']:,}\n"
            
            if 'event_type' in result.aggregations:
                response_text += "\n**By Event Type:**\n"
                for item in result.aggregations['event_type'][:5]:
                    response_text += f"  • {item['key']}: {item['count']:,}\n"
        
        return {'count': result.total_hits, 'aggregations': result.aggregations}, response_text
    
    async def _handle_search(self, query: str, intent: Dict) -> tuple:
        """Handle general search query"""
        action = self.add_action("search_events", intent['filters'])
        
        # Add full-text search if no specific filters
        if not intent['filters'] and not intent.get('time_range'):
            intent['filters']['search'] = query
        
        dl_query = DataLakeQuery(
            query_type="search",
            filters=intent['filters'],
            time_range=intent.get('time_range'),
            limit=20,
            sort_by="event_time",
            sort_order="desc"
        )
        
        result = data_lake.query(dl_query)
        
        self.complete_action(action, {"hits": result.total_hits, "returned": len(result.events)})
        
        response_text = f"""🔍 **Search Results**

Found **{result.total_hits:,}** matching events (showing top {len(result.events)})

"""
        for event in result.events[:10]:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                event.get("severity"), "⚪"
            )
            device = event.get("device", {}).get("hostname", "Unknown")
            response_text += f"{severity_icon} **{event['event_type']}** on `{device}`\n"
            response_text += f"   {event.get('message', 'No message')[:80]}\n"
            response_text += f"   _Source: {event['source']} | {event['event_time'][:19]}_\n\n"
        
        return {
            'total_hits': result.total_hits,
            'events': result.events,
            'query_time_ms': result.query_time_ms
        }, response_text
    
    def _generate_suggestions(self, intent: Dict, response_data: Dict) -> List[str]:
        """Generate follow-up suggestions"""
        suggestions = []
        
        if intent['type'] == 'statistics':
            suggestions.extend([
                "Show me all critical alerts",
                "What suspicious activity happened today?",
                "List recent network connections to external IPs"
            ])
        elif response_data.get('total_hits', 0) > 0:
            suggestions.extend([
                "Can you investigate these events further?",
                "Show me related threat intelligence",
                "What should be our response actions?"
            ])
        else:
            suggestions.extend([
                "Try a broader search",
                "Show me overall statistics",
                "List recent high severity events"
            ])
        
        return suggestions
