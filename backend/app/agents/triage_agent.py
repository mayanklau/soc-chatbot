"""
Triage Agent - Handles alert prioritization and initial assessment
Specializes in quick evaluation and routing of security alerts
"""

import re
from typing import Dict, Any, List
from datetime import datetime, timedelta
from app.agents.base_agent import BaseSOCAgent
from app.models.chat_models import AgentType, AgentResponse, DataLakeQuery
from app.services.data_lake import data_lake


class TriageAgent(BaseSOCAgent):
    """
    Triage Agent - Performs initial alert assessment, prioritization,
    and provides quick recommendations for alert handling
    """
    
    def __init__(self):
        super().__init__(AgentType.TRIAGE)
        
        # Priority scoring weights
        self.severity_scores = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25,
            'informational': 10
        }
        
        # MITRE ATT&CK high-priority techniques
        self.critical_techniques = [
            'T1003',  # Credential Dumping
            'T1059',  # Command and Scripting Interpreter
            'T1055',  # Process Injection
            'T1021',  # Remote Services
            'T1486',  # Data Encrypted for Impact (Ransomware)
            'T1567',  # Exfiltration Over Web Service
            'T1071',  # Application Layer Protocol (C2)
        ]
    
    def can_handle(self, query: str, context: Dict[str, Any]) -> float:
        """Check if this agent can handle the query"""
        query_lower = query.lower()
        score = 0.0
        
        # Triage-specific keywords
        triage_keywords = [
            'triage', 'prioritize', 'priority', 'urgent', 'important',
            'alert', 'alerts', 'assess', 'evaluate', 'review',
            'open alerts', 'pending', 'queue', 'backlog',
            'what should i', 'where to start', 'most critical',
            'handle first', 'investigate first'
        ]
        
        for keyword in triage_keywords:
            if keyword in query_lower:
                score += 0.2
        
        # Check for alert-related context
        if 'alert' in query_lower:
            score += 0.15
        
        return min(score, 1.0)
    
    async def process(self, query: str, context: Dict[str, Any]) -> AgentResponse:
        """Process the triage request"""
        self.reset()
        start_time = datetime.utcnow()
        
        self.add_thought("Initiating triage assessment of current alert queue", 0.9)
        
        # Get open alerts
        action = self.add_action("fetch_open_alerts", {})
        alerts = data_lake.get_alerts(status="open")
        self.complete_action(action, {"count": len(alerts)})
        
        self.add_thought(f"Found {len(alerts)} open alerts to triage", 0.95)
        
        # Score and prioritize alerts
        prioritized = await self._prioritize_alerts(alerts)
        
        # Generate triage report
        response_text = self._generate_triage_report(prioritized)
        
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return AgentResponse(
            agent_type=self.agent_type,
            response=response_text,
            confidence=0.88,
            actions_taken=self.actions,
            thoughts=self.thoughts,
            data={
                'prioritized_alerts': prioritized,
                'total_open': len(alerts),
                'critical_count': len([a for a in prioritized if a['priority_score'] >= 90])
            },
            suggestions=[
                "Investigate the top priority alert",
                "Show me threat intelligence for these IOCs",
                "What response actions are recommended?",
                "Get timeline for the affected hosts"
            ],
            processing_time_ms=processing_time
        )
    
    async def _prioritize_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Score and prioritize alerts"""
        action = self.add_action("calculate_priority_scores", {"alert_count": len(alerts)})
        
        scored_alerts = []
        for alert in alerts:
            score = self._calculate_priority_score(alert)
            scored_alert = {
                **alert,
                'priority_score': score,
                'priority_factors': self._get_priority_factors(alert, score)
            }
            scored_alerts.append(scored_alert)
        
        # Sort by priority score descending
        scored_alerts.sort(key=lambda x: x['priority_score'], reverse=True)
        
        self.complete_action(action, {"scored": len(scored_alerts)})
        self.add_thought("Completed priority scoring based on severity, MITRE mapping, and context", 0.9)
        
        return scored_alerts
    
    def _calculate_priority_score(self, alert: Dict) -> int:
        """Calculate priority score for an alert"""
        score = 0
        
        # Base severity score
        severity = alert.get('severity', 'low')
        score += self.severity_scores.get(severity, 25)
        
        # MITRE ATT&CK technique bonus
        mitre_mappings = alert.get('mitre_attack', [])
        for mapping in mitre_mappings:
            technique_id = mapping.get('technique_id', '')
            if any(technique_id.startswith(t) for t in self.critical_techniques):
                score += 20
                break
        
        # Threat indicator bonus
        if alert.get('threat_indicators'):
            score += 15
            # High confidence IOCs
            for ioc in alert.get('threat_indicators', []):
                if ioc.get('confidence', 0) > 0.9:
                    score += 10
                    break
        
        # Critical asset bonus (servers, DCs)
        hostname = alert.get('device', {}).get('hostname', '')
        if 'SRV' in hostname or 'DC' in hostname:
            score += 15
        
        # Executive/admin user bonus
        username = alert.get('actor', {}).get('user_name', '')
        if username in ['admin', 'root', 'SYSTEM'] or 'admin' in username.lower():
            score += 10
        
        return min(score, 100)
    
    def _get_priority_factors(self, alert: Dict, score: int) -> List[str]:
        """Get human-readable priority factors"""
        factors = []
        
        severity = alert.get('severity', 'low')
        factors.append(f"Severity: {severity.upper()}")
        
        if alert.get('mitre_attack'):
            techniques = [m.get('technique_name', m.get('technique_id', 'Unknown')) 
                         for m in alert.get('mitre_attack', [])]
            factors.append(f"MITRE: {', '.join(techniques[:2])}")
        
        if alert.get('threat_indicators'):
            factors.append(f"IOCs: {len(alert['threat_indicators'])} indicators")
        
        hostname = alert.get('device', {}).get('hostname', '')
        if 'SRV' in hostname:
            factors.append("Critical asset: Server")
        
        return factors
    
    def _generate_triage_report(self, prioritized: List[Dict]) -> str:
        """Generate triage report"""
        report = """🎯 **Alert Triage Report**

"""
        # Summary
        critical = len([a for a in prioritized if a['priority_score'] >= 90])
        high = len([a for a in prioritized if 70 <= a['priority_score'] < 90])
        medium = len([a for a in prioritized if 50 <= a['priority_score'] < 70])
        low = len([a for a in prioritized if a['priority_score'] < 50])
        
        report += f"""**Queue Summary:**
🔴 Critical Priority: {critical}
🟠 High Priority: {high}
🟡 Medium Priority: {medium}
🟢 Low Priority: {low}

---

**🚨 Top Priority Alerts (Handle First):**

"""
        # Top 5 alerts
        for i, alert in enumerate(prioritized[:5], 1):
            score = alert['priority_score']
            score_icon = "🔴" if score >= 90 else "🟠" if score >= 70 else "🟡" if score >= 50 else "🟢"
            
            report += f"""**{i}. {alert['alert_name']}** {score_icon} Score: {score}/100
   • Alert ID: `{alert['alert_id']}`
   • Device: `{alert.get('device', {}).get('hostname', 'Unknown')}`
   • Factors: {' | '.join(alert['priority_factors'][:3])}
   • Description: {alert.get('alert_description', 'N/A')[:100]}

"""
        
        if len(prioritized) > 5:
            report += f"\n_...and {len(prioritized) - 5} more alerts in queue_\n"
        
        # Recommendations
        report += """
---

**📋 Recommended Actions:**
1. Investigate top critical alerts immediately
2. Correlate related events across affected hosts
3. Check threat intelligence for any IOCs
4. Prepare containment actions for confirmed threats
"""
        
        return report


class ThreatIntelAgent(BaseSOCAgent):
    """
    Threat Intelligence Agent - Provides threat context, IOC enrichment,
    and threat actor intelligence
    """
    
    def __init__(self):
        super().__init__(AgentType.THREAT_INTEL)
        
        # Mock threat intelligence database
        self.threat_db = {
            '185.220.101.1': {
                'type': 'ip',
                'threat_type': 'C2 Server',
                'threat_actor': 'APT28',
                'confidence': 0.95,
                'first_seen': '2024-06-15',
                'campaigns': ['SolarStorm', 'DarkPhoenix'],
                'description': 'Known command and control server associated with APT28 operations',
                'recommendations': [
                    'Block at perimeter firewall',
                    'Search for historical connections',
                    'Check for data exfiltration'
                ]
            },
            '91.121.87.10': {
                'type': 'ip',
                'threat_type': 'Malware Distribution',
                'threat_actor': 'Emotet Gang',
                'confidence': 0.88,
                'first_seen': '2024-08-20',
                'campaigns': ['Emotet Revival'],
                'description': 'Malware distribution server hosting Emotet payloads',
                'recommendations': [
                    'Block IP and associated domains',
                    'Scan endpoints for Emotet indicators',
                    'Review email logs for phishing'
                ]
            },
            'malware-c2.evil.com': {
                'type': 'domain',
                'threat_type': 'C2 Domain',
                'threat_actor': 'Unknown',
                'confidence': 0.92,
                'first_seen': '2024-09-01',
                'description': 'Command and control domain used by multiple malware families',
                'recommendations': [
                    'Block domain at DNS level',
                    'Check for beaconing activity',
                    'Investigate affected endpoints'
                ]
            }
        }
    
    def can_handle(self, query: str, context: Dict[str, Any]) -> float:
        """Check if this agent can handle the query"""
        query_lower = query.lower()
        score = 0.0
        
        intel_keywords = [
            'threat', 'intelligence', 'intel', 'ioc', 'indicator',
            'apt', 'actor', 'campaign', 'malware', 'attribution',
            'enrich', 'lookup', 'reputation', 'what do we know',
            'who is behind', 'threat actor', 'c2', 'command and control'
        ]
        
        for keyword in intel_keywords:
            if keyword in query_lower:
                score += 0.2
        
        # Check for IOC patterns
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', query):
            score += 0.15
        if re.search(r'\b[a-f0-9]{32,64}\b', query_lower):
            score += 0.15
        if re.search(r'\b[\w\.-]+\.(com|net|org|io|xyz)\b', query_lower):
            score += 0.1
        
        return min(score, 1.0)
    
    async def process(self, query: str, context: Dict[str, Any]) -> AgentResponse:
        """Process threat intelligence request"""
        self.reset()
        start_time = datetime.utcnow()
        
        self.add_thought("Analyzing request for threat intelligence lookup", 0.9)
        
        # Extract IOCs from query
        iocs = self._extract_iocs(query)
        
        if iocs:
            response_text, intel_data = await self._enrich_iocs(iocs)
        else:
            # General threat landscape query
            response_text, intel_data = await self._threat_landscape()
        
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return AgentResponse(
            agent_type=self.agent_type,
            response=response_text,
            confidence=0.85,
            actions_taken=self.actions,
            thoughts=self.thoughts,
            data=intel_data,
            suggestions=[
                "Search for related IOCs in our data",
                "What containment actions should we take?",
                "Show me affected hosts",
                "Get timeline of related events"
            ],
            processing_time_ms=processing_time
        )
    
    def _extract_iocs(self, text: str) -> List[Dict]:
        """Extract IOCs from text"""
        iocs = []
        
        # IPs
        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        for ip in ips:
            iocs.append({'type': 'ip', 'value': ip})
        
        # Hashes
        hashes = re.findall(r'\b([a-f0-9]{32,64})\b', text.lower())
        for h in hashes:
            iocs.append({'type': 'hash', 'value': h})
        
        # Domains (simple pattern)
        domains = re.findall(r'\b([\w\.-]+\.(com|net|org|io|xyz))\b', text.lower())
        for d in domains:
            iocs.append({'type': 'domain', 'value': d[0]})
        
        return iocs
    
    async def _enrich_iocs(self, iocs: List[Dict]) -> tuple:
        """Enrich IOCs with threat intelligence"""
        action = self.add_action("enrich_iocs", {"count": len(iocs)})
        
        enriched = []
        for ioc in iocs:
            intel = self.threat_db.get(ioc['value'])
            if intel:
                enriched.append({**ioc, 'intel': intel, 'found': True})
            else:
                enriched.append({**ioc, 'intel': None, 'found': False})
        
        self.complete_action(action, {"enriched": len([e for e in enriched if e['found']])})
        
        # Generate response
        found = [e for e in enriched if e['found']]
        not_found = [e for e in enriched if not e['found']]
        
        response = """🔍 **Threat Intelligence Report**

"""
        if found:
            response += "**🎯 Known Threat Indicators:**\n\n"
            for item in found:
                intel = item['intel']
                response += f"""**{item['type'].upper()}: `{item['value']}`**
• Threat Type: {intel.get('threat_type', 'Unknown')}
• Threat Actor: {intel.get('threat_actor', 'Unknown')}
• Confidence: {intel.get('confidence', 0) * 100:.0f}%
• First Seen: {intel.get('first_seen', 'Unknown')}
• Description: {intel.get('description', 'N/A')}

**Recommendations:**
"""
                for rec in intel.get('recommendations', []):
                    response += f"  → {rec}\n"
                response += "\n"
        
        if not_found:
            response += f"\n**⚪ No Intelligence Found ({len(not_found)} IOCs):**\n"
            for item in not_found:
                response += f"  • {item['type']}: `{item['value']}`\n"
        
        return response, {'enriched_iocs': enriched}
    
    async def _threat_landscape(self) -> tuple:
        """Provide general threat landscape overview"""
        action = self.add_action("get_threat_landscape", {})
        
        # Get events with threat indicators
        query = DataLakeQuery(
            query_type="search",
            filters={"has_threat_indicators": True},
            limit=100
        )
        result = data_lake.query(query)
        
        self.complete_action(action, {"threat_events": result.total_hits})
        
        # Aggregate threat types
        threat_types = {}
        threat_actors = {}
        for event in result.events:
            for ioc in event.get('threat_indicators', []):
                t_type = ioc.get('threat_type', 'unknown')
                threat_types[t_type] = threat_types.get(t_type, 0) + 1
        
        response = """🌐 **Current Threat Landscape**

**Detected Threat Activity:**
"""
        response += f"• Total events with threat indicators: {result.total_hits}\n\n"
        
        if threat_types:
            response += "**Threat Types Observed:**\n"
            for t_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:5]:
                response += f"  • {t_type}: {count} events\n"
        
        response += """
**Active Threat Actors in Database:**
• APT28 - Nation-state actor, C2 infrastructure active
• Emotet Gang - Malware distribution ongoing
• Various unknown actors

**Recommended Focus Areas:**
1. Monitor for C2 beaconing activity
2. Review email security for phishing attempts
3. Ensure endpoint protection is updated
"""
        
        return response, {'threat_events': result.total_hits, 'threat_types': threat_types}
