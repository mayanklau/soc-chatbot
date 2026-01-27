"""
Incident Response Agent - Handles response recommendations and playbooks
Specializes in containment, eradication, and recovery guidance
"""

import re
from typing import Dict, Any, List
from datetime import datetime
from app.agents.base_agent import BaseSOCAgent
from app.models.chat_models import AgentType, AgentResponse, DataLakeQuery
from app.services.data_lake import data_lake


class IncidentResponseAgent(BaseSOCAgent):
    """
    Incident Response Agent - Provides response recommendations,
    playbook execution guidance, and containment strategies
    """
    
    def __init__(self):
        super().__init__(AgentType.INCIDENT_RESPONSE)
        
        # Response playbooks
        self.playbooks = {
            'malware': {
                'name': 'Malware Infection Response',
                'severity_threshold': 'high',
                'steps': [
                    {'phase': 'Containment', 'action': 'Isolate affected endpoint from network', 'priority': 1},
                    {'phase': 'Containment', 'action': 'Block malicious hashes at endpoint protection', 'priority': 2},
                    {'phase': 'Containment', 'action': 'Block associated C2 domains/IPs at firewall', 'priority': 3},
                    {'phase': 'Eradication', 'action': 'Run full antimalware scan on affected systems', 'priority': 4},
                    {'phase': 'Eradication', 'action': 'Remove malicious files and registry entries', 'priority': 5},
                    {'phase': 'Recovery', 'action': 'Restore system from clean backup if needed', 'priority': 6},
                    {'phase': 'Recovery', 'action': 'Verify system integrity before reconnecting', 'priority': 7},
                    {'phase': 'Lessons Learned', 'action': 'Document timeline and update detection rules', 'priority': 8}
                ]
            },
            'credential_theft': {
                'name': 'Credential Theft Response',
                'severity_threshold': 'critical',
                'steps': [
                    {'phase': 'Containment', 'action': 'Disable compromised accounts immediately', 'priority': 1},
                    {'phase': 'Containment', 'action': 'Revoke active sessions and tokens', 'priority': 2},
                    {'phase': 'Containment', 'action': 'Isolate source system', 'priority': 3},
                    {'phase': 'Eradication', 'action': 'Force password reset for affected users', 'priority': 4},
                    {'phase': 'Eradication', 'action': 'Review and rotate service account credentials', 'priority': 5},
                    {'phase': 'Eradication', 'action': 'Check for persistence mechanisms', 'priority': 6},
                    {'phase': 'Recovery', 'action': 'Enable MFA if not already active', 'priority': 7},
                    {'phase': 'Recovery', 'action': 'Monitor for further unauthorized access', 'priority': 8},
                    {'phase': 'Lessons Learned', 'action': 'Review authentication logs for scope', 'priority': 9}
                ]
            },
            'c2_communication': {
                'name': 'C2 Communication Response',
                'severity_threshold': 'critical',
                'steps': [
                    {'phase': 'Containment', 'action': 'Block C2 IP/domain at perimeter', 'priority': 1},
                    {'phase': 'Containment', 'action': 'Isolate affected endpoints', 'priority': 2},
                    {'phase': 'Containment', 'action': 'Capture network traffic for analysis', 'priority': 3},
                    {'phase': 'Eradication', 'action': 'Identify and remove malware/implant', 'priority': 4},
                    {'phase': 'Eradication', 'action': 'Search for lateral movement indicators', 'priority': 5},
                    {'phase': 'Eradication', 'action': 'Check for data staging/exfiltration', 'priority': 6},
                    {'phase': 'Recovery', 'action': 'Verify clean state of affected systems', 'priority': 7},
                    {'phase': 'Recovery', 'action': 'Update threat intelligence with new IOCs', 'priority': 8},
                    {'phase': 'Lessons Learned', 'action': 'Assess potential data exposure', 'priority': 9}
                ]
            },
            'data_exfiltration': {
                'name': 'Data Exfiltration Response',
                'severity_threshold': 'critical',
                'steps': [
                    {'phase': 'Containment', 'action': 'Block exfiltration destination immediately', 'priority': 1},
                    {'phase': 'Containment', 'action': 'Isolate source systems', 'priority': 2},
                    {'phase': 'Containment', 'action': 'Preserve evidence (memory, logs, network captures)', 'priority': 3},
                    {'phase': 'Eradication', 'action': 'Identify exfiltration method and tools', 'priority': 4},
                    {'phase': 'Eradication', 'action': 'Determine scope of accessed data', 'priority': 5},
                    {'phase': 'Recovery', 'action': 'Assess regulatory notification requirements', 'priority': 6},
                    {'phase': 'Recovery', 'action': 'Implement additional DLP controls', 'priority': 7},
                    {'phase': 'Lessons Learned', 'action': 'Conduct full breach assessment', 'priority': 8}
                ]
            },
            'suspicious_login': {
                'name': 'Suspicious Login Response',
                'severity_threshold': 'medium',
                'steps': [
                    {'phase': 'Containment', 'action': 'Verify with user if login is legitimate', 'priority': 1},
                    {'phase': 'Containment', 'action': 'If unauthorized, force logout and disable account', 'priority': 2},
                    {'phase': 'Eradication', 'action': 'Reset user credentials', 'priority': 3},
                    {'phase': 'Eradication', 'action': 'Review recent account activity', 'priority': 4},
                    {'phase': 'Recovery', 'action': 'Enable additional authentication factors', 'priority': 5},
                    {'phase': 'Lessons Learned', 'action': 'Check for credential exposure sources', 'priority': 6}
                ]
            }
        }
    
    def can_handle(self, query: str, context: Dict[str, Any]) -> float:
        """Check if this agent can handle the query"""
        query_lower = query.lower()
        score = 0.0
        
        ir_keywords = [
            'respond', 'response', 'contain', 'containment', 'isolate', 'isolation',
            'remediate', 'remediation', 'eradicate', 'recover', 'recovery',
            'playbook', 'runbook', 'what should i do', 'how to respond',
            'next steps', 'action', 'handle', 'mitigate', 'block',
            'disable', 'quarantine', 'incident response', 'ir'
        ]
        
        for keyword in ir_keywords:
            if keyword in query_lower:
                score += 0.2
        
        return min(score, 1.0)
    
    async def process(self, query: str, context: Dict[str, Any]) -> AgentResponse:
        """Process incident response request"""
        self.reset()
        start_time = datetime.utcnow()
        
        self.add_thought("Analyzing incident context to determine appropriate response playbook", 0.9)
        
        # Determine incident type from query/context
        incident_type = self._classify_incident(query, context)
        self.add_thought(f"Classified incident type: {incident_type}", 0.85)
        
        # Get relevant playbook
        playbook = self.playbooks.get(incident_type, self.playbooks['malware'])
        
        # Get affected entities from context or query
        affected_entities = self._extract_entities(query, context)
        
        # Generate response plan
        response_text = self._generate_response_plan(playbook, affected_entities, query)
        
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return AgentResponse(
            agent_type=self.agent_type,
            response=response_text,
            confidence=0.88,
            actions_taken=self.actions,
            thoughts=self.thoughts,
            data={
                'incident_type': incident_type,
                'playbook': playbook,
                'affected_entities': affected_entities
            },
            suggestions=[
                "Execute containment actions",
                "Get timeline for affected hosts",
                "Search for related IOCs",
                "Check for lateral movement"
            ],
            processing_time_ms=processing_time
        )
    
    def _classify_incident(self, query: str, context: Dict[str, Any]) -> str:
        """Classify the incident type"""
        query_lower = query.lower()
        
        # Check for specific incident indicators
        if any(word in query_lower for word in ['mimikatz', 'credential', 'password', 'dump', 'lsass']):
            return 'credential_theft'
        elif any(word in query_lower for word in ['c2', 'beacon', 'command and control', 'callback']):
            return 'c2_communication'
        elif any(word in query_lower for word in ['exfil', 'data theft', 'upload', 'staging']):
            return 'data_exfiltration'
        elif any(word in query_lower for word in ['login', 'authentication', 'brute', 'unauthorized access']):
            return 'suspicious_login'
        elif any(word in query_lower for word in ['malware', 'virus', 'ransomware', 'trojan']):
            return 'malware'
        
        # Check context for event types
        if context.get('event_type') == 'process_activity':
            return 'malware'
        elif context.get('event_type') == 'network_activity':
            return 'c2_communication'
        
        return 'malware'  # Default
    
    def _extract_entities(self, query: str, context: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract affected entities"""
        entities = {
            'hosts': [],
            'ips': [],
            'users': []
        }
        
        # From query
        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', query)
        entities['ips'].extend(ips)
        
        hostnames = re.findall(r'\b(WKS-\d+|SRV-\w+)\b', query)
        entities['hosts'].extend(hostnames)
        
        # From context
        if context.get('device', {}).get('hostname'):
            entities['hosts'].append(context['device']['hostname'])
        if context.get('device', {}).get('ip'):
            entities['ips'].append(context['device']['ip'])
        if context.get('actor', {}).get('user_name'):
            entities['users'].append(context['actor']['user_name'])
        
        return entities
    
    def _generate_response_plan(self, playbook: Dict, entities: Dict, query: str) -> str:
        """Generate incident response plan"""
        action = self.add_action("generate_response_plan", {
            "playbook": playbook['name'],
            "entities": entities
        })
        
        response = f"""🚨 **Incident Response Plan**

**Playbook:** {playbook['name']}
**Severity Level:** {playbook['severity_threshold'].upper()}

"""
        # Affected entities
        if any(entities.values()):
            response += "**Affected Entities:**\n"
            if entities['hosts']:
                response += f"  • Hosts: {', '.join(set(entities['hosts']))}\n"
            if entities['ips']:
                response += f"  • IPs: {', '.join(set(entities['ips']))}\n"
            if entities['users']:
                response += f"  • Users: {', '.join(set(entities['users']))}\n"
            response += "\n"
        
        response += "---\n\n"
        
        # Group steps by phase
        phases = {}
        for step in playbook['steps']:
            phase = step['phase']
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(step)
        
        phase_icons = {
            'Containment': '🛡️',
            'Eradication': '🔥',
            'Recovery': '🔄',
            'Lessons Learned': '📝'
        }
        
        for phase, steps in phases.items():
            icon = phase_icons.get(phase, '📋')
            response += f"**{icon} {phase}**\n"
            for step in steps:
                response += f"  {step['priority']}. {step['action']}\n"
            response += "\n"
        
        # Quick actions
        response += """---

**⚡ Immediate Actions:**
"""
        immediate = [s for s in playbook['steps'] if s['priority'] <= 3]
        for step in immediate:
            response += f"  → {step['action']}\n"
        
        response += """
**📞 Escalation Contacts:**
  • SOC Manager: On-call rotation
  • CSIRT Lead: For critical incidents
  • Legal/Compliance: If data breach suspected
"""
        
        self.complete_action(action, {"phases": list(phases.keys())})
        
        return response
