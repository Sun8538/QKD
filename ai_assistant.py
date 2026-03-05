"""
AI Assistant Module for Quantum Key Management
Uses Azure OpenAI for intelligent key rotation recommendations
"""
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

class AIKeyManagementAssistant:
    """
    AI-powered assistant for quantum key management decisions
    Uses Azure OpenAI for intelligent recommendations
    """
    
    def __init__(self, azure_endpoint: str = None, azure_key: str = None, deployment: str = None):
        self.azure_endpoint = azure_endpoint or os.environ.get('AZURE_OPENAI_ENDPOINT', '')
        self.azure_key = azure_key or os.environ.get('AZURE_OPENAI_KEY', '')
        self.deployment = deployment or os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'gpt-4o')
        self.api_version = '2024-11-20'
        self.client = None
        self._initialize_client()
        print(f"AI Assistant initialized with endpoint: {self.azure_endpoint[:30]}..." if self.azure_endpoint else "AI Assistant: No endpoint configured")
        
    def _initialize_client(self):
        """Initialize Azure OpenAI client if credentials are available"""
        try:
            if self.azure_endpoint and self.azure_key:
                from openai import AzureOpenAI
                self.client = AzureOpenAI(
                    azure_endpoint=self.azure_endpoint,
                    api_key=self.azure_key,
                    api_version=self.api_version
                )
        except ImportError:
            print("OpenAI package not installed. AI features will use fallback logic.")
        except Exception as e:
            print(f".: {e}")
    
    def _get_ai_response(self, prompt: str) -> str:
        """Get response from Azure OpenAI"""
        if not self.client:
            print("AI Client not initialized, using fallback")
            return self._fallback_response(prompt)
        
        try:
            response = self.client.chat.completions.create(
                model=self.deployment,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a quantum cryptography security expert assistant. 
                        You help manage quantum keys for secure IoT communications.
                        Provide concise, actionable recommendations for key management.
                        Focus on security best practices and optimal key rotation schedules."""
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.7
            )
            content = response.choices[0].message.content
            return content if content else self._fallback_response(prompt)
        except Exception as e:
            print(f"AI API error: {e}")
            print(f"Endpoint: {self.azure_endpoint}")
            print(f"Deployment: {self.deployment}")
            return self._fallback_response(prompt)
    
    def _fallback_response(self, prompt: str) -> str:
        """Fallback logic when AI is not available - provides varied intelligent responses"""
        prompt_lower = prompt.lower()
        
        # Key rotation queries
        if any(word in prompt_lower for word in ["rotation", "refresh", "rotate", "renew"]):
            return """🔄 **Key Rotation Recommendations:**

Based on quantum security best practices:

1. **Immediate Actions:**
   - Rotate keys every 5 minutes for high-security sessions
   - Immediately rotate if error rate exceeds 5%
   - Force rotation after 100 message exchanges

2. **Optimal Refresh Schedule:**
   - High-security channels: Every 2-3 minutes
   - Standard channels: Every 5-10 minutes
   - Low-activity channels: Every 15-30 minutes

3. **Security Notes:**
   - Monitor QBER (Quantum Bit Error Rate) continuously
   - Log all key operations for audit trail
   - Implement automatic expiration after 1 hour maximum

💡 *Tip: Use the 'Schedule Rotation' button to automate key refresh.*"""

        # Security and threat queries
        elif any(word in prompt_lower for word in ["security", "threat", "attack", "secure", "protect", "vulnerability"]):
            return """🛡️ **Security Assessment:**

**Current Security Recommendations:**
1. Enable continuous error rate monitoring
2. Implement automatic key invalidation on anomalies
3. Use multi-factor verification for key access
4. Maintain encrypted backup of key metadata

**⚠️ Threat Indicators to Watch:**
- Sudden increase in error rates (>5%)
- Unusual access patterns
- Failed verification attempts
- Timing anomalies in key exchange

**Preventive Measures:**
- Regular key rotation
- Access logging and auditing
- Quantum-resistant backup protocols"""

        # Error rate queries
        elif any(word in prompt_lower for word in ["error", "qber", "rate", "quality"]):
            return """📊 **Error Rate Analysis:**

**Understanding QBER (Quantum Bit Error Rate):**
- **< 3%**: Excellent - Key is highly secure
- **3-5%**: Good - Normal operational range
- **5-11%**: Warning - Consider key rotation
- **> 11%**: Critical - Possible eavesdropping detected

**Actions Based on Error Rate:**
1. Below 5%: Continue normal operations
2. 5-8%: Schedule key rotation soon
3. 8-11%: Immediate rotation recommended
4. Above 11%: Stop transmission, generate new key

💡 *Your current keys are monitored in the Security Health panel.*"""

        # Best practices queries
        elif any(word in prompt_lower for word in ["best practice", "recommend", "tip", "advice", "how to"]):
            return """📚 **QKD Best Practices:**

**1. Key Management:**
- Generate new keys for each communication session
- Never reuse quantum keys
- Implement automatic key expiration

**2. Channel Security:**
- Verify all channel members before sharing keys
- Use separate keys for different security levels
- Monitor channel activity for anomalies

**3. File Encryption:**
- Always encrypt sensitive files before sharing
- Use QR codes for secure key distribution
- Implement approval workflows for file access

**4. Monitoring:**
- Check error rates regularly
- Review access logs
- Set up alerts for suspicious activity"""

        # Help or general queries
        elif any(word in prompt_lower for word in ["help", "what", "how", "can you"]):
            return """🤖 **Quantum Security Assistant**

I can help you with:

1. **🔄 Key Rotation** - When and how to refresh your quantum keys
2. **🛡️ Security Analysis** - Assess your current security posture
3. **📊 Error Monitoring** - Understanding QBER and key quality
4. **📁 File Security** - Best practices for encrypted file sharing
5. **👥 Channel Management** - Securing group communications

**Quick Actions:**
- Click "Analyze All Keys" to get a full security report
- Use "Schedule Rotation" for automatic key refresh
- Check the Security Health panel for real-time metrics

*Ask me specific questions for detailed recommendations!*"""

        # Default response with context-aware suggestions
        else:
            return f"""🤖 **Quantum Security Analysis:**

Based on your query about "{prompt[:50]}...", here are my recommendations:

**Key Security Tips:**
1. Regularly rotate quantum keys (every 5-10 minutes recommended)
2. Monitor error rates - keep QBER below 5%
3. Use separate keys for different security levels
4. Enable automatic key expiration

**Available Actions:**
- 🔍 Click "Analyze All Keys" for a comprehensive security audit
- 📊 Check Security Health panel for real-time metrics
- ⚙️ Use Schedule Rotation for automated key management

*For specific guidance, try asking about: key rotation, security best practices, error rates, or threat detection.*"""

    def analyze_key_health(self, key_data: Dict) -> Dict[str, Any]:
        """Analyze the health of a quantum key"""
        analysis = {
            'key_id': key_data.get('key_id', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'health_score': 100,
            'recommendations': [],
            'warnings': [],
            'status': 'healthy'
        }
        
        # Check error rate
        error_rate = key_data.get('error_rate', 0)
        if error_rate > 0.11:
            analysis['health_score'] -= 50
            analysis['warnings'].append('Critical: Error rate exceeds security threshold!')
            analysis['status'] = 'critical'
            analysis['recommendations'].append('Immediately generate new key - possible eavesdropping')
        elif error_rate > 0.05:
            analysis['health_score'] -= 20
            analysis['warnings'].append('Warning: Elevated error rate detected')
            analysis['recommendations'].append('Consider regenerating key soon')
        
        # Check age
        created_at = key_data.get('created_at')
        if created_at:
            try:
                created_time = datetime.fromisoformat(created_at)
                age_minutes = (datetime.now() - created_time).total_seconds() / 60
                
                if age_minutes > 60:
                    analysis['health_score'] -= 30
                    analysis['warnings'].append('Key is older than 1 hour')
                    analysis['recommendations'].append('Rotate key to maintain forward secrecy')
                elif age_minutes > 30:
                    analysis['health_score'] -= 10
                    analysis['recommendations'].append('Schedule key rotation within 30 minutes')
            except:
                pass
        
        # Check usage count
        usage_count = key_data.get('usage_count', 0)
        if usage_count > 100:
            analysis['health_score'] -= 15
            analysis['recommendations'].append('High usage count - consider rotation')
        
        # Determine final status
        if analysis['health_score'] >= 80:
            analysis['status'] = 'healthy'
        elif analysis['health_score'] >= 50:
            analysis['status'] = 'warning'
        else:
            analysis['status'] = 'critical'
        
        return analysis
    
    def get_rotation_recommendation(self, channel_data: Dict, key_data: Dict) -> Dict[str, Any]:
        """Get AI-powered recommendation for key rotation"""
        prompt = f"""Analyze this quantum key distribution scenario and provide rotation recommendations:

Channel Info:
- Type: {channel_data.get('channel_type', 'group')}
- Members: {channel_data.get('member_count', 1)}
- Activity Level: {channel_data.get('activity_level', 'moderate')}
- Security Level: {channel_data.get('security_level', 'standard')}

Current Key Status:
- Age: {key_data.get('age_minutes', 0)} minutes
- Error Rate: {key_data.get('error_rate', 0)*100:.2f}%
- Usage Count: {key_data.get('usage_count', 0)}
- Last Refresh: {key_data.get('last_refresh', 'never')}

Provide:
1. Should the key be rotated now? (Yes/No)
2. Recommended rotation interval
3. Security risk assessment (Low/Medium/High)
4. Specific actions to take"""

        ai_response = self._get_ai_response(prompt)
        
        # Parse and structure the response
        recommendation = {
            'timestamp': datetime.now().isoformat(),
            'channel_id': channel_data.get('channel_id'),
            'key_id': key_data.get('key_id'),
            'ai_analysis': ai_response,
            'should_rotate': self._should_rotate(key_data),
            'recommended_interval': self._calculate_optimal_interval(channel_data, key_data),
            'risk_level': self._assess_risk_level(key_data)
        }
        
        return recommendation
    
    def _should_rotate(self, key_data: Dict) -> bool:
        """Determine if key should be rotated based on rules"""
        error_rate = key_data.get('error_rate', 0)
        age_minutes = key_data.get('age_minutes', 0)
        usage_count = key_data.get('usage_count', 0)
        
        if error_rate > 0.05:
            return True
        if age_minutes > 45:
            return True
        if usage_count > 80:
            return True
        return False
    
    def _calculate_optimal_interval(self, channel_data: Dict, key_data: Dict) -> int:
        """Calculate optimal refresh interval in seconds"""
        base_interval = 300  # 5 minutes
        
        # Adjust based on channel type
        channel_type = channel_data.get('channel_type', 'group')
        if channel_type == 'private':
            base_interval = 600  # 10 minutes for private chats
        
        # Adjust based on security level
        security_level = channel_data.get('security_level', 'standard')
        if security_level == 'high':
            base_interval = base_interval // 2
        elif security_level == 'low':
            base_interval = base_interval * 2
        
        # Adjust based on error rate
        error_rate = key_data.get('error_rate', 0)
        if error_rate > 0.03:
            base_interval = base_interval // 2
        
        return max(120, min(1800, base_interval))  # Between 2-30 minutes
    
    def _assess_risk_level(self, key_data: Dict) -> str:
        """Assess the current security risk level"""
        error_rate = key_data.get('error_rate', 0)
        age_minutes = key_data.get('age_minutes', 0)
        
        if error_rate > 0.08 or age_minutes > 60:
            return 'high'
        elif error_rate > 0.04 or age_minutes > 30:
            return 'medium'
        return 'low'
    
    def get_security_advice(self, query: str, context: Dict = None) -> str:
        if context is None:
            context = {}
        """Get general security advice from AI"""
        context_str = ""
        if context:
            context_str = f"\nContext: {json.dumps(context, indent=2)}"
        
        prompt = f"""As a quantum cryptography security expert, answer this question:

{query}
{context_str}

Provide practical, actionable advice focused on:
1. Immediate actions if any
2. Best practices
3. Potential risks to consider"""

        return self._get_ai_response(prompt)
    
    def log_decision(self, decision_type: str, decision_data: Dict, outcome: str) -> Dict:
        """Log an AI-assisted decision for audit"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'decision_type': decision_type,
            'input_data': decision_data,
            'outcome': outcome,
            'ai_assisted': self.client is not None
        }
        return log_entry


class KeyRotationScheduler:
    """Manages automatic key rotation schedules"""
    
    def __init__(self, ai_assistant: AIKeyManagementAssistant = None):
        if ai_assistant is None:
            raise ValueError("AI Assistant is required for AIWebIntegration")
        self.ai_assistant = ai_assistant
        self.schedules = {}
        
    def create_schedule(self, key_id: str, interval_seconds: int = 300) -> Dict:
        """Create a key rotation schedule"""
        now = datetime.now()
        schedule = {
            'key_id': key_id,
            'interval': interval_seconds,
            'created_at': now.isoformat(),
            'last_rotation': now.isoformat(),
            'next_rotation': (now + timedelta(seconds=interval_seconds)).isoformat(),
            'rotation_count': 0,
            'is_active': True
        }
        self.schedules[key_id] = schedule
        return schedule
    
    def check_due_rotations(self) -> List[str]:
        """Get list of key IDs that need rotation"""
        now = datetime.now()
        due_keys = []
        
        for key_id, schedule in self.schedules.items():
            if not schedule.get('is_active'):
                continue
            
            next_rotation = datetime.fromisoformat(schedule['next_rotation'])
            if now >= next_rotation:
                due_keys.append(key_id)
        
        return due_keys
    
    def record_rotation(self, key_id: str) -> Dict:
        """Record that a key rotation has occurred"""
        if key_id not in self.schedules:
            return None
        
        now = datetime.now()
        schedule = self.schedules[key_id]
        schedule['last_rotation'] = now.isoformat()
        schedule['next_rotation'] = (now + timedelta(seconds=schedule['interval'])).isoformat()
        schedule['rotation_count'] += 1
        
        return schedule
    
    def update_interval(self, key_id: str, new_interval: int) -> Dict:
        """Update the rotation interval for a key"""
        if key_id not in self.schedules:
            return None
        
        self.schedules[key_id]['interval'] = new_interval
        # Recalculate next rotation based on last rotation
        last = datetime.fromisoformat(self.schedules[key_id]['last_rotation'])
        self.schedules[key_id]['next_rotation'] = (last + timedelta(seconds=new_interval)).isoformat()
        
        return self.schedules[key_id]


if __name__ == '__main__':
    # Test the AI assistant
    assistant = AIKeyManagementAssistant()
    
    # Test key health analysis
    test_key = {
        'key_id': 'test-123',
        'error_rate': 0.03,
        'created_at': (datetime.now() - timedelta(minutes=25)).isoformat(),
        'usage_count': 45
    }
    
    print("Testing AI Key Management Assistant...")
    print("\n=== Key Health Analysis ===")
    health = assistant.analyze_key_health(test_key)
    print(f"Health Score: {health['health_score']}")
    print(f"Status: {health['status']}")
    print(f"Recommendations: {health['recommendations']}")
    
    print("\n=== Rotation Recommendation ===")
    test_channel = {
        'channel_type': 'group',
        'member_count': 5,
        'activity_level': 'high',
        'security_level': 'standard'
    }
    
    test_key['age_minutes'] = 25
    recommendation = assistant.get_rotation_recommendation(test_channel, test_key)
    print(f"Should Rotate: {recommendation['should_rotate']}")
    print(f"Recommended Interval: {recommendation['recommended_interval']} seconds")
    print(f"Risk Level: {recommendation['risk_level']}")
    
    print("\n=== Security Advice ===")
    advice = assistant.get_security_advice("What are the best practices for QKD key management in IoT?")
    print(advice)
