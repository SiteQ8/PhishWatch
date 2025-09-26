"""
Threat Classifier Module
Provides risk scoring and classification for detected domains
"""

import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)

class ThreatClassifier:
    """Machine learning-inspired threat classification for phishing domains"""

    def __init__(self):
        # Weights for different risk factors
        self.weights = {
            'similarity_score': 0.25,
            'recently_registered': 0.20,
            'suspicious_patterns': 0.15,
            'dns_issues': 0.10,
            'certificate_issues': 0.10,
            'geographical_risk': 0.10,
            'tld_reputation': 0.10
        }

        # High-risk TLDs
        self.high_risk_tlds = [
            '.tk', '.ml', '.cf', '.ga', '.buzz', '.click', '.download',
            '.loan', '.cricket', '.science', '.work', '.party'
        ]

        # High-risk countries for phishing
        self.high_risk_countries = ['RU', 'CN', 'KP', 'IR']

        # Suspicious certificate issuers (free/automated CAs often used by attackers)
        self.suspicious_cas = [
            "Let's Encrypt",  # Not inherently bad, but often used by attackers
            'ZeroSSL',
            'cPanel, Inc.',
            'Sectigo'  # When used with suspicious domains
        ]

    def calculate_risk_score(self, domain: str, analysis: Dict) -> int:
        """
        Calculate comprehensive risk score for a domain

        Args:
            domain: Domain name
            analysis: Domain analysis results

        Returns:
            Risk score from 0-100
        """
        risk_score = 0
        risk_components = {}

        try:
            # Similarity-based scoring
            similarity_risk = self._calculate_similarity_risk(analysis)
            risk_components['similarity'] = similarity_risk
            risk_score += similarity_risk * self.weights['similarity_score']

            # Registration age scoring
            registration_risk = self._calculate_registration_risk(analysis)
            risk_components['registration'] = registration_risk
            risk_score += registration_risk * self.weights['recently_registered']

            # Pattern-based scoring
            pattern_risk = self._calculate_pattern_risk(domain, analysis)
            risk_components['patterns'] = pattern_risk
            risk_score += pattern_risk * self.weights['suspicious_patterns']

            # DNS-based scoring
            dns_risk = self._calculate_dns_risk(analysis)
            risk_components['dns'] = dns_risk
            risk_score += dns_risk * self.weights['dns_issues']

            # Geographical scoring
            geo_risk = self._calculate_geographical_risk(analysis)
            risk_components['geographical'] = geo_risk
            risk_score += geo_risk * self.weights['geographical_risk']

            # TLD reputation scoring
            tld_risk = self._calculate_tld_risk(domain)
            risk_components['tld'] = tld_risk
            risk_score += tld_risk * self.weights['tld_reputation']

            # Normalize to 0-100 scale
            final_score = min(100, max(0, int(risk_score)))

            logger.debug(f"Risk calculation for {domain}: {risk_components} = {final_score}")

            return final_score

        except Exception as e:
            logger.error(f"Error calculating risk score for {domain}: {e}")
            return 50  # Default medium risk

    def _calculate_similarity_risk(self, analysis: Dict) -> float:
        """Calculate risk based on similarity to known brands"""
        similarity_score = analysis.get('similarity_score', 0)

        # If high similarity to known brand, high risk
        if similarity_score > 80:
            return 90.0
        elif similarity_score > 60:
            return 70.0
        elif similarity_score > 40:
            return 50.0
        elif similarity_score > 20:
            return 30.0
        else:
            return 10.0

    def _calculate_registration_risk(self, analysis: Dict) -> float:
        """Calculate risk based on domain registration age"""
        technical_data = analysis.get('technical_data', {})
        days_old = technical_data.get('days_old')

        if days_old is None:
            return 30.0  # Unknown age, medium risk

        # Very recently registered domains are high risk
        if days_old < 1:
            return 95.0
        elif days_old < 7:
            return 80.0
        elif days_old < 30:
            return 60.0
        elif days_old < 90:
            return 40.0
        elif days_old < 365:
            return 20.0
        else:
            return 10.0

    def _calculate_pattern_risk(self, domain: str, analysis: Dict) -> float:
        """Calculate risk based on suspicious patterns"""
        risk_factors = analysis.get('risk_factors', [])
        base_risk = 0.0

        # Count different types of risk factors
        keyword_risks = [f for f in risk_factors if 'keyword' in f.lower()]
        structure_risks = [f for f in risk_factors if any(x in f.lower() for x in ['hyphen', 'number', 'length'])]
        tld_risks = [f for f in risk_factors if 'tld' in f.lower()]

        # Weight different risk types
        base_risk += len(keyword_risks) * 25
        base_risk += len(structure_risks) * 15
        base_risk += len(tld_risks) * 20

        # Check for typosquatting indicators
        if analysis.get('typosquatting_detected', False):
            base_risk += 40

        # Check for homograph attacks (Unicode lookalikes)
        if self._has_homograph_characters(domain):
            base_risk += 30

        return min(100.0, base_risk)

    def _calculate_dns_risk(self, analysis: Dict) -> float:
        """Calculate risk based on DNS configuration"""
        technical_data = analysis.get('technical_data', {})
        risk = 0.0

        # Failed DNS resolution
        if 'Failed to resolve' in technical_data.get('dns_resolution', ''):
            risk += 20.0

        # Private or suspicious IP ranges
        if technical_data.get('ip_risk'):
            risk += 30.0

        # Missing or suspicious MX records
        mx_records = technical_data.get('mx_records', [])
        if not mx_records:
            risk += 15.0

        # Suspicious nameservers
        ns_records = technical_data.get('ns_records', [])
        suspicious_ns_patterns = ['free', 'temp', 'hosting', 'parking']
        for ns in ns_records:
            if any(pattern in ns.lower() for pattern in suspicious_ns_patterns):
                risk += 10.0

        return min(100.0, risk)

    def _calculate_geographical_risk(self, analysis: Dict) -> float:
        """Calculate risk based on geographical factors"""
        technical_data = analysis.get('technical_data', {})
        country = technical_data.get('country', '').upper()

        if country in self.high_risk_countries:
            return 80.0
        elif country in ['PK', 'BD', 'NG', 'ID']:  # Moderate risk countries
            return 50.0
        elif country in ['US', 'CA', 'GB', 'DE', 'FR', 'AU']:  # Lower risk
            return 20.0
        else:
            return 30.0  # Unknown or medium risk

    def _calculate_tld_risk(self, domain: str) -> float:
        """Calculate risk based on TLD reputation"""
        domain_lower = domain.lower()

        # Check for high-risk TLDs
        for tld in self.high_risk_tlds:
            if domain_lower.endswith(tld):
                return 80.0

        # Check for suspicious new gTLDs
        suspicious_new_tlds = ['.email', '.live', '.online', '.site', '.website']
        for tld in suspicious_new_tlds:
            if domain_lower.endswith(tld):
                return 60.0

        # Traditional TLDs are generally lower risk
        traditional_tlds = ['.com', '.net', '.org', '.edu', '.gov']
        for tld in traditional_tlds:
            if domain_lower.endswith(tld):
                return 20.0

        return 40.0  # Default for other TLDs

    def _has_homograph_characters(self, domain: str) -> bool:
        """Check for homograph attack characters (Unicode lookalikes)"""
        # Common homograph characters that look like ASCII
        homograph_chars = {
            'а': 'a',  # Cyrillic 'a'
            'е': 'e',  # Cyrillic 'e'
            'о': 'o',  # Cyrillic 'o'
            'р': 'p',  # Cyrillic 'p'
            'у': 'y',  # Cyrillic 'y'
            'х': 'x',  # Cyrillic 'x'
            'с': 'c',  # Cyrillic 'c'
            'ο': 'o',  # Greek omicron
            'ρ': 'p',  # Greek rho
            'α': 'a',  # Greek alpha
        }

        for char in domain:
            if char in homograph_chars:
                return True

        return False

    def classify_threat_level(self, risk_score: int) -> str:
        """
        Classify threat level based on risk score

        Args:
            risk_score: Risk score from 0-100

        Returns:
            Threat level string
        """
        if risk_score >= 90:
            return 'CRITICAL'
        elif risk_score >= 70:
            return 'HIGH'
        elif risk_score >= 50:
            return 'MEDIUM'
        elif risk_score >= 30:
            return 'LOW'
        else:
            return 'MINIMAL'

    def get_threat_color(self, risk_score: int) -> str:
        """Get color code for threat level visualization"""
        threat_level = self.classify_threat_level(risk_score)

        color_map = {
            'CRITICAL': '#dc2626',  # Red
            'HIGH': '#ea580c',      # Orange
            'MEDIUM': '#ca8a04',    # Yellow
            'LOW': '#16a34a',       # Green
            'MINIMAL': '#059669'    # Teal
        }

        return color_map.get(threat_level, '#6b7280')  # Gray for unknown

    def generate_threat_report(self, domain: str, analysis: Dict, risk_score: int) -> Dict:
        """Generate comprehensive threat assessment report"""
        threat_level = self.classify_threat_level(risk_score)

        report = {
            'domain': domain,
            'risk_score': risk_score,
            'threat_level': threat_level,
            'color': self.get_threat_color(risk_score),
            'assessment_timestamp': datetime.now().isoformat(),
            'recommendations': self._generate_recommendations(risk_score, analysis),
            'summary': self._generate_summary(domain, risk_score, analysis)
        }

        return report

    def _generate_recommendations(self, risk_score: int, analysis: Dict) -> List[str]:
        """Generate security recommendations based on assessment"""
        recommendations = []

        if risk_score >= 90:
            recommendations.extend([
                'IMMEDIATE ACTION REQUIRED: Block domain immediately',
                'Add domain to security blacklists',
                'Monitor for similar domains',
                'Alert security team and users'
            ])
        elif risk_score >= 70:
            recommendations.extend([
                'Block domain in security systems',
                'Add to monitoring watchlist',
                'Consider user notification'
            ])
        elif risk_score >= 50:
            recommendations.extend([
                'Add to monitoring watchlist',
                'Investigate further if accessed by users',
                'Consider blocking based on organization policy'
            ])
        else:
            recommendations.append('Continue monitoring')

        # Specific recommendations based on analysis
        if analysis.get('typosquatting_detected'):
            recommendations.append('Investigate for brand impersonation')

        if analysis.get('technical_data', {}).get('recently_registered'):
            recommendations.append('Monitor for rapid infrastructure changes')

        return recommendations

    def _generate_summary(self, domain: str, risk_score: int, analysis: Dict) -> str:
        """Generate human-readable threat summary"""
        threat_level = self.classify_threat_level(risk_score)
        similarity_target = analysis.get('similarity_target', 'unknown brand')

        if risk_score >= 90:
            return f"CRITICAL THREAT: {domain} appears to be impersonating {similarity_target} with high confidence. Immediate blocking recommended."
        elif risk_score >= 70:
            return f"HIGH RISK: {domain} shows strong indicators of phishing targeting {similarity_target}. Blocking recommended."
        elif risk_score >= 50:
            return f"MEDIUM RISK: {domain} has suspicious characteristics that warrant monitoring and potential blocking."
        else:
            return f"LOW RISK: {domain} has some suspicious characteristics but may be legitimate. Continue monitoring."
