"""
Domain Analyzer Module
Provides comprehensive domain analysis for phishing detection
"""

import dns.resolver
import ipaddress
import logging
import re
import socket
import whois
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class DomainAnalyzer:
    """Comprehensive domain analysis for phishing detection"""

    def __init__(self):
        self.known_brands = [
            'paypal', 'microsoft', 'google', 'amazon', 'apple', 'facebook',
            'netflix', 'dropbox', 'adobe', 'zoom', 'linkedin', 'twitter',
            'instagram', 'whatsapp', 'spotify', 'github', 'stackoverflow'
        ]

        self.suspicious_patterns = [
            r'[0-9]+', r'[il1]', r'[o0]', r'-+', r'\.+',
            r'secure?', r'verify?', r'account', r'login', r'signin',
            r'update', r'suspend', r'confirm', r'support'
        ]

    def analyze_domain(self, domain: str) -> Dict:
        """
        Perform comprehensive analysis of a domain

        Args:
            domain: Domain name to analyze

        Returns:
            Dictionary containing analysis results
        """
        analysis = {
            'domain': domain,
            'analysis_timestamp': datetime.now().isoformat(),
            'is_suspicious': False,
            'similarity_target': '',
            'risk_factors': [],
            'technical_data': {}
        }

        try:
            # Basic domain validation
            if not self._is_valid_domain(domain):
                analysis['risk_factors'].append('Invalid domain format')
                return analysis

            # Similarity analysis
            similarity_data = self._analyze_similarity(domain)
            analysis.update(similarity_data)

            # Technical analysis
            technical_data = self._analyze_technical(domain)
            analysis['technical_data'] = technical_data

            # Pattern analysis
            pattern_risks = self._analyze_patterns(domain)
            analysis['risk_factors'].extend(pattern_risks)

            # Age and registration analysis
            registration_data = self._analyze_registration(domain)
            analysis['technical_data'].update(registration_data)

            # DNS analysis
            dns_data = self._analyze_dns(domain)
            analysis['technical_data'].update(dns_data)

        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {e}")
            analysis['error'] = str(e)

        return analysis

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name format"""
        if not domain or len(domain) > 253:
            return False

        # Basic domain regex
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )

        return bool(domain_pattern.match(domain))

    def _analyze_similarity(self, domain: str) -> Dict:
        """Analyze similarity to known brands"""
        similarity_data = {
            'similarity_target': '',
            'similarity_score': 0,
            'levenshtein_distance': 999
        }

        domain_lower = domain.lower()

        for brand in self.known_brands:
            # Check if brand appears in domain
            if brand in domain_lower:
                # Calculate various similarity metrics
                distance = self._levenshtein_distance(brand, domain_lower)

                # Check for common typosquatting patterns
                if self._is_typosquatting(brand, domain_lower):
                    similarity_data.update({
                        'similarity_target': brand,
                        'similarity_score': 90,
                        'levenshtein_distance': distance,
                        'typosquatting_detected': True
                    })
                    break

                # Check for substring match with additions
                if distance < similarity_data['levenshtein_distance']:
                    similarity_data.update({
                        'similarity_target': brand,
                        'similarity_score': max(0, 100 - distance * 10),
                        'levenshtein_distance': distance
                    })

        return similarity_data

    def _is_typosquatting(self, brand: str, domain: str) -> bool:
        """Detect common typosquatting patterns"""
        # Character substitution patterns
        substitutions = {
            'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '@',
            'g': '9', 's': '5', 't': '7'
        }

        # Check for character substitutions
        for original, substitute in substitutions.items():
            if brand.replace(original, substitute) in domain:
                return True

        # Check for character omissions
        for i in range(len(brand)):
            omitted = brand[:i] + brand[i+1:]
            if omitted in domain and len(omitted) > 2:
                return True

        # Check for character additions
        common_additions = ['-', '1', '2', 'x', 'z']
        for addition in common_additions:
            if brand + addition in domain or addition + brand in domain:
                return True

        return False

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _analyze_patterns(self, domain: str) -> List[str]:
        """Analyze domain for suspicious patterns"""
        risk_factors = []

        # Check for suspicious keywords
        suspicious_words = [
            'secure', 'verify', 'account', 'login', 'signin', 'update',
            'suspend', 'confirm', 'support', 'billing', 'payment'
        ]

        domain_lower = domain.lower()
        for word in suspicious_words:
            if word in domain_lower:
                risk_factors.append(f'Contains suspicious keyword: {word}')

        # Check for excessive hyphens or numbers
        if domain.count('-') > 2:
            risk_factors.append('Excessive hyphens in domain')

        if len(re.findall(r'\d', domain)) > 3:
            risk_factors.append('Excessive numbers in domain')

        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.cf', '.ga', '.buzz', '.click', '.download']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                risk_factors.append(f'Suspicious TLD: {tld}')

        # Check domain length
        if len(domain) > 50:
            risk_factors.append('Unusually long domain name')

        return risk_factors

    def _analyze_technical(self, domain: str) -> Dict:
        """Perform technical analysis of domain"""
        technical_data = {}

        try:
            # Resolve IP address
            ip_address = socket.gethostbyname(domain)
            technical_data['ip_address'] = ip_address

            # Check if IP is in suspicious ranges
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private:
                    technical_data['ip_risk'] = 'Private IP address'
                elif ip_obj.is_loopback:
                    technical_data['ip_risk'] = 'Loopback IP address'
            except:
                pass

        except socket.gaierror:
            technical_data['dns_resolution'] = 'Failed to resolve'
        except Exception as e:
            technical_data['technical_error'] = str(e)

        return technical_data

    def _analyze_registration(self, domain: str) -> Dict:
        """Analyze domain registration information"""
        registration_data = {}

        try:
            w = whois.whois(domain)

            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                registration_data['creation_date'] = creation_date.isoformat() if creation_date else None

                # Check if domain is recently registered (last 30 days)
                if creation_date:
                    days_old = (datetime.now() - creation_date).days
                    registration_data['days_old'] = days_old

                    if days_old < 30:
                        registration_data['recently_registered'] = True

            if w.registrar:
                registration_data['registrar'] = w.registrar

            if w.country:
                registration_data['country'] = w.country

        except Exception as e:
            registration_data['whois_error'] = str(e)

        return registration_data

    def _analyze_dns(self, domain: str) -> Dict:
        """Analyze DNS records"""
        dns_data = {}

        try:
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_data['mx_records'] = [str(mx) for mx in mx_records]
            except:
                dns_data['mx_records'] = []

            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                dns_data['txt_records'] = [str(txt) for txt in txt_records]
            except:
                dns_data['txt_records'] = []

            # NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_data['ns_records'] = [str(ns) for ns in ns_records]
            except:
                dns_data['ns_records'] = []

        except Exception as e:
            dns_data['dns_analysis_error'] = str(e)

        return dns_data
