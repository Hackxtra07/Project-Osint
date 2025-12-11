#!/home/hackxtra/myenv/bin/python3
"""
OSINT Analytics Suite - Tkinter Version
Compatible with Python 3.12+
All Features Functional
"""

import sys
import os
import json
import sqlite3
import socket
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import hashlib
import re
import threading
import time
import subprocess
from urllib.parse import urlparse, quote_plus
import csv
from io import BytesIO, StringIO
import base64
import logging
import configparser

# Collections import compatibility fix for Python 3.12+
import collections
import collections.abc
# Add the missing imports that requests needs
collections.Mapping = collections.abc.Mapping
collections.MutableMapping = collections.abc.MutableMapping
collections.Iterable = collections.abc.Iterable
collections.Sequence = collections.abc.Sequence
collections.Callable = collections.abc.Callable

# Now import requests after the fix
import requests

# Tkinter imports
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import filedialog, messagebox, scrolledtext
import tkinter.font as tkFont
from tkinter import simpledialog

# Additional imports (install with pip)
try:
    # Try to import whois packages (optional - will fall back gracefully)
    try:
        from whois import whois
    except ImportError:
        try:
            from pythonwhois import get_whois
            # Create wrapper for compatibility
            class whois:
                @staticmethod
                def whois(domain):
                    return get_whois(domain)
        except ImportError:
            # No whois module available - will use fallback
            whois = None
    
    import dns.resolver
    import dns.reversename
    from bs4 import BeautifulSoup
    from PIL import Image, ImageTk, ImageOps
    from textblob import TextBlob
    import folium
    import pandas as pd
    import numpy as np
    import matplotlib
    matplotlib.use('TkAgg')  # Set backend before importing pyplot
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import networkx as nx
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install required packages with: pip install dnspython beautifulsoup4 pillow textblob folium pandas numpy matplotlib scikit-learn networkx")
    sys.exit(1)

import html
import webbrowser
import mimetypes
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('osint_suite.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE MANAGER (COMPLETE)
# ============================================================================

class OSINTDatabase:
    def __init__(self, db_path="data/osint_data.db"):
        self.db_path = db_path
        self.init_database()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
    
    def init_database(self):
        """Initialize all database tables"""
        os.makedirs("data", exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Core tables
        tables = [
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                tags TEXT,
                notes TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT,
                confidence INTEGER DEFAULT 50,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS ip_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                ip TEXT UNIQUE NOT NULL,
                country TEXT,
                city TEXT,
                region TEXT,
                isp TEXT,
                org TEXT,
                asn TEXT,
                latitude REAL,
                longitude REAL,
                timezone TEXT,
                threat_score INTEGER DEFAULT 0,
                abuse_reports INTEGER DEFAULT 0,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                domain TEXT UNIQUE NOT NULL,
                registrar TEXT,
                created_date TEXT,
                expires_date TEXT,
                nameservers TEXT,
                status TEXT,
                emails TEXT,
                dns_a TEXT,
                dns_mx TEXT,
                dns_ns TEXT,
                dns_txt TEXT,
                ssl_issuer TEXT,
                ssl_expiry TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS social_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                platform TEXT NOT NULL,
                username TEXT NOT NULL,
                url TEXT,
                name TEXT,
                bio TEXT,
                location TEXT,
                followers INTEGER DEFAULT 0,
                following INTEGER DEFAULT 0,
                posts INTEGER DEFAULT 0,
                verified BOOLEAN DEFAULT FALSE,
                last_post TEXT,
                profile_image TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                email TEXT UNIQUE NOT NULL,
                verified BOOLEAN DEFAULT FALSE,
                breaches INTEGER DEFAULT 0,
                breach_details TEXT,
                social_profiles TEXT,
                disposable BOOLEAN DEFAULT FALSE,
                gravatar_hash TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS usernames (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                username TEXT NOT NULL,
                platform TEXT,
                url TEXT,
                found_at TEXT,
                metadata TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS phone_numbers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                phone TEXT NOT NULL,
                country TEXT,
                carrier TEXT,
                line_type TEXT,
                valid BOOLEAN,
                metadata TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                filename TEXT,
                filetype TEXT,
                size INTEGER,
                md5_hash TEXT,
                sha256_hash TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                path TEXT,
                metadata TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
                source_type TEXT,
                target_id INTEGER,
                target_type TEXT,
                relationship TEXT,
                strength INTEGER DEFAULT 1,
                evidence TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (source_id) REFERENCES targets (id),
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                scan_type TEXT,
                results TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER,
                content TEXT,
                author TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS exports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER,
                export_type TEXT,
                filename TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id)
            )
            """
        ]
        
        for table_sql in tables:
            try:
                cursor.execute(table_sql)
            except Exception as e:
                logger.error(f"Error creating table: {e}")
        
        # Create indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_targets_investigation ON targets(investigation_id)",
            "CREATE INDEX IF NOT EXISTS idx_ip_target ON ip_addresses(target_id)",
            "CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_addresses(ip)",
            "CREATE INDEX IF NOT EXISTS idx_domain_name ON domains(domain)",
            "CREATE INDEX IF NOT EXISTS idx_email_address ON emails(email)",
            "CREATE INDEX IF NOT EXISTS idx_social_platform ON social_profiles(platform, username)",
            "CREATE INDEX IF NOT EXISTS idx_scan_target ON scans(target_id)",
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
            except Exception as e:
                logger.debug(f"Index creation warning: {e}")
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    # ========== CRUD Operations ==========
    
    def add_investigation(self, name, description="", tags=""):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO investigations (name, description, tags) VALUES (?, ?, ?)",
            (name, description, tags)
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def add_target(self, investigation_id, target_type, value, source="", confidence=50):
        cursor = self.conn.cursor()
        cursor.execute(
            """INSERT INTO targets (investigation_id, type, value, source, confidence) 
               VALUES (?, ?, ?, ?, ?)""",
            (investigation_id, target_type, value, source, confidence)
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def update_ip_data(self, target_id, ip_data):
        cursor = self.conn.cursor()
        
        # Check if IP exists
        cursor.execute("SELECT id FROM ip_addresses WHERE ip = ?", (ip_data['ip'],))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute("""
                UPDATE ip_addresses SET
                country=?, city=?, region=?, isp=?, org=?, asn=?,
                latitude=?, longitude=?, timezone=?, threat_score=?,
                abuse_reports=?, last_checked=CURRENT_TIMESTAMP
                WHERE ip=?
            """, (
                ip_data.get('country'), ip_data.get('city'), ip_data.get('region'),
                ip_data.get('isp'), ip_data.get('org'), ip_data.get('asn'),
                ip_data.get('latitude'), ip_data.get('longitude'), ip_data.get('timezone'),
                ip_data.get('threat_score', 0), ip_data.get('abuse_reports', 0),
                ip_data['ip']
            ))
        else:
            cursor.execute("""
                INSERT INTO ip_addresses 
                (target_id, ip, country, city, region, isp, org, asn, 
                 latitude, longitude, timezone, threat_score, abuse_reports)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target_id, ip_data['ip'], ip_data.get('country'), ip_data.get('city'),
                ip_data.get('region'), ip_data.get('isp'), ip_data.get('org'),
                ip_data.get('asn'), ip_data.get('latitude'), ip_data.get('longitude'),
                ip_data.get('timezone'), ip_data.get('threat_score', 0),
                ip_data.get('abuse_reports', 0)
            ))
        
        self.conn.commit()
    
    def update_domain_data(self, target_id, domain_data):
        cursor = self.conn.cursor()
        
        cursor.execute("SELECT id FROM domains WHERE domain = ?", (domain_data['domain'],))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute("""
                UPDATE domains SET
                registrar=?, created_date=?, expires_date=?,
                nameservers=?, status=?, emails=?,
                dns_a=?, dns_mx=?, dns_ns=?, dns_txt=?,
                ssl_issuer=?, ssl_expiry=?
                WHERE domain=?
            """, (
                domain_data.get('registrar'), domain_data.get('created_date'),
                domain_data.get('expires_date'), domain_data.get('nameservers'),
                domain_data.get('status'), domain_data.get('emails'),
                domain_data.get('dns_a'), domain_data.get('dns_mx'),
                domain_data.get('dns_ns'), domain_data.get('dns_txt'),
                domain_data.get('ssl_issuer'), domain_data.get('ssl_expiry'),
                domain_data['domain']
            ))
        else:
            cursor.execute("""
                INSERT INTO domains 
                (target_id, domain, registrar, created_date, expires_date,
                 nameservers, status, emails, dns_a, dns_mx, dns_ns, dns_txt,
                 ssl_issuer, ssl_expiry)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target_id, domain_data['domain'], domain_data.get('registrar'),
                domain_data.get('created_date'), domain_data.get('expires_date'),
                domain_data.get('nameservers'), domain_data.get('status'),
                domain_data.get('emails'), domain_data.get('dns_a'),
                domain_data.get('dns_mx'), domain_data.get('dns_ns'),
                domain_data.get('dns_txt'), domain_data.get('ssl_issuer'),
                domain_data.get('ssl_expiry')
            ))
        
        self.conn.commit()
    
    def add_social_profile(self, target_id, platform, username, **kwargs):
        cursor = self.conn.cursor()
        
        cursor.execute(
            """INSERT INTO social_profiles 
               (target_id, platform, username, url, name, bio, location, 
                followers, following, posts, verified, last_post, profile_image)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target_id, platform, username,
                kwargs.get('url'), kwargs.get('name'), kwargs.get('bio'),
                kwargs.get('location'), kwargs.get('followers', 0),
                kwargs.get('following', 0), kwargs.get('posts', 0),
                kwargs.get('verified', False), kwargs.get('last_post'),
                kwargs.get('profile_image')
            )
        )
        self.conn.commit()
    
    def add_email(self, target_id, email, **kwargs):
        cursor = self.conn.cursor()
        
        cursor.execute(
            """INSERT INTO emails 
               (target_id, email, verified, breaches, breach_details, 
                social_profiles, disposable, gravatar_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target_id, email, kwargs.get('verified', False),
                kwargs.get('breaches', 0), kwargs.get('breach_details'),
                kwargs.get('social_profiles'), kwargs.get('disposable', False),
                kwargs.get('gravatar_hash')
            )
        )
        self.conn.commit()
    
    # ========== Query Methods ==========
    
    def get_investigations(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM investigations ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]
    
    def get_targets(self, investigation_id=None):
        cursor = self.conn.cursor()
        if investigation_id:
            cursor.execute(
                "SELECT * FROM targets WHERE investigation_id = ? ORDER BY last_seen DESC",
                (investigation_id,)
            )
        else:
            cursor.execute("SELECT * FROM targets ORDER BY last_seen DESC")
        return [dict(row) for row in cursor.fetchall()]
    
    def get_ip_data(self, ip):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM ip_addresses WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_domain_data(self, domain):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM domains WHERE domain = ?", (domain,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def search_targets(self, query):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM targets 
            WHERE value LIKE ? OR type LIKE ?
            ORDER BY last_seen DESC
        """, (f"%{query}%", f"%{query}%"))
        return [dict(row) for row in cursor.fetchall()]
    
    def get_relationships(self, target_id):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM relationships 
            WHERE source_id = ? OR target_id = ?
            ORDER BY strength DESC
        """, (target_id, target_id))
        return [dict(row) for row in cursor.fetchall()]
    
    def add_relationship(self, source_id, source_type, target_id, target_type, relationship, strength=1):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO relationships 
            (source_id, source_type, target_id, target_type, relationship, strength)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (source_id, source_type, target_id, target_type, relationship, strength))
        self.conn.commit()
    
    def close(self):
        self.conn.close()

# ============================================================================
# CORE OSINT MODULES (ALL WORKING)
# ============================================================================

class IPAnalyzer:
    """Complete IP analysis module"""
    
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze(self, ip_address):
        """Complete IP analysis"""
        try:
            results = {
                'ip': ip_address,
                'basic_info': self.get_basic_info(ip_address),
                'geolocation': self.get_geolocation(ip_address),
                'threat_intel': self.get_threat_intelligence(ip_address),
                'ports': self.scan_ports(ip_address),
                'reverse_dns': self.get_reverse_dns(ip_address),
                'associated_domains': self.find_associated_domains(ip_address),
                'timestamp': datetime.now().isoformat()
            }
            
            # Try to get WHOIS if ipwhois is available
            try:
                results['whois'] = self.get_ip_whois(ip_address)
            except ImportError:
                results['whois'] = {'error': 'ipwhois module not installed'}
            except Exception as e:
                results['whois'] = {'error': str(e)}
                
            return results
        except Exception as e:
            logger.error(f"IP analysis error: {e}")
            return {'ip': ip_address, 'error': str(e)}
    
    def get_basic_info(self, ip):
        """Get basic IP information"""
        try:
            # Validate IP
            ip_obj = ipaddress.ip_address(ip)
            return {
                'valid': True,
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_global': ip_obj.is_global
            }
        except Exception as e:
            return {'valid': False, 'error': f'Invalid IP address: {e}'}
    
    def get_geolocation(self, ip):
        """Get IP geolocation using free APIs"""
        try:
            # Try ip-api.com first (free, no key needed)
            response = self.session.get(f'http://ip-api.com/json/{ip}?fields=66846719', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'countryCode': data.get('countryCode', ''),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'zip': data.get('zip', ''),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0),
                        'timezone': data.get('timezone', ''),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'as': data.get('as', ''),
                        'reverse': data.get('reverse', ''),
                        'mobile': data.get('mobile', False),
                        'proxy': data.get('proxy', False),
                        'hosting': data.get('hosting', False)
                    }
            
            # Fallback to ipinfo.io (requires key in config)
            if 'ipinfo' in self.api_keys and self.api_keys['ipinfo']:
                response = self.session.get(
                    f'https://ipinfo.io/{ip}/json?token={self.api_keys["ipinfo"]}',
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    loc = data.get('loc', '0,0').split(',')
                    return {
                        'country': data.get('country', 'Unknown'),
                        'region': data.get('region', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'loc': data.get('loc', '0,0'),
                        'lat': float(loc[0]) if len(loc) > 0 else 0,
                        'lon': float(loc[1]) if len(loc) > 1 else 0,
                        'org': data.get('org', 'Unknown'),
                        'postal': data.get('postal', ''),
                        'timezone': data.get('timezone', ''),
                        'hostname': data.get('hostname', '')
                    }
            
            return {'error': 'Could not retrieve geolocation'}
            
        except Exception as e:
            logger.error(f"Geolocation error: {e}")
            return {'error': str(e)}
    
    def get_threat_intelligence(self, ip):
        """Check IP against threat intelligence sources"""
        threats = {}
        
        # AbuseIPDB (requires API key)
        if 'abuseipdb' in self.api_keys and self.api_keys['abuseipdb']:
            threats['abuseipdb'] = self.check_abuseipdb(ip)
        
        # VirusTotal (requires API key)
        if 'virustotal' in self.api_keys and self.api_keys['virustotal']:
            threats['virustotal'] = self.check_virustotal(ip)
        
        # Check for known malicious IP patterns
        threats['basic_checks'] = self.basic_threat_checks(ip)
        
        return threats
    
    def check_abuseipdb(self, ip):
        """Check AbuseIPDB for reports"""
        try:
            headers = {
                'Key': self.api_keys['abuseipdb'],
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': True
            }
            response = self.session.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                    'totalReports': data.get('totalReports', 0),
                    'lastReportedAt': data.get('lastReportedAt'),
                    'isPublic': data.get('isPublic', False),
                    'isTor': data.get('isTor', False),
                    'isWhitelisted': data.get('isWhitelisted', False)
                }
        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
        
        return None
    
    def check_virustotal(self, ip):
        """Check VirusTotal for IP reputation"""
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            response = self.session.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()['data']
                attributes = data.get('attributes', {})
                return {
                    'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                    'reputation': attributes.get('reputation', 0),
                    'network': attributes.get('network', {}),
                    'last_analysis_results': attributes.get('last_analysis_results', {})
                }
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
        
        return None
    
    def basic_threat_checks(self, ip):
        """Basic threat checks without API keys"""
        try:
            checks = {
                'is_private': False,
                'is_multicast': False,
                'is_reserved': False,
                'is_loopback': ip == '127.0.0.1',
                'is_bogon': self.is_bogon_ip(ip)
            }
            
            ip_obj = ipaddress.ip_address(ip)
            checks['is_private'] = ip_obj.is_private
            checks['is_multicast'] = ip_obj.is_multicast
            checks['is_reserved'] = ip_obj.is_reserved
            
            # Common malicious IP ranges (simplified)
            malicious_ranges = [
                '185.220.101.',  # Tor exit nodes
                '192.42.116.',   # Tor exit nodes
                '45.134.225.',   # Known spam
                '91.240.118.'    # Known spam
            ]
            
            checks['in_known_ranges'] = any(ip.startswith(r) for r in malicious_ranges)
            
            return checks
        except Exception as e:
            return {'error': str(e)}
    
    def is_bogon_ip(self, ip):
        """Check if IP is in bogon (reserved) range"""
        bogon_prefixes = [
            '0.', '10.', '100.64.', '100.65.', '100.66.', '100.67.', '100.68.',
            '100.69.', '100.70.', '100.71.', '100.72.', '100.73.', '100.74.',
            '100.75.', '100.76.', '100.77.', '100.78.', '100.79.', '100.80.',
            '100.81.', '100.82.', '100.83.', '100.84.', '100.85.', '100.86.',
            '100.87.', '100.88.', '100.89.', '100.90.', '100.91.', '100.92.',
            '100.93.', '100.94.', '100.95.', '100.96.', '100.97.', '100.98.',
            '100.99.', '100.100.', '100.101.', '100.102.', '100.103.', '100.104.',
            '100.105.', '100.106.', '100.107.', '100.108.', '100.109.', '100.110.',
            '100.111.', '100.112.', '100.113.', '100.114.', '100.115.', '100.116.',
            '100.117.', '100.118.', '100.119.', '100.120.', '100.121.', '100.122.',
            '100.123.', '100.124.', '100.125.', '100.126.', '100.127.', '127.',
            '169.254.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
            '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
            '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.0.0.',
            '192.0.2.', '192.168.', '198.18.', '198.19.', '198.51.100.', '203.0.113.',
            '240.', '241.', '242.', '243.', '244.', '245.', '246.', '247.', '248.',
            '249.', '250.', '251.', '252.', '253.', '254.', '255.'
        ]
        return any(ip.startswith(p) for p in bogon_prefixes)
    
    def scan_ports(self, ip, ports='21-23,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,8080'):
        """Scan common ports"""
        open_ports = []
        
        try:
            # Parse port range
            port_list = []
            for part in ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(part))
            
            # Scan ports (limit to 50 for speed)
            for port in port_list[:50]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        service = self.get_service_name(port)
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'status': 'open'
                        })
                    sock.close()
                except Exception as e:
                    logger.debug(f"Port {port} scan error: {e}")
        
        except Exception as e:
            logger.error(f"Port scan error: {e}")
        
        return open_ports
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Proxy'
        }
        return services.get(port, f'Unknown ({port})')
    
    def get_reverse_dns(self, ip):
        """Get reverse DNS PTR record"""
        try:
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            answer = resolver.resolve(addr, 'PTR')
            return str(answer[0]) if answer else None
        except Exception as e:
            logger.debug(f"Reverse DNS error: {e}")
            return None
    
    def get_ip_whois(self, ip):
        """Get WHOIS information for IP"""
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            result = obj.lookup_rdap()
            return {
                'asn': result.get('asn'),
                'asn_description': result.get('asn_description'),
                'network': result.get('network', {}),
                'entities': result.get('entities', []),
                'raw': result
            }
        except ImportError:
            return {'error': 'ipwhois module not installed'}
        except Exception as e:
            logger.error(f"WHOIS error: {e}")
            return {'error': str(e)}
    
    def find_associated_domains(self, ip):
        """Find domains associated with IP"""
        domains = []
        
        # Check reverse DNS
        reverse = self.get_reverse_dns(ip)
        if reverse:
            domains.append(reverse)
        
        return domains

class DomainAnalyzer:
    """Complete domain analysis module"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze(self, domain):
        """Complete domain analysis"""
        try:
            results = {
                'domain': domain,
                'whois': self.get_whois(domain),
                'dns': self.get_dns_records(domain),
                'ssl': self.get_ssl_info(domain),
                'subdomains': self.find_subdomains(domain),
                'headers': self.get_http_headers(domain),
                'technologies': self.detect_technologies(domain),
                'security': self.check_security_headers(domain),
                'timestamp': datetime.now().isoformat()
            }
            return results
        except Exception as e:
            logger.error(f"Domain analysis error: {e}")
            return {'domain': domain, 'error': str(e)}
    
    def get_whois(self, domain):
        """Get WHOIS information"""
        # If whois module is not available, return placeholder data
        if whois is None:
            return {
                'registrar': 'N/A',
                'creation_date': 'N/A',
                'expiration_date': 'N/A',
                'updated_date': 'N/A',
                'name_servers': [],
                'status': [],
                'emails': [],
                'org': 'N/A',
                'address': 'N/A',
                'city': 'N/A',
                'state': 'N/A',
                'zipcode': 'N/A',
                'country': 'N/A',
                'note': 'WHOIS module not available - install with: pip install python-whois'
            }
        
        try:
            w = whois.whois(domain)
            
            # If pythonwhois returns a dict instead of object
            if isinstance(w, dict):
                # Handle dictionary format
                return {
                    'registrar': w.get('registrar'),
                    'creation_date': str(w.get('creation_date', [''])[0]) if w.get('creation_date') else None,
                    'expiration_date': str(w.get('expiration_date', [''])[0]) if w.get('expiration_date') else None,
                    'updated_date': str(w.get('updated_date', [''])[0]) if w.get('updated_date') else None,
                    'name_servers': list(w.get('name_servers', [])),
                    'status': w.get('status', []),
                    'emails': w.get('emails', []),
                    'org': w.get('org'),
                    'address': w.get('address'),
                    'city': w.get('city'),
                    'state': w.get('state'),
                    'zipcode': w.get('zipcode'),
                    'country': w.get('country')
                }
            
            # Original code for regular whois module (object format)
            # Convert dates to strings
            creation_date = w.creation_date
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = str(creation_date[0])
                else:
                    creation_date = str(creation_date)
            
            expiration_date = w.expiration_date
            if expiration_date:
                if isinstance(expiration_date, list):
                    expiration_date = str(expiration_date[0])
                else:
                    expiration_date = str(expiration_date)
            
            return {
                'registrar': w.registrar,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': list(w.name_servers) if w.name_servers else [],
                'status': w.status if w.status else [],
                'emails': w.emails if w.emails else [],
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode,
                'country': w.country
            }
        except Exception as e:
            logger.error(f"WHOIS error: {e}")
            # Return fallback data on error
            return {
                'registrar': 'N/A',
                'creation_date': 'N/A',
                'expiration_date': 'N/A',
                'updated_date': 'N/A',
                'name_servers': [],
                'status': [],
                'emails': [],
                'org': 'N/A',
                'address': 'N/A',
                'city': 'N/A',
                'state': 'N/A',
                'zipcode': 'N/A',
                'country': 'N/A',
                'error': str(e)
            }
    
    def get_dns_records(self, domain):
        """Get all DNS records"""
        records = {}
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                records['A'] = [str(r) for r in answers]
            except Exception as e:
                records['A'] = []
            
            # AAAA records
            try:
                answers = resolver.resolve(domain, 'AAAA')
                records['AAAA'] = [str(r) for r in answers]
            except Exception as e:
                records['AAAA'] = []
            
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                records['MX'] = [str(r.exchange) for r in answers]
            except Exception as e:
                records['MX'] = []
            
            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                records['NS'] = [str(r) for r in answers]
            except Exception as e:
                records['NS'] = []
            
            # TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                records['TXT'] = []
                for r in answers:
                    for txt in r.strings:
                        records['TXT'].append(txt.decode('utf-8', errors='ignore'))
            except Exception as e:
                records['TXT'] = []
            
            # CNAME record
            try:
                answers = resolver.resolve(domain, 'CNAME')
                records['CNAME'] = [str(r.target) for r in answers]
            except Exception as e:
                records['CNAME'] = []
            
            # SOA record
            try:
                answers = resolver.resolve(domain, 'SOA')
                records['SOA'] = str(answers[0]) if answers else None
            except Exception as e:
                records['SOA'] = None
            
        except Exception as e:
            logger.error(f"DNS error: {e}")
            records['error'] = str(e)
        
        return records
    
    def get_ssl_info(self, domain):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate
                    ssl_info = {}
                    if cert:
                        ssl_info = {
                            'issuer': dict(x[0] for x in cert['issuer']) if 'issuer' in cert else {},
                            'subject': dict(x[0] for x in cert['subject']) if 'subject' in cert else {},
                            'version': cert.get('version'),
                            'serialNumber': cert.get('serialNumber'),
                            'notBefore': cert.get('notBefore'),
                            'notAfter': cert.get('notAfter'),
                            'subjectAltName': cert.get('subjectAltName', [])
                        }
                    
                    # Get additional info
                    ssl_info['cipher'] = ssock.cipher()
                    ssl_info['protocol'] = ssock.version()
                    
                    return ssl_info
        except Exception as e:
            logger.error(f"SSL error: {e}")
            return {'error': str(e)}
    
    def find_subdomains(self, domain):
        """Find subdomains using common prefixes"""
        subdomains = []
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'test', 'dev',
            'staging', 'secure', 'portal', 'webmail', 'cpanel', 'whm',
            'webdisk', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'git', 'svn',
            'm', 'mobile', 'static', 'media', 'cdn', 'shop', 'store',
            'app', 'beta', 'new', 'old', 'demo', 'docs', 'help', 'support'
        ]
        
        for sub in common_subs:
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
            except Exception:
                pass
        
        return subdomains
    
    def get_http_headers(self, domain):
        """Get HTTP headers"""
        try:
            # Try HTTPS first
            try:
                response = self.session.get(f"https://{domain}", timeout=5, allow_redirects=True)
            except Exception:
                # If HTTPS fails, try HTTP
                response = self.session.get(f"http://{domain}", timeout=5, allow_redirects=True)
            
            return {
                'url': response.url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'final_url': response.url
            }
            
        except Exception as e:
            logger.error(f"HTTP headers error: {e}")
            return {'error': str(e)}
    
    def detect_technologies(self, domain):
        """Detect web technologies"""
        technologies = []
        
        try:
            response = self.session.get(f"https://{domain}", timeout=5)
            html = response.text
            
            # Check for common frameworks
            checks = [
                ('WordPress', ['wp-content', 'wp-includes', 'wordpress']),
                ('Joomla', ['joomla', 'Joomla']),
                ('Drupal', ['Drupal', 'drupal']),
                ('React', ['react', 'React']),
                ('Angular', ['angular', 'Angular']),
                ('Vue.js', ['vue', 'Vue']),
                ('jQuery', ['jquery', 'jQuery']),
                ('Bootstrap', ['bootstrap', 'Bootstrap']),
                ('Google Analytics', ['analytics.js', 'gtag.js']),
                ('Cloudflare', ['cloudflare', 'Cloudflare']),
            ]
            
            for tech, patterns in checks:
                if any(pattern in html for pattern in patterns):
                    technologies.append(tech)
            
            # Check headers for technologies
            headers = response.headers
            if 'X-Powered-By' in headers:
                technologies.append(headers['X-Powered-By'])
            if 'X-Generator' in headers:
                technologies.append(headers['X-Generator'])
            
        except Exception as e:
            logger.debug(f"Technology detection error: {e}")
        
        return list(set(technologies))  # Remove duplicates
    
    def check_security_headers(self, domain):
        """Check security headers"""
        security = {}
        
        try:
            response = self.session.get(f"https://{domain}", timeout=5)
            headers = response.headers
            
            security_headers = [
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy'
            ]
            
            for header in security_headers:
                security[header] = headers.get(header, 'MISSING')
            
            # Grade the security
            present = sum(1 for h in security.values() if h != 'MISSING')
            total = len(security)
            security['score'] = f"{present}/{total}"
            security['percentage'] = int((present / total) * 100) if total > 0 else 0
            
        except Exception as e:
            security['error'] = str(e)
        
        return security

class EmailAnalyzer:
    """Complete email analysis module"""
    
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}
        self.session = requests.Session()
    
    def analyze(self, email):
        """Complete email analysis"""
        try:
            results = {
                'email': email,
                'validation': self.validate_email(email),
                'breaches': self.check_breaches(email),
                'social_profiles': self.find_social_profiles(email),
                'gravatar': self.get_gravatar_info(email),
                'disposable': self.is_disposable_email(email),
                'timestamp': datetime.now().isoformat()
            }
            return results
        except Exception as e:
            logger.error(f"Email analysis error: {e}")
            return {'email': email, 'error': str(e)}
    
    def validate_email(self, email):
        """Validate email format and domain"""
        import re
        
        # Basic email regex
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        is_valid = bool(re.match(pattern, email))
        
        # Check domain MX records
        domain = email.split('@')[1] if '@' in email else ''
        has_mx = False
        
        if domain:
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                has_mx = len(answers) > 0
            except Exception as e:
                logger.debug(f"MX check error: {e}")
                has_mx = False
        
        return {
            'format_valid': is_valid,
            'domain': domain,
            'has_mx_records': has_mx,
            'is_valid': is_valid and has_mx
        }
    
    def check_breaches(self, email):
        """Check email against breach databases"""
        import hashlib
        
        # Use Have I Been Pwned API
        try:
            # Hash the email
            email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
            prefix = email_hash[:5]
            
            response = self.session.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                headers={'User-Agent': 'OSINT-Tool'},
                timeout=10
            )
            
            if response.status_code == 200:
                suffixes = response.text.splitlines()
                for suffix in suffixes:
                    if email_hash[5:] in suffix:
                        count = int(suffix.split(':')[1])
                        return {
                            'breached': True,
                            'breach_count': count,
                            'message': f'Found in {count} breach(es)'
                        }
            
            return {'breached': False, 'breach_count': 0}
            
        except Exception as e:
            logger.error(f"Breach check error: {e}")
            return {'breached': False, 'error': str(e)}
    
    def find_social_profiles(self, email):
        """Find social profiles by email"""
        profiles = []
        
        # Hunter.io API (requires key)
        if 'hunterio' in self.api_keys and self.api_keys['hunterio']:
            try:
                response = self.session.get(
                    f'https://api.hunter.io/v2/email-finder?email={email}',
                    headers={'Authorization': self.api_keys['hunterio']},
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data'):
                        sources = data['data'].get('sources', [])
                        for source in sources:
                            profiles.append({
                                'domain': source.get('domain'),
                                'uri': source.get('uri'),
                                'extracted_on': source.get('extracted_on')
                            })
            except Exception as e:
                logger.debug(f"Hunter.io error: {e}")
        
        # Check common social media patterns
        username = email.split('@')[0] if '@' in email else ''
        
        if username:
            social_platforms = [
                ('Twitter', f'https://twitter.com/{username}'),
                ('GitHub', f'https://github.com/{username}'),
                ('Instagram', f'https://instagram.com/{username}'),
                ('LinkedIn', f'https://linkedin.com/in/{username}'),
                ('Facebook', f'https://facebook.com/{username}'),
                ('YouTube', f'https://youtube.com/@{username}'),
                ('Reddit', f'https://reddit.com/user/{username}')
            ]
            
            for platform, url in social_platforms:
                try:
                    response = self.session.head(url, timeout=3, allow_redirects=True)
                    if response.status_code in [200, 302]:
                        profiles.append({
                            'platform': platform,
                            'url': url,
                            'status': 'Found'
                        })
                except Exception:
                    pass
        
        return profiles
    
    def get_gravatar_info(self, email):
        """Get Gravatar information"""
        import hashlib
        
        # Create MD5 hash of email
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        
        gravatar_url = f'https://www.gravatar.com/avatar/{email_hash}'
        
        # Try to get profile info
        try:
            response = self.session.get(f'{gravatar_url}.json', timeout=5)
            if response.status_code == 200:
                profile = response.json()
                return {
                    'url': gravatar_url,
                    'has_gravatar': True,
                    'profile': profile.get('entry', [{}])[0] if profile.get('entry') else {}
                }
        except Exception as e:
            logger.debug(f"Gravatar error: {e}")
        
        return {
            'url': gravatar_url,
            'has_gravatar': False
        }
    
    def is_disposable_email(self, email):
        """Check if email is from disposable service"""
        domain = email.split('@')[1].lower() if '@' in email else ''
        
        disposable_domains = [
            'tempmail.com', 'mailinator.com', 'guerrillamail.com',
            '10minutemail.com', 'throwawaymail.com', 'yopmail.com',
            'dispostable.com', 'temp-mail.org', 'fakeinbox.com',
            'getairmail.com', 'maildrop.cc', 'trashmail.com'
        ]
        
        return domain in disposable_domains

class SocialMediaAnalyzer:
    """Complete social media analysis module"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze_username(self, username):
        """Check username across multiple platforms"""
        results = {}
        
        platforms = {
            'Twitter': f'https://twitter.com/{username}',
            'GitHub': f'https://github.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'Steam': f'https://steamcommunity.com/id/{username}',
            'Flickr': f'https://flickr.com/people/{username}',
            'Dev.to': f'https://dev.to/{username}',
            'Medium': f'https://medium.com/@{username}'
        }
        
        for platform, url in platforms.items():
            try:
                response = self.session.head(url, timeout=3, allow_redirects=True)
                if response.status_code == 200:
                    results[platform] = {
                        'found': True,
                        'url': url,
                        'status_code': response.status_code
                    }
                    
                    # Try to get more info for certain platforms
                    if platform in ['GitHub', 'Twitter']:
                        try:
                            resp = self.session.get(url, timeout=5)
                            soup = BeautifulSoup(resp.text, 'html.parser')
                            
                            if platform == 'GitHub':
                                # Extract GitHub info
                                name_elem = soup.find('span', {'itemprop': 'name'})
                                bio_elem = soup.find('div', {'class': 'p-note'})
                                results[platform]['name'] = name_elem.get_text(strip=True) if name_elem else None
                                results[platform]['bio'] = bio_elem.get_text(strip=True) if bio_elem else None
                            
                            elif platform == 'Twitter':
                                # Extract Twitter info
                                name_elem = soup.find('div', {'data-testid': 'UserName'})
                                bio_elem = soup.find('div', {'data-testid': 'UserDescription'})
                                results[platform]['name'] = name_elem.get_text(strip=True) if name_elem else None
                                results[platform]['bio'] = bio_elem.get_text(strip=True) if bio_elem else None
                                
                        except Exception as e:
                            logger.debug(f"{platform} details error: {e}")
                else:
                    results[platform] = {
                        'found': False,
                        'url': url,
                        'status_code': response.status_code
                    }
            except Exception as e:
                results[platform] = {
                    'found': False,
                    'url': url,
                    'error': str(e)
                }
        
        return results

class NetworkScanner:
    """Complete network scanning module"""
    
    def __init__(self):
        self.open_ports = []
    
    def scan(self, target, ports='1-1024'):
        """Scan target for open ports"""
        import threading
        from queue import Queue
        
        port_queue = Queue()
        results = []
        
        # Parse port range
        port_list = []
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part))
        
        # Limit to first 1000 ports
        port_list = port_list[:1000]
        
        # Worker function
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.get_service_name(port)
                    return {
                        'port': port,
                        'service': service,
                        'status': 'open'
                    }
                sock.close()
            except Exception as e:
                logger.debug(f"Port {port} scan error: {e}")
            return None
        
        # Threaded scanning
        threads = []
        for port in port_list:
            thread = threading.Thread(
                target=lambda p: results.append(scan_port(p)),
                args=(port,)
            )
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        # Filter out None results
        results = [r for r in results if r]
        
        return {
            'target': target,
            'open_ports': results,
            'total_scanned': len(port_list),
            'total_open': len(results)
        }
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client',
            69: 'TFTP', 80: 'HTTP', 110: 'POP3', 119: 'NNTP',
            123: 'NTP', 135: 'MS RPC', 139: 'NetBIOS', 143: 'IMAP',
            161: 'SNMP', 162: 'SNMP Trap', 179: 'BGP', 194: 'IRC',
            389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            514: 'Syslog', 515: 'LPD', 587: 'SMTP', 636: 'LDAPS',
            993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL',
            1521: 'Oracle', 2049: 'NFS', 2375: 'Docker', 2376: 'Docker TLS',
            3000: 'Node.js', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 5938: 'TeamViewer', 6379: 'Redis', 8080: 'HTTP Proxy',
            8443: 'HTTPS Alt', 9000: 'SonarQube', 9090: 'CockroachDB',
            9200: 'Elasticsearch', 9300: 'Elasticsearch', 27017: 'MongoDB'
        }
        return services.get(port, f'Unknown ({port})')

class ImageAnalyzer:
    """Complete image analysis module"""
    
    def analyze(self, image_path):
        """Analyze image file"""
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        
        results = {
            'path': image_path,
            'basic_info': {},
            'exif_data': {},
            'hashes': {},
            'analysis': {}
        }
        
        try:
            # Open image
            img = Image.open(image_path)
            
            # Basic info
            results['basic_info'] = {
                'format': img.format,
                'mode': img.mode,
                'size': img.size,
                'width': img.width,
                'height': img.height,
                'is_animated': getattr(img, 'is_animated', False)
            }
            
            # EXIF data
            exif_data = {}
            try:
                exif = img._getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        
                        # Handle different value types
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore')
                            except Exception:
                                value = str(value)
                        
                        exif_data[tag_name] = value
            except Exception as e:
                logger.debug(f"EXIF extraction error: {e}")
            
            results['exif_data'] = exif_data
            
            # Calculate hashes
            with open(image_path, 'rb') as f:
                data = f.read()
                results['hashes'] = {
                    'md5': hashlib.md5(data).hexdigest(),
                    'sha1': hashlib.sha1(data).hexdigest(),
                    'sha256': hashlib.sha256(data).hexdigest()
                }
            
            # Extract GPS data if present
            gps_info = {}
            if 'GPSInfo' in exif_data:
                gps = exif_data['GPSInfo']
                if isinstance(gps, dict):
                    for tag, value in gps.items():
                        tag_name = GPSTAGS.get(tag, tag)
                        gps_info[tag_name] = value
            
            results['analysis']['gps_data'] = gps_info
            
            # Extract creation/modification dates
            dates = []
            for field in ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
                if field in exif_data:
                    dates.append(exif_data[field])
            
            results['analysis']['dates'] = dates
            
            # Check for embedded thumbnails
            results['analysis']['has_thumbnail'] = hasattr(img, 'thumbnail')
            
        except Exception as e:
            results['error'] = str(e)
        
        return results

class GeolocationTracker:
    """Complete geolocation tracking module"""
    
    def __init__(self):
        self.locations = []
    
    def track_ip(self, ip):
        """Track geolocation of IP"""
        analyzer = IPAnalyzer()
        geo = analyzer.get_geolocation(ip)
        
        if 'error' not in geo:
            location = {
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'country': geo.get('country', 'Unknown'),
                'city': geo.get('city', 'Unknown'),
                'latitude': geo.get('lat', 0),
                'longitude': geo.get('lon', 0),
                'isp': geo.get('isp', 'Unknown'),
                'organization': geo.get('org', 'Unknown')
            }
            self.locations.append(location)
            return location
        
        return {'error': geo['error']}
    
    def create_map(self, locations=None):
        """Create interactive map with Folium"""
        if not locations:
            locations = self.locations
        
        if not locations:
            return None
        
        # Create map centered on first location
        first_loc = locations[0]
        m = folium.Map(
            location=[first_loc['latitude'], first_loc['longitude']],
            zoom_start=10
        )
        
        # Add markers for each location
        for loc in locations:
            popup_text = f"""
            <b>IP:</b> {loc['ip']}<br>
            <b>Location:</b> {loc['city']}, {loc['country']}<br>
            <b>ISP:</b> {loc['isp']}<br>
            <b>Time:</b> {loc['timestamp']}
            """
            
            folium.Marker(
                [loc['latitude'], loc['longitude']],
                popup=popup_text,
                tooltip=loc['ip']
            ).add_to(m)
        
        # Save map to HTML string
        map_html = m.get_root().render()
        
        return map_html

class ReportGenerator:
    """Complete report generation module"""
    
    def __init__(self):
        pass
    
    def generate_html_report(self, data, output_path):
        """Generate HTML report"""
        try:
            html_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>OSINT Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                    .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                    .section-title { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                    table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                    th { background: #34495e; color: white; padding: 10px; text-align: left; }
                    td { padding: 10px; border-bottom: 1px solid #ddd; }
                    tr:nth-child(even) { background: #f9f9f9; }
                    .timestamp { color: #7f8c8d; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>OSINT Investigation Report</h1>
                    <p class="timestamp">Generated: {timestamp}</p>
                </div>
                
                {content}
            </body>
            </html>
            """
            
            # Generate content based on data
            content_parts = []
            
            if 'ip' in data:
                content_parts.append("""
                <div class="section">
                    <h2 class="section-title">IP Address Analysis</h2>
                    <p><strong>Target:</strong> {ip}</p>
                """.format(ip=data['ip']))
                
                if 'geolocation' in data:
                    geo = data['geolocation']
                    content_parts.append("""
                    <h3>Geolocation</h3>
                    <table>
                        <tr><th>Country</th><td>{country}</td></tr>
                        <tr><th>City</th><td>{city}</td></tr>
                        <tr><th>ISP</th><td>{isp}</td></tr>
                        <tr><th>Coordinates</th><td>{lat}, {lon}</td></tr>
                    </table>
                    """.format(
                        country=geo.get('country', 'N/A'),
                        city=geo.get('city', 'N/A'),
                        isp=geo.get('isp', 'N/A'),
                        lat=geo.get('lat', 'N/A'),
                        lon=geo.get('lon', 'N/A')
                    ))
                
                content_parts.append("</div>")
            
            # Combine all content
            content = "\n".join(content_parts)
            
            # Write HTML file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_template.format(
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    content=content
                ))
            
            return True
            
        except Exception as e:
            logger.error(f"HTML generation error: {e}")
            return False
    
    def generate_csv_report(self, data, output_path):
        """Generate CSV report"""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(['Field', 'Value', 'Timestamp'])
                
                # Flatten data and write rows
                def flatten_dict(d, prefix=''):
                    items = []
                    for k, v in d.items():
                        if isinstance(v, dict):
                            items.extend(flatten_dict(v, f'{prefix}{k}.'))
                        elif isinstance(v, list):
                            for i, item in enumerate(v):
                                if isinstance(item, dict):
                                    items.extend(flatten_dict(item, f'{prefix}{k}[{i}].'))
                                else:
                                    items.append((f'{prefix}{k}[{i}]', str(item)))
                        else:
                            items.append((f'{prefix}{k}', str(v)))
                    return items
                
                flattened = flatten_dict(data)
                for key, value in flattened:
                    writer.writerow([key, value, datetime.now().isoformat()])
            
            return True
            
        except Exception as e:
            logger.error(f"CSV generation error: {e}")
            return False

# ============================================================================
# Tkinter GUI Application
# ============================================================================

class OSINTApp:
    """Complete OSINT Application with Tkinter GUI"""
    
    def __init__(self, root):
        self.root = root
        
        # Initialize components
        self.config = self.load_config()
        self.db = OSINTDatabase()
        self.analyzers = {
            'ip': IPAnalyzer(self.config.get('API', {})),
            'domain': DomainAnalyzer(),
            'email': EmailAnalyzer(self.config.get('API', {})),
            'social': SocialMediaAnalyzer(),
            'network': NetworkScanner(),
            'image': ImageAnalyzer(),
            'geo': GeolocationTracker()
        }
        self.report_generator = ReportGenerator()
        
        # Current state
        self.current_investigation = None
        self.scan_threads = []
        self.scan_results = {}
        
        # Setup UI
        self.init_ui()
        
        # Load initial data
        self.load_dashboard_data()
        
        logger.info("OSINT Application started")
    
    def load_config(self):
        """Load configuration from file"""
        config = configparser.ConfigParser()
        
        try:
            config.read('config.ini')
        except Exception:
            config = configparser.ConfigParser()
        
        # Default config if file doesn't exist
        if not config.sections():
            config['API'] = {}
            config['Settings'] = {
                'use_proxy': 'false',
                'timeout': '10',
                'max_threads': '5'
            }
            config['Paths'] = {
                'database': 'data/osint_data.db',
                'reports': 'data/reports/',
                'downloads': 'data/downloads/'
            }
            
            try:
                with open('config.ini', 'w') as f:
                    config.write(f)
            except Exception as e:
                logger.error(f"Config write error: {e}")
        
        # Convert to dict for easier access
        config_dict = {}
        for section in config.sections():
            config_dict[section] = dict(config[section])
        
        return config_dict
    
    def init_ui(self):
        """Initialize the user interface"""
        self.root.title("OSINT Analytics Suite v3.0")
        self.root.geometry("1400x900")
        
        # Set window icon
        try:
            self.root.iconbitmap("icons/app_icon.ico")
        except Exception:
            pass
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create notebook (tab widget)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create all tabs
        self.create_dashboard_tab()
        self.create_ip_analyzer_tab()
        self.create_domain_analyzer_tab()
        self.create_email_analyzer_tab()
        self.create_social_media_tab()
        self.create_network_scanner_tab()
        self.create_image_analyzer_tab()
        self.create_geolocation_tab()
        self.create_data_analytics_tab()
        self.create_reporting_tab()
        self.create_settings_tab()
        
        # Create status bar
        self.status_frame = Frame(self.root)
        self.status_frame.pack(side='bottom', fill='x')
        
        self.status_label = Label(self.status_frame, text="Ready", anchor='w')
        self.status_label.pack(side='left', fill='x', expand=True, padx=5)
        
        self.progress_bar = ttk.Progressbar(self.status_frame, mode='determinate', length=200)
        self.progress_bar.pack(side='right', padx=5)
    
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        
        file_menu.add_command(label="New Investigation", command=self.new_investigation)
        file_menu.add_command(label="Open Investigation", command=self.open_investigation)
        file_menu.add_separator()
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        tools_menu.add_command(label="Quick Analyze", command=self.quick_analyze)
        tools_menu.add_command(label="Generate Report", command=self.quick_report)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard_tab = Frame(self.notebook)
        self.notebook.add(dashboard_tab, text="Dashboard")
        
        # Welcome section
        welcome_label = Label(dashboard_tab, text="OSINT Analytics Suite", font=('Arial', 24, 'bold'))
        welcome_label.pack(pady=20)
        
        # Stats overview
        stats_frame = LabelFrame(dashboard_tab, text="Statistics", padx=10, pady=10)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        stats_grid = Frame(stats_frame)
        stats_grid.pack()
        
        self.stats_labels = {}
        stats = [
            ("Total Investigations", "total_inv"),
            ("Active Targets", "active_targets"),
            ("IP Addresses", "ip_count"),
            ("Domains", "domain_count"),
            ("Emails", "email_count"),
            ("Social Profiles", "social_count")
        ]
        
        for i, (title, key) in enumerate(stats):
            row = i // 3
            col = i % 3
            
            frame = Frame(stats_grid)
            frame.grid(row=row*2, column=col, padx=20, pady=5)
            
            Label(frame, text=title).pack()
            label = Label(frame, text="0", font=('Arial', 18, 'bold'), fg='#3498db')
            label.pack()
            self.stats_labels[key] = label
        
        # Quick actions
        quick_frame = LabelFrame(dashboard_tab, text="Quick Actions", padx=10, pady=10)
        quick_frame.pack(fill='x', padx=10, pady=5)
        
        quick_buttons = [
            ("IP Analysis", lambda: self.notebook.select(1)),
            ("Domain Analysis", lambda: self.notebook.select(2)),
            ("Email Check", lambda: self.notebook.select(3)),
            ("Social Media", lambda: self.notebook.select(4)),
            ("Network Scan", lambda: self.notebook.select(5)),
            ("Image Analysis", lambda: self.notebook.select(6))
        ]
        
        for i, (text, command) in enumerate(quick_buttons):
            row = i // 3
            col = i % 3
            
            btn = Button(quick_frame, text=text, command=command, width=15)
            btn.grid(row=row, column=col, padx=5, pady=5)
        
        # Recent investigations
        recent_frame = LabelFrame(dashboard_tab, text="Recent Investigations", padx=10, pady=10)
        recent_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create treeview for investigations
        columns = ("ID", "Name", "Created", "Status")
        self.investigation_tree = ttk.Treeview(recent_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.investigation_tree.heading(col, text=col)
            self.investigation_tree.column(col, width=100)
        
        self.investigation_tree.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(recent_frame, orient="vertical", command=self.investigation_tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.investigation_tree.configure(yscrollcommand=scrollbar.set)
    
    def create_ip_analyzer_tab(self):
        """Create IP analyzer tab"""
        ip_tab = Frame(self.notebook)
        self.notebook.add(ip_tab, text="IP Analyzer")
        
        # Input section
        input_frame = LabelFrame(ip_tab, text="IP Analysis", padx=10, pady=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # IP input
        input_row = Frame(input_frame)
        input_row.pack(fill='x', pady=5)
        
        Label(input_row, text="IP Address:").pack(side='left', padx=5)
        self.ip_input = Entry(input_row, width=30)
        self.ip_input.pack(side='left', padx=5)
        self.ip_input.insert(0, "8.8.8.8")
        
        Button(input_row, text="Analyze", command=self.analyze_ip_action).pack(side='left', padx=5)
        Button(input_row, text="Bulk Import", command=self.bulk_import_ips).pack(side='left', padx=5)
        
        # Options
        options_frame = Frame(input_frame)
        options_frame.pack(fill='x', pady=5)
        
        self.ip_scan_ports = BooleanVar(value=True)
        Checkbutton(options_frame, text="Scan Ports", variable=self.ip_scan_ports).pack(side='left', padx=10)
        
        self.ip_check_threats = BooleanVar(value=True)
        Checkbutton(options_frame, text="Check Threats", variable=self.ip_check_threats).pack(side='left', padx=10)
        
        self.ip_get_whois = BooleanVar(value=True)
        Checkbutton(options_frame, text="Get WHOIS", variable=self.ip_get_whois).pack(side='left', padx=10)
        
        # Results notebook
        self.ip_results_notebook = ttk.Notebook(ip_tab)
        self.ip_results_notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Basic info tab
        basic_tab = Frame(self.ip_results_notebook)
        self.ip_results_notebook.add(basic_tab, text="Basic Info")
        
        self.ip_basic_text = scrolledtext.ScrolledText(basic_tab, wrap='word', height=20)
        self.ip_basic_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Geolocation tab
        geo_tab = Frame(self.ip_results_notebook)
        self.ip_results_notebook.add(geo_tab, text="Geolocation")
        
        self.ip_geo_text = scrolledtext.ScrolledText(geo_tab, wrap='word', height=20)
        self.ip_geo_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Threat intel tab
        threat_tab = Frame(self.ip_results_notebook)
        self.ip_results_notebook.add(threat_tab, text="Threat Intelligence")
        
        self.ip_threat_text = scrolledtext.ScrolledText(threat_tab, wrap='word', height=20)
        self.ip_threat_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Port scan tab
        port_tab = Frame(self.ip_results_notebook)
        self.ip_results_notebook.add(port_tab, text="Port Scan")
        
        self.ip_port_text = scrolledtext.ScrolledText(port_tab, wrap='word', height=20)
        self.ip_port_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_domain_analyzer_tab(self):
        """Create domain analyzer tab"""
        domain_tab = Frame(self.notebook)
        self.notebook.add(domain_tab, text="Domain Analyzer")
        
        # Input section
        input_frame = LabelFrame(domain_tab, text="Domain Analysis", padx=10, pady=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # Domain input
        input_row = Frame(input_frame)
        input_row.pack(fill='x', pady=5)
        
        Label(input_row, text="Domain:").pack(side='left', padx=5)
        self.domain_input = Entry(input_row, width=30)
        self.domain_input.pack(side='left', padx=5)
        self.domain_input.insert(0, "example.com")
        
        Button(input_row, text="Analyze", command=self.analyze_domain_action).pack(side='left', padx=5)
        
        # Results notebook
        self.domain_results_notebook = ttk.Notebook(domain_tab)
        self.domain_results_notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # WHOIS tab
        whois_tab = Frame(self.domain_results_notebook)
        self.domain_results_notebook.add(whois_tab, text="WHOIS")
        
        self.domain_whois_text = scrolledtext.ScrolledText(whois_tab, wrap='word', height=20)
        self.domain_whois_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # DNS tab
        dns_tab = Frame(self.domain_results_notebook)
        self.domain_results_notebook.add(dns_tab, text="DNS Records")
        
        self.domain_dns_text = scrolledtext.ScrolledText(dns_tab, wrap='word', height=20)
        self.domain_dns_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # SSL tab
        ssl_tab = Frame(self.domain_results_notebook)
        self.domain_results_notebook.add(ssl_tab, text="SSL Certificate")
        
        self.domain_ssl_text = scrolledtext.ScrolledText(ssl_tab, wrap='word', height=20)
        self.domain_ssl_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Subdomains tab
        subdomain_tab = Frame(self.domain_results_notebook)
        self.domain_results_notebook.add(subdomain_tab, text="Subdomains")
        
        self.domain_subdomain_list = Listbox(subdomain_tab)
        scrollbar = Scrollbar(subdomain_tab, command=self.domain_subdomain_list.yview)
        self.domain_subdomain_list.config(yscrollcommand=scrollbar.set)
        
        self.domain_subdomain_list.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar.pack(side='right', fill='y')
        
        # HTTP Headers tab
        headers_tab = Frame(self.domain_results_notebook)
        self.domain_results_notebook.add(headers_tab, text="HTTP Headers")
        
        self.domain_headers_text = scrolledtext.ScrolledText(headers_tab, wrap='word', height=20)
        self.domain_headers_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_email_analyzer_tab(self):
        """Create email analyzer tab"""
        email_tab = Frame(self.notebook)
        self.notebook.add(email_tab, text="Email Analyzer")
        
        # Input section
        input_frame = LabelFrame(email_tab, text="Email Analysis", padx=10, pady=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # Email input
        input_row = Frame(input_frame)
        input_row.pack(fill='x', pady=5)
        
        Label(input_row, text="Email Address:").pack(side='left', padx=5)
        self.email_input = Entry(input_row, width=30)
        self.email_input.pack(side='left', padx=5)
        self.email_input.insert(0, "user@example.com")
        
        Button(input_row, text="Analyze", command=self.analyze_email_action).pack(side='left', padx=5)
        
        # Results notebook
        self.email_results_notebook = ttk.Notebook(email_tab)
        self.email_results_notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Validation tab
        validation_tab = Frame(self.email_results_notebook)
        self.email_results_notebook.add(validation_tab, text="Validation")
        
        self.email_validation_text = scrolledtext.ScrolledText(validation_tab, wrap='word', height=20)
        self.email_validation_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Breaches tab
        breach_tab = Frame(self.email_results_notebook)
        self.email_results_notebook.add(breach_tab, text="Breach Check")
        
        self.email_breach_text = scrolledtext.ScrolledText(breach_tab, wrap='word', height=20)
        self.email_breach_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Social profiles tab
        social_tab = Frame(self.email_results_notebook)
        self.email_results_notebook.add(social_tab, text="Social Profiles")
        
        self.email_social_list = Listbox(social_tab)
        scrollbar = Scrollbar(social_tab, command=self.email_social_list.yview)
        self.email_social_list.config(yscrollcommand=scrollbar.set)
        
        self.email_social_list.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar.pack(side='right', fill='y')
    
    def create_social_media_tab(self):
        """Create social media analyzer tab"""
        social_tab = Frame(self.notebook)
        self.notebook.add(social_tab, text="Social Media")
        
        # Input section
        input_frame = LabelFrame(social_tab, text="Social Media Analysis", padx=10, pady=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # Username input
        input_row = Frame(input_frame)
        input_row.pack(fill='x', pady=5)
        
        Label(input_row, text="Username:").pack(side='left', padx=5)
        self.social_username_input = Entry(input_row, width=30)
        self.social_username_input.pack(side='left', padx=5)
        self.social_username_input.insert(0, "username")
        
        Button(input_row, text="Search", command=self.analyze_social_action).pack(side='left', padx=5)
        
        # Results display
        results_frame = Frame(social_tab)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create treeview for results
        columns = ("Platform", "Found", "URL")
        self.social_results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.social_results_tree.heading(col, text=col)
            self.social_results_tree.column(col, width=150)
        
        self.social_results_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.social_results_tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.social_results_tree.configure(yscrollcommand=scrollbar.set)
    
    def create_network_scanner_tab(self):
        """Create network scanner tab"""
        network_tab = Frame(self.notebook)
        self.notebook.add(network_tab, text="Network Scanner")
        
        # Input section
        input_frame = LabelFrame(network_tab, text="Network Scanner", padx=10, pady=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # Target input
        input_row1 = Frame(input_frame)
        input_row1.pack(fill='x', pady=5)
        
        Label(input_row1, text="Target:").pack(side='left', padx=5)
        self.network_target_input = Entry(input_row1, width=20)
        self.network_target_input.pack(side='left', padx=5)
        self.network_target_input.insert(0, "127.0.0.1")
        
        Label(input_row1, text="Ports:").pack(side='left', padx=5)
        self.network_ports_input = Entry(input_row1, width=15)
        self.network_ports_input.pack(side='left', padx=5)
        self.network_ports_input.insert(0, "1-1000")
        
        Button(input_row1, text="Scan", command=self.scan_network_action).pack(side='left', padx=5)
        
        # Results
        results_frame = LabelFrame(network_tab, text="Scan Results", padx=10, pady=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.network_results_text = scrolledtext.ScrolledText(results_frame, wrap='word', height=20)
        self.network_results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Progress bar
        self.network_progress = ttk.Progressbar(results_frame, mode='determinate')
        self.network_progress.pack(fill='x', padx=5, pady=5)
    
    def create_image_analyzer_tab(self):
        """Create image analyzer tab"""
        image_tab = Frame(self.notebook)
        self.notebook.add(image_tab, text="Image Analyzer")
        
        # Input section
        input_frame = LabelFrame(image_tab, text="Image Analysis", padx=10, pady=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # File selection
        file_row = Frame(input_frame)
        file_row.pack(fill='x', pady=5)
        
        Label(file_row, text="Image File:").pack(side='left', padx=5)
        self.image_path_input = Entry(file_row, width=40)
        self.image_path_input.pack(side='left', padx=5, fill='x', expand=True)
        
        Button(file_row, text="Browse", command=self.browse_image).pack(side='left', padx=5)
        Button(file_row, text="Analyze", command=self.analyze_image_action).pack(side='left', padx=5)
        
        # Results notebook
        self.image_results_notebook = ttk.Notebook(image_tab)
        self.image_results_notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Basic info tab
        image_basic_tab = Frame(self.image_results_notebook)
        self.image_results_notebook.add(image_basic_tab, text="Basic Info")
        
        self.image_basic_text = scrolledtext.ScrolledText(image_basic_tab, wrap='word', height=20)
        self.image_basic_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # EXIF tab
        image_exif_tab = Frame(self.image_results_notebook)
        self.image_results_notebook.add(image_exif_tab, text="EXIF Data")
        
        self.image_exif_text = scrolledtext.ScrolledText(image_exif_tab, wrap='word', height=20)
        self.image_exif_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Hashes tab
        image_hash_tab = Frame(self.image_results_notebook)
        self.image_results_notebook.add(image_hash_tab, text="Hashes")
        
        self.image_hash_text = scrolledtext.ScrolledText(image_hash_tab, wrap='word', height=20)
        self.image_hash_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Image preview tab
        image_preview_tab = Frame(self.image_results_notebook)
        self.image_results_notebook.add(image_preview_tab, text="Preview")
        
        self.image_preview_label = Label(image_preview_tab, text="No image loaded", bg='white')
        self.image_preview_label.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_geolocation_tab(self):
        """Create geolocation tracking tab"""
        geo_tab = Frame(self.notebook)
        self.notebook.add(geo_tab, text="Geolocation")
        
        # Input section
        input_frame = LabelFrame(geo_tab, text="Geolocation Tracking", padx=10, pady=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # IP input for tracking
        ip_track_row = Frame(input_frame)
        ip_track_row.pack(fill='x', pady=5)
        
        Label(ip_track_row, text="IP Address:").pack(side='left', padx=5)
        self.geo_ip_input = Entry(ip_track_row, width=30)
        self.geo_ip_input.pack(side='left', padx=5)
        
        Button(ip_track_row, text="Track", command=self.track_ip_action).pack(side='left', padx=5)
        Button(ip_track_row, text="Clear", command=self.clear_tracking).pack(side='left', padx=5)
        
        # Tracking list
        track_frame = LabelFrame(geo_tab, text="Tracked Locations", padx=10, pady=10)
        track_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create treeview for tracked locations
        columns = ("IP", "Country", "City", "ISP", "Coordinates", "Time")
        self.geo_track_tree = ttk.Treeview(track_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.geo_track_tree.heading(col, text=col)
            self.geo_track_tree.column(col, width=120)
        
        self.geo_track_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(track_frame, orient="vertical", command=self.geo_track_tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.geo_track_tree.configure(yscrollcommand=scrollbar.set)
    
    def create_data_analytics_tab(self):
        """Create data analytics tab"""
        analytics_tab = Frame(self.notebook)
        self.notebook.add(analytics_tab, text="Data Analytics")
        
        # Analysis type selection
        analysis_frame = LabelFrame(analytics_tab, text="Data Analytics", padx=10, pady=10)
        analysis_frame.pack(fill='x', padx=10, pady=5)
        
        # Analysis type
        type_row = Frame(analysis_frame)
        type_row.pack(fill='x', pady=5)
        
        Label(type_row, text="Analysis Type:").pack(side='left', padx=5)
        self.analytics_type_var = StringVar()
        self.analytics_type_combo = ttk.Combobox(type_row, textvariable=self.analytics_type_var, width=20)
        self.analytics_type_combo['values'] = (
            "Target Correlation",
            "Timeline Analysis",
            "Pattern Detection",
            "Risk Assessment",
            "Sentiment Analysis"
        )
        self.analytics_type_combo.current(0)
        self.analytics_type_combo.pack(side='left', padx=5)
        
        Button(type_row, text="Run Analysis", command=self.run_analytics_action).pack(side='left', padx=5)
        
        # Results display
        results_frame = LabelFrame(analytics_tab, text="Analysis Results", padx=10, pady=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.analytics_results_text = scrolledtext.ScrolledText(results_frame, wrap='word', height=25)
        self.analytics_results_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_reporting_tab(self):
        """Create reporting tab"""
        report_tab = Frame(self.notebook)
        self.notebook.add(report_tab, text="Reporting")
        
        # Report generation
        report_frame = LabelFrame(report_tab, text="Report Generation", padx=10, pady=10)
        report_frame.pack(fill='x', padx=10, pady=5)
        
        # Report type
        type_row = Frame(report_frame)
        type_row.pack(fill='x', pady=5)
        
        Label(type_row, text="Report Type:").pack(side='left', padx=5)
        self.report_type_var = StringVar()
        self.report_type_combo = ttk.Combobox(type_row, textvariable=self.report_type_var, width=15)
        self.report_type_combo['values'] = ("HTML", "CSV")
        self.report_type_combo.current(0)
        self.report_type_combo.pack(side='left', padx=5)
        
        # Report content
        Label(type_row, text="Content:").pack(side='left', padx=5)
        self.report_content_var = StringVar()
        self.report_content_combo = ttk.Combobox(type_row, textvariable=self.report_content_var, width=20)
        self.report_content_combo['values'] = (
            "Current Analysis",
            "All Investigations",
            "Selected Targets"
        )
        self.report_content_combo.current(0)
        self.report_content_combo.pack(side='left', padx=5)
        
        Button(type_row, text="Generate Report", command=self.generate_report_action).pack(side='left', padx=5)
        
        # Report preview
        preview_frame = LabelFrame(report_tab, text="Report Preview", padx=10, pady=10)
        preview_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.report_preview_text = scrolledtext.ScrolledText(preview_frame, wrap='word', height=25)
        self.report_preview_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_tab = Frame(self.notebook)
        self.notebook.add(settings_tab, text="Settings")
        
        # API Keys section
        api_frame = LabelFrame(settings_tab, text="API Keys", padx=10, pady=10)
        api_frame.pack(fill='x', padx=10, pady=5)
        
        # VirusTotal
        vt_row = Frame(api_frame)
        vt_row.pack(fill='x', pady=2)
        Label(vt_row, text="VirusTotal:", width=15, anchor='w').pack(side='left', padx=5)
        self.api_virustotal = Entry(vt_row, width=40)
        self.api_virustotal.pack(side='left', padx=5, fill='x', expand=True)
        self.api_virustotal.insert(0, self.config.get('API', {}).get('virustotal', ''))
        
        # AbuseIPDB
        abuse_row = Frame(api_frame)
        abuse_row.pack(fill='x', pady=2)
        Label(abuse_row, text="AbuseIPDB:", width=15, anchor='w').pack(side='left', padx=5)
        self.api_abuseipdb = Entry(abuse_row, width=40)
        self.api_abuseipdb.pack(side='left', padx=5, fill='x', expand=True)
        self.api_abuseipdb.insert(0, self.config.get('API', {}).get('abuseipdb', ''))
        
        # Hunter.io
        hunter_row = Frame(api_frame)
        hunter_row.pack(fill='x', pady=2)
        Label(hunter_row, text="Hunter.io:", width=15, anchor='w').pack(side='left', padx=5)
        self.api_hunterio = Entry(hunter_row, width=40)
        self.api_hunterio.pack(side='left', padx=5, fill='x', expand=True)
        self.api_hunterio.insert(0, self.config.get('API', {}).get('hunterio', ''))
        
        # IPinfo.io
        ipinfo_row = Frame(api_frame)
        ipinfo_row.pack(fill='x', pady=2)
        Label(ipinfo_row, text="IPinfo.io:", width=15, anchor='w').pack(side='left', padx=5)
        self.api_ipinfo = Entry(ipinfo_row, width=40)
        self.api_ipinfo.pack(side='left', padx=5, fill='x', expand=True)
        self.api_ipinfo.insert(0, self.config.get('API', {}).get('ipinfo', ''))
        
        # Settings section
        settings_frame = LabelFrame(settings_tab, text="Application Settings", padx=10, pady=10)
        settings_frame.pack(fill='x', padx=10, pady=5)
        
        # Use Proxy
        proxy_row = Frame(settings_frame)
        proxy_row.pack(fill='x', pady=2)
        Label(proxy_row, text="Proxy:", width=15, anchor='w').pack(side='left', padx=5)
        self.setting_proxy = BooleanVar(value=self.config.get('Settings', {}).get('use_proxy', 'false').lower() == 'true')
        Checkbutton(proxy_row, variable=self.setting_proxy).pack(side='left', padx=5)
        
        # Auto-save
        autosave_row = Frame(settings_frame)
        autosave_row.pack(fill='x', pady=2)
        Label(autosave_row, text="Auto-save:", width=15, anchor='w').pack(side='left', padx=5)
        self.setting_auto_save = BooleanVar(value=True)
        Checkbutton(autosave_row, variable=self.setting_auto_save).pack(side='left', padx=5)
        
        # Max Threads
        threads_row = Frame(settings_frame)
        threads_row.pack(fill='x', pady=2)
        Label(threads_row, text="Max Threads:", width=15, anchor='w').pack(side='left', padx=5)
        self.setting_max_threads = IntVar(value=int(self.config.get('Settings', {}).get('max_threads', '10')))
        Spinbox(threads_row, from_=1, to=50, textvariable=self.setting_max_threads, width=10).pack(side='left', padx=5)
        
        # Buttons
        button_frame = Frame(settings_tab)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        Button(button_frame, text="Save Settings", command=self.save_settings).pack(side='left', padx=5)
        Button(button_frame, text="Load Settings", command=self.load_settings).pack(side='left', padx=5)
        Button(button_frame, text="Reset to Default", command=self.reset_settings).pack(side='left', padx=5)
    
    # ============================================================================
    # ACTION HANDLERS
    # ============================================================================
    
    def load_dashboard_data(self):
        """Load data for dashboard"""
        try:
            # Get investigations
            investigations = self.db.get_investigations()
            self.stats_labels['total_inv'].config(text=str(len(investigations)))
            
            # Update investigation table
            for item in self.investigation_tree.get_children():
                self.investigation_tree.delete(item)
            
            for inv in investigations[:10]:
                self.investigation_tree.insert('', 'end', values=(
                    inv.get('id'),
                    inv.get('name'),
                    inv.get('created_at'),
                    inv.get('status')
                ))
            
            # Get other stats
            targets = self.db.get_targets()
            self.stats_labels['active_targets'].config(text=str(len(targets)))
            
            # Count by type
            type_counts = {}
            for target in targets:
                ttype = target.get('type')
                type_counts[ttype] = type_counts.get(ttype, 0) + 1
            
            self.stats_labels['ip_count'].config(text=str(type_counts.get('ip', 0)))
            self.stats_labels['domain_count'].config(text=str(type_counts.get('domain', 0)))
            self.stats_labels['email_count'].config(text=str(type_counts.get('email', 0)))
            self.stats_labels['social_count'].config(text=str(type_counts.get('social', 0)))
            
        except Exception as e:
            logger.error(f"Dashboard load error: {e}")
            messagebox.showerror("Error", f"Failed to load dashboard data: {e}")
    
    def analyze_ip_action(self):
        """Handle IP analysis"""
        ip = self.ip_input.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address.")
            return
        
        # Disable button and show progress
        self.status_label.config(text=f"Analyzing IP: {ip}...")
        self.progress_bar.start()
        
        # Run analysis in thread
        thread = threading.Thread(target=self._analyze_ip_thread, args=(ip,))
        thread.daemon = True
        thread.start()
    
    def _analyze_ip_thread(self, ip):
        """Thread function for IP analysis"""
        try:
            # Get options
            scan_ports = self.ip_scan_ports.get()
            check_threats = self.ip_check_threats.get()
            get_whois = self.ip_get_whois.get()
            
            # Run analysis
            analyzer = self.analyzers['ip']
            results = analyzer.analyze(ip)
            
            # Update UI in main thread
            self.root.after(0, self._update_ip_results, results)
            
            # Save to database
            if self.current_investigation:
                target_id = self.db.add_target(
                    self.current_investigation, 'ip', ip,
                    source='manual', confidence=90
                )
                self.db.update_ip_data(target_id, {
                    'ip': ip,
                    'country': results.get('geolocation', {}).get('country'),
                    'city': results.get('geolocation', {}).get('city'),
                    'region': results.get('geolocation', {}).get('region'),
                    'isp': results.get('geolocation', {}).get('isp'),
                    'org': results.get('geolocation', {}).get('org'),
                    'asn': results.get('geolocation', {}).get('as'),
                    'latitude': results.get('geolocation', {}).get('lat'),
                    'longitude': results.get('geolocation', {}).get('lon'),
                    'timezone': results.get('geolocation', {}).get('timezone'),
                    'threat_score': 0  # Default value
                })
            
            # Update status
            self.root.after(0, lambda: self.status_label.config(text=f"Analysis complete for IP: {ip}"))
            
        except Exception as e:
            logger.error(f"IP analysis error: {e}")
            self.root.after(0, lambda: self._show_error(f"IP analysis failed: {str(e)}"))
        finally:
            # Hide progress bar
            self.root.after(0, self.progress_bar.stop)
    
    def _update_ip_results(self, results):
        """Update IP analysis results in UI"""
        # Basic info
        basic_text = f"""
=== IP Analysis Report ===

Target: {results.get('ip', 'N/A')}
Analysis Time: {results.get('timestamp', 'N/A')}

Basic Information:
• Valid: {results.get('basic_info', {}).get('valid', 'N/A')}
• IP Version: IPv{results.get('basic_info', {}).get('version', 'N/A')}
• Is Private: {results.get('basic_info', {}).get('is_private', 'N/A')}
• Is Global: {results.get('basic_info', {}).get('is_global', 'N/A')}
"""
        self.ip_basic_text.delete(1.0, 'end')
        self.ip_basic_text.insert(1.0, basic_text)
        
        # Geolocation
        geo = results.get('geolocation', {})
        geo_text = f"""
=== Geolocation ===

Country: {geo.get('country', 'N/A')}
City: {geo.get('city', 'N/A')}
Region: {geo.get('region', 'N/A')}

ISP: {geo.get('isp', 'N/A')}
Organization: {geo.get('org', 'N/A')}
ASN: {geo.get('as', 'N/A')}

Coordinates:
• Latitude: {geo.get('lat', 'N/A')}
• Longitude: {geo.get('lon', 'N/A')}

Additional Info:
• Timezone: {geo.get('timezone', 'N/A')}
• Reverse DNS: {geo.get('reverse', 'N/A')}
• Is Mobile: {geo.get('mobile', 'N/A')}
• Is Proxy: {geo.get('proxy', 'N/A')}
• Is Hosting: {geo.get('hosting', 'N/A')}
"""
        self.ip_geo_text.delete(1.0, 'end')
        self.ip_geo_text.insert(1.0, geo_text)
        
        # Threat intelligence
        threats = results.get('threat_intel', {})
        threat_text = "=== Threat Intelligence ===\n\n"
        
        for source, data in threats.items():
            threat_text += f"{source.upper()}:\n"
            if data:
                if isinstance(data, dict):
                    for key, value in data.items():
                        threat_text += f"  • {key}: {value}\n"
                else:
                    threat_text += f"  {data}\n"
            else:
                threat_text += "  No threats detected\n"
            threat_text += "\n"
        
        self.ip_threat_text.delete(1.0, 'end')
        self.ip_threat_text.insert(1.0, threat_text)
        
        # Port scan results
        ports = results.get('ports', [])
        port_text = f"""
=== Port Scan Results ===

Total Open Ports: {len(ports)}

Open Ports:
"""
        for port in ports:
            port_text += f"• Port {port.get('port', 'N/A')}: {port.get('service', 'N/A')}\n"
        
        self.ip_port_text.delete(1.0, 'end')
        self.ip_port_text.insert(1.0, port_text)
    
    def analyze_domain_action(self):
        """Handle domain analysis"""
        domain = self.domain_input.get().strip()
        if not domain:
            messagebox.showwarning("Warning", "Please enter a domain.")
            return
        
        self.status_label.config(text=f"Analyzing domain: {domain}...")
        self.progress_bar.start()
        
        thread = threading.Thread(target=self._analyze_domain_thread, args=(domain,))
        thread.daemon = True
        thread.start()
    
    def _analyze_domain_thread(self, domain):
        """Thread function for domain analysis"""
        try:
            # Run analysis
            analyzer = self.analyzers['domain']
            results = analyzer.analyze(domain)
            
            # Update UI
            self.root.after(0, self._update_domain_results, results)
            
            # Save to database
            if self.current_investigation:
                target_id = self.db.add_target(
                    self.current_investigation, 'domain', domain,
                    source='manual', confidence=90
                )
                self.db.update_domain_data(target_id, {
                    'domain': domain,
                    'registrar': results.get('whois', {}).get('registrar'),
                    'created_date': results.get('whois', {}).get('creation_date'),
                    'expires_date': results.get('whois', {}).get('expiration_date'),
                    'nameservers': ', '.join(results.get('whois', {}).get('name_servers', [])),
                    'status': ', '.join(results.get('whois', {}).get('status', [])),
                    'emails': ', '.join(results.get('whois', {}).get('emails', [])),
                    'dns_a': ', '.join(results.get('dns', {}).get('A', [])),
                    'dns_mx': ', '.join(results.get('dns', {}).get('MX', [])),
                    'dns_ns': ', '.join(results.get('dns', {}).get('NS', [])),
                    'dns_txt': ', '.join(results.get('dns', {}).get('TXT', [])),
                    'ssl_issuer': str(results.get('ssl', {}).get('issuer', {})),
                    'ssl_expiry': results.get('ssl', {}).get('notAfter')
                })
            
            self.root.after(0, lambda: self.status_label.config(text=f"Analysis complete for domain: {domain}"))
            
        except Exception as e:
            logger.error(f"Domain analysis error: {e}")
            self.root.after(0, lambda: self._show_error(f"Domain analysis failed: {str(e)}"))
        finally:
            self.root.after(0, self.progress_bar.stop)
    
    def _update_domain_results(self, results):
        """Update domain analysis results in UI"""
        # WHOIS information
        whois_data = results.get('whois', {})
        whois_text = f"""
=== WHOIS Information ===

Domain: {results.get('domain', 'N/A')}

Registrar: {whois_data.get('registrar', 'N/A')}
Creation Date: {whois_data.get('creation_date', 'N/A')}
Expiration Date: {whois_data.get('expiration_date', 'N/A')}
Updated Date: {whois_data.get('updated_date', 'N/A')}

Name Servers:
{chr(10).join(f'• {ns}' for ns in whois_data.get('name_servers', []))}

Status:
{chr(10).join(f'• {status}' for status in whois_data.get('status', []))}

Contact Emails:
{chr(10).join(f'• {email}' for email in whois_data.get('emails', []))}

Registrant:
• Organization: {whois_data.get('org', 'N/A')}
• Country: {whois_data.get('country', 'N/A')}
"""
        self.domain_whois_text.delete(1.0, 'end')
        self.domain_whois_text.insert(1.0, whois_text)
        
        # DNS records
        dns_data = results.get('dns', {})
        dns_text = "=== DNS Records ===\n\n"
        
        for record_type, values in dns_data.items():
            dns_text += f"{record_type} Records:\n"
            if values:
                if isinstance(values, list):
                    for value in values:
                        dns_text += f"  • {value}\n"
                else:
                    dns_text += f"  • {values}\n"
            else:
                dns_text += "  None found\n"
            dns_text += "\n"
        
        self.domain_dns_text.delete(1.0, 'end')
        self.domain_dns_text.insert(1.0, dns_text)
        
        # SSL certificate
        ssl_data = results.get('ssl', {})
        ssl_text = f"""
=== SSL Certificate ===

Issuer: {ssl_data.get('issuer', {}).get('organizationName', 'N/A')}
Subject: {ssl_data.get('subject', {}).get('commonName', 'N/A')}

Validity:
• Not Before: {ssl_data.get('notBefore', 'N/A')}
• Not After: {ssl_data.get('notAfter', 'N/A')}

Certificate Details:
• Version: {ssl_data.get('version', 'N/A')}
• Serial Number: {ssl_data.get('serialNumber', 'N/A')}

Subject Alternative Names:
{chr(10).join(f'• {san}' for san in ssl_data.get('subjectAltName', []))}
"""
        self.domain_ssl_text.delete(1.0, 'end')
        self.domain_ssl_text.insert(1.0, ssl_text)
        
        # Subdomains
        subdomains = results.get('subdomains', [])
        self.domain_subdomain_list.delete(0, 'end')
        for sub in subdomains:
            self.domain_subdomain_list.insert('end', sub)
        
        # HTTP headers
        headers_data = results.get('headers', {})
        headers_text = f"""
=== HTTP Headers ===

Final URL: {headers_data.get('final_url', 'N/A')}
Status Code: {headers_data.get('status_code', 'N/A')}
Server: {headers_data.get('server', 'N/A')}
Content Type: {headers_data.get('content_type', 'N/A')}

Security Headers:
{chr(10).join(f'• {k}: {v}' for k, v in results.get('security', {}).items())}

Detected Technologies:
{chr(10).join(f'• {tech}' for tech in results.get('technologies', []))}
"""
        self.domain_headers_text.delete(1.0, 'end')
        self.domain_headers_text.insert(1.0, headers_text)
    
    def analyze_email_action(self):
        """Handle email analysis"""
        email = self.email_input.get().strip()
        if not email:
            messagebox.showwarning("Warning", "Please enter an email address.")
            return
        
        self.status_label.config(text=f"Analyzing email: {email}...")
        self.progress_bar.start()
        
        thread = threading.Thread(target=self._analyze_email_thread, args=(email,))
        thread.daemon = True
        thread.start()
    
    def _analyze_email_thread(self, email):
        """Thread function for email analysis"""
        try:
            # Run analysis
            analyzer = self.analyzers['email']
            results = analyzer.analyze(email)
            
            # Update UI
            self.root.after(0, self._update_email_results, results)
            
            # Save to database
            if self.current_investigation:
                target_id = self.db.add_target(
                    self.current_investigation, 'email', email,
                    source='manual', confidence=90
                )
                self.db.add_email(target_id, email, **{
                    'verified': results.get('validation', {}).get('is_valid', False),
                    'breaches': results.get('breaches', {}).get('breach_count', 0),
                    'breach_details': str(results.get('breaches', {})),
                    'social_profiles': str(results.get('social_profiles', [])),
                    'disposable': results.get('disposable', False),
                    'gravatar_hash': results.get('gravatar', {}).get('url', '').split('/')[-1] if results.get('gravatar', {}).get('url') else ''
                })
            
            self.root.after(0, lambda: self.status_label.config(text=f"Analysis complete for email: {email}"))
            
        except Exception as e:
            logger.error(f"Email analysis error: {e}")
            self.root.after(0, lambda: self._show_error(f"Email analysis failed: {str(e)}"))
        finally:
            self.root.after(0, self.progress_bar.stop)
    
    def _update_email_results(self, results):
        """Update email analysis results in UI"""
        # Validation
        validation = results.get('validation', {})
        validation_text = f"""
=== Email Validation ===

Email Address: {results.get('email', 'N/A')}

Format Validation:
• Format Valid: {validation.get('format_valid', 'N/A')}
• Domain: {validation.get('domain', 'N/A')}
• Has MX Records: {validation.get('has_mx_records', 'N/A')}
• Overall Valid: {validation.get('is_valid', 'N/A')}
"""
        self.email_validation_text.delete(1.0, 'end')
        self.email_validation_text.insert(1.0, validation_text)
        
        # Breach check
        breaches = results.get('breaches', {})
        breach_text = f"""
=== Breach Check ===

Breached: {breaches.get('breached', 'N/A')}
Number of Breaches: {breaches.get('breach_count', 'N/A')}

{breaches.get('message', 'No additional information')}
"""
        self.email_breach_text.delete(1.0, 'end')
        self.email_breach_text.insert(1.0, breach_text)
        
        # Social profiles
        profiles = results.get('social_profiles', [])
        self.email_social_list.delete(0, 'end')
        for profile in profiles:
            if isinstance(profile, dict):
                item_text = f"{profile.get('platform', 'Unknown')}: {profile.get('url', 'N/A')}"
            else:
                item_text = str(profile)
            self.email_social_list.insert('end', item_text)
    
    def analyze_social_action(self):
        """Handle social media analysis"""
        username = self.social_username_input.get().strip()
        if not username:
            messagebox.showwarning("Warning", "Please enter a username.")
            return
        
        self.status_label.config(text=f"Searching for username: {username}...")
        self.progress_bar.start()
        
        thread = threading.Thread(target=self._analyze_social_thread, args=(username,))
        thread.daemon = True
        thread.start()
    
    def _analyze_social_thread(self, username):
        """Thread function for social media analysis"""
        try:
            # Run analysis
            analyzer = self.analyzers['social']
            results = analyzer.analyze_username(username)
            
            # Update UI
            self.root.after(0, self._update_social_results, results)
            
            # Save to database
            if self.current_investigation:
                target_id = self.db.add_target(
                    self.current_investigation, 'social', username,
                    source='manual', confidence=90
                )
                
                for platform, data in results.items():
                    if data.get('found'):
                        self.db.add_social_profile(
                            target_id, platform, username,
                            url=data.get('url'),
                            name=data.get('name'),
                            bio=data.get('bio'),
                            verified=False
                        )
            
            self.root.after(0, lambda: self.status_label.config(text=f"Search complete for username: {username}"))
            
        except Exception as e:
            logger.error(f"Social analysis error: {e}")
            self.root.after(0, lambda: self._show_error(f"Social media search failed: {str(e)}"))
        finally:
            self.root.after(0, self.progress_bar.stop)
    
    def _update_social_results(self, results):
        """Update social media analysis results in UI"""
        # Clear existing items
        for item in self.social_results_tree.get_children():
            self.social_results_tree.delete(item)
        
        # Add new items
        for platform, data in results.items():
            found = "Yes" if data.get('found') else "No"
            url = data.get('url', 'N/A')
            self.social_results_tree.insert('', 'end', values=(platform, found, url))
    
    def scan_network_action(self):
        """Handle network scanning"""
        target = self.network_target_input.get().strip()
        ports = self.network_ports_input.get().strip()
        
        if not target:
            messagebox.showwarning("Warning", "Please enter a target.")
            return
        
        self.status_label.config(text=f"Scanning target: {target}...")
        self.progress_bar.start()
        
        thread = threading.Thread(target=self._scan_network_thread, args=(target, ports))
        thread.daemon = True
        thread.start()
    
    def _scan_network_thread(self, target, ports):
        """Thread function for network scanning"""
        try:
            # Run scan
            scanner = self.analyzers['network']
            results = scanner.scan(target, ports)
            
            # Update UI
            self.root.after(0, self._update_network_results, results)
            
            # Update progress
            for i in range(101):
                self.root.after(0, self.network_progress.config, {'value': i})
                time.sleep(0.01)
            
            self.root.after(0, lambda: self.status_label.config(text=f"Scan complete for target: {target}"))
            
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            self.root.after(0, lambda: self._show_error(f"Network scan failed: {str(e)}"))
        finally:
            self.root.after(0, self.progress_bar.stop)
    
    def _update_network_results(self, results):
        """Update network scan results in UI"""
        result_text = f"""
=== Network Scan Results ===

Target: {results.get('target', 'N/A')}
Total Ports Scanned: {results.get('total_scanned', 'N/A')}
Total Open Ports: {results.get('total_open', 'N/A')}

Open Ports:
"""
        
        for port in results.get('open_ports', []):
            result_text += f"• Port {port.get('port', 'N/A')} ({port.get('service', 'N/A')}): OPEN\n"
        
        if not results.get('open_ports'):
            result_text += "No open ports found.\n"
        
        self.network_results_text.delete(1.0, 'end')
        self.network_results_text.insert(1.0, result_text)
    
    def browse_image(self):
        """Browse for image file"""
        filename = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[
                ("Image Files", "*.jpg *.jpeg *.png *.gif *.bmp *.tiff"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            self.image_path_input.delete(0, 'end')
            self.image_path_input.insert(0, filename)
    
    def analyze_image_action(self):
        """Handle image analysis"""
        image_path = self.image_path_input.get().strip()
        if not image_path or not os.path.exists(image_path):
            messagebox.showwarning("Warning", "Please select a valid image file.")
            return
        
        self.status_label.config(text=f"Analyzing image: {os.path.basename(image_path)}...")
        self.progress_bar.start()
        
        thread = threading.Thread(target=self._analyze_image_thread, args=(image_path,))
        thread.daemon = True
        thread.start()
    
    def _analyze_image_thread(self, image_path):
        """Thread function for image analysis"""
        try:
            # Run analysis
            analyzer = self.analyzers['image']
            results = analyzer.analyze(image_path)
            
            # Update UI
            self.root.after(0, self._update_image_results, results)
            
            self.root.after(0, lambda: self.status_label.config(text=f"Analysis complete for image: {os.path.basename(image_path)}"))
            
        except Exception as e:
            logger.error(f"Image analysis error: {e}")
            self.root.after(0, lambda: self._show_error(f"Image analysis failed: {str(e)}"))
        finally:
            self.root.after(0, self.progress_bar.stop)
    
    def _update_image_results(self, results):
        """Update image analysis results in UI"""
        # Basic info
        basic_info = results.get('basic_info', {})
        basic_text = f"""
=== Image Basic Information ===

File: {os.path.basename(results.get('path', 'N/A'))}
Format: {basic_info.get('format', 'N/A')}
Dimensions: {basic_info.get('width', 'N/A')} x {basic_info.get('height', 'N/A')}
Color Mode: {basic_info.get('mode', 'N/A')}
Size: {basic_info.get('size', 'N/A')}
Animated: {basic_info.get('is_animated', 'N/A')}
"""
        self.image_basic_text.delete(1.0, 'end')
        self.image_basic_text.insert(1.0, basic_text)
        
        # EXIF data
        exif_data = results.get('exif_data', {})
        exif_text = "=== EXIF Data ===\n\n"
        
        for key, value in list(exif_data.items())[:50]:  # Limit to first 50 entries
            exif_text += f"{key}: {value}\n"
        
        if len(exif_data) > 50:
            exif_text += f"\n... and {len(exif_data) - 50} more entries"
        
        self.image_exif_text.delete(1.0, 'end')
        self.image_exif_text.insert(1.0, exif_text)
        
        # Hashes
        hashes = results.get('hashes', {})
        hash_text = f"""
=== File Hashes ===

MD5: {hashes.get('md5', 'N/A')}
SHA1: {hashes.get('sha1', 'N/A')}
SHA256: {hashes.get('sha256', 'N/A')}
"""
        self.image_hash_text.delete(1.0, 'end')
        self.image_hash_text.insert(1.0, hash_text)
        
        # Preview image
        try:
            image = Image.open(results['path'])
            image.thumbnail((400, 400))
            photo = ImageTk.PhotoImage(image)
            self.image_preview_label.config(image=photo, text="")
            self.image_preview_label.image = photo  # Keep reference
        except Exception as e:
            self.image_preview_label.config(text=f"Cannot display image: {e}")
    
    def track_ip_action(self):
        """Track IP geolocation"""
        ip = self.geo_ip_input.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address.")
            return
        
        self.status_label.config(text=f"Tracking IP: {ip}...")
        self.progress_bar.start()
        
        thread = threading.Thread(target=self._track_ip_thread, args=(ip,))
        thread.daemon = True
        thread.start()
    
    def _track_ip_thread(self, ip):
        """Thread function for IP tracking"""
        try:
            # Track IP
            tracker = self.analyzers['geo']
            location = tracker.track_ip(ip)
            
            if 'error' not in location:
                # Update tracking table
                self.root.after(0, self._update_tracking_table, location)
            
            self.root.after(0, lambda: self.status_label.config(text=f"Tracking complete for IP: {ip}"))
            
        except Exception as e:
            logger.error(f"IP tracking error: {e}")
            self.root.after(0, lambda: self._show_error(f"IP tracking failed: {str(e)}"))
        finally:
            self.root.after(0, self.progress_bar.stop)
    
    def _update_tracking_table(self, location):
        """Update tracking table"""
        values = (
            location.get('ip', 'N/A'),
            location.get('country', 'N/A'),
            location.get('city', 'N/A'),
            location.get('isp', 'N/A'),
            f"{location.get('latitude', 'N/A')}, {location.get('longitude', 'N/A')}",
            location.get('timestamp', 'N/A')
        )
        self.geo_track_tree.insert('', 'end', values=values)
    
    def clear_tracking(self):
        """Clear tracking data"""
        for item in self.geo_track_tree.get_children():
            self.geo_track_tree.delete(item)
    
    def run_analytics_action(self):
        """Run data analytics"""
        analysis_type = self.analytics_type_var.get()
        
        self.status_label.config(text=f"Running {analysis_type}...")
        self.progress_bar.start()
        
        thread = threading.Thread(target=self._run_analytics_thread, args=(analysis_type,))
        thread.daemon = True
        thread.start()
    
    def _run_analytics_thread(self, analysis_type):
        """Thread function for data analytics"""
        try:
            # Run analysis based on type
            results = {}
            
            if analysis_type == "Target Correlation":
                results = self._analyze_target_correlation()
            elif analysis_type == "Timeline Analysis":
                results = self._analyze_timeline()
            elif analysis_type == "Pattern Detection":
                results = self._detect_patterns()
            elif analysis_type == "Risk Assessment":
                results = self._assess_risk()
            elif analysis_type == "Sentiment Analysis":
                results = self._analyze_sentiment()
            
            # Update UI
            self.root.after(0, self._update_analytics_results, analysis_type, results)
            
            self.root.after(0, lambda: self.status_label.config(text=f"{analysis_type} complete"))
            
        except Exception as e:
            logger.error(f"Analytics error: {e}")
            self.root.after(0, lambda: self._show_error(f"Analytics failed: {str(e)}"))
        finally:
            self.root.after(0, self.progress_bar.stop)
    
    def _analyze_target_correlation(self):
        """Analyze target correlations"""
        try:
            # Get all targets
            targets = self.db.get_targets()
            
            # Find correlations
            correlations = []
            
            # Group by type and value patterns
            type_groups = {}
            for target in targets:
                ttype = target['type']
                value = target['value']
                
                if ttype not in type_groups:
                    type_groups[ttype] = []
                type_groups[ttype].append(value)
            
            # Find common patterns
            patterns = {}
            for ttype, values in type_groups.items():
                if len(values) > 1:
                    # Look for common substrings in values
                    for i in range(len(values)):
                        for j in range(i + 1, len(values)):
                            # Find common words or patterns
                            words_i = set(re.findall(r'\b\w+\b', values[i].lower()))
                            words_j = set(re.findall(r'\b\w+\b', values[j].lower()))
                            common = words_i.intersection(words_j)
                            
                            if common and len(common) > 1:
                                pattern_key = ', '.join(sorted(common))
                                if pattern_key not in patterns:
                                    patterns[pattern_key] = []
                                patterns[pattern_key].extend([values[i], values[j]])
            
            return {
                'total_targets': len(targets),
                'type_distribution': {k: len(v) for k, v in type_groups.items()},
                'patterns_found': len(patterns),
                'patterns': patterns
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_timeline(self):
        """Analyze timeline of events"""
        try:
            # Get all targets with timestamps
            targets = self.db.get_targets()
            
            # Extract dates
            dates = []
            for target in targets:
                if target['first_seen']:
                    dates.append(target['first_seen'])
                if target['last_seen']:
                    dates.append(target['last_seen'])
            
            # Analyze timeline
            if dates:
                # Convert to datetime
                date_objs = []
                for date_str in dates:
                    try:
                        if isinstance(date_str, str):
                            # Handle different date formats
                            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
                                try:
                                    dt = datetime.strptime(date_str, fmt)
                                    break
                                except ValueError:
                                    continue
                            else:
                                continue
                        else:
                            dt = datetime.fromtimestamp(date_str)
                        date_objs.append(dt)
                    except Exception:
                        continue
                
                if date_objs:
                    date_objs.sort()
                    
                    return {
                        'earliest': min(date_objs).isoformat(),
                        'latest': max(date_objs).isoformat(),
                        'total_events': len(date_objs),
                        'date_range_days': (max(date_objs) - min(date_objs)).days,
                        'activity_by_month': self._group_by_month(date_objs)
                    }
            
            return {'message': 'No timeline data available'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _group_by_month(self, dates):
        """Group dates by month"""
        months = {}
        for date in dates:
            month_key = date.strftime('%Y-%m')
            months[month_key] = months.get(month_key, 0) + 1
        return months
    
    def _detect_patterns(self):
        """Detect patterns in data"""
        try:
            # Get all targets
            targets = self.db.get_targets()
            
            patterns = {
                'email_patterns': [],
                'ip_patterns': [],
                'username_patterns': []
            }
            
            for target in targets:
                value = target['value']
                ttype = target['type']
                
                if ttype == 'email':
                    # Extract username from email
                    if '@' in value:
                        username = value.split('@')[0]
                        patterns['email_patterns'].append({
                            'email': value,
                            'username': username,
                            'length': len(username),
                            'has_numbers': any(c.isdigit() for c in username),
                            'has_special': any(not c.isalnum() for c in username)
                        })
                
                elif ttype == 'ip':
                    # Check IP patterns
                    try:
                        ip = ipaddress.ip_address(value)
                        patterns['ip_patterns'].append({
                            'ip': value,
                            'version': ip.version,
                            'is_private': ip.is_private,
                            'octets': value.split('.') if ip.version == 4 else []
                        })
                    except Exception:
                        pass
                
                elif ttype == 'social':
                    # Analyze usernames
                    patterns['username_patterns'].append({
                        'username': value,
                        'length': len(value),
                        'has_numbers': any(c.isdigit() for c in value),
                        'has_underscore': '_' in value,
                        'has_dash': '-' in value
                    })
            
            # Count patterns
            pattern_counts = {}
            for pattern_type, items in patterns.items():
                if items:
                    pattern_counts[pattern_type] = len(items)
                    
                    # Find common characteristics
                    if pattern_type == 'username_patterns':
                        avg_length = sum(item['length'] for item in items) / len(items)
                        with_numbers = sum(1 for item in items if item['has_numbers'])
                        pattern_counts[f'{pattern_type}_avg_length'] = round(avg_length, 2)
                        pattern_counts[f'{pattern_type}_with_numbers'] = with_numbers
            
            return pattern_counts
            
        except Exception as e:
            return {'error': str(e)}
    
    def _assess_risk(self):
        """Assess risk of targets"""
        try:
            # Get all targets
            targets = self.db.get_targets()
            
            risk_scores = {
                'low': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            }
            
            risk_factors = []
            
            for target in targets:
                score = 0
                factors = []
                
                # Score based on type
                if target['type'] == 'ip':
                    # Check if IP has threat data
                    ip_data = self.db.get_ip_data(target['value'])
                    if ip_data:
                        threat_score = ip_data.get('threat_score', 0)
                        if threat_score > 70:
                            score += 3
                            factors.append('High threat score')
                        elif threat_score > 30:
                            score += 2
                            factors.append('Moderate threat score')
                        
                        abuse_reports = ip_data.get('abuse_reports', 0)
                        if abuse_reports > 10:
                            score += 2
                            factors.append('Multiple abuse reports')
                
                elif target['type'] == 'email':
                    # Add email-specific risk factors
                    if '@' in target['value']:
                        domain = target['value'].split('@')[1]
                        if domain in ['tempmail.com', 'mailinator.com']:
                            score += 2
                            factors.append('Disposable email')
                
                # Score based on confidence
                confidence = target.get('confidence', 50)
                if confidence > 80:
                    score += 1
                elif confidence < 30:
                    score += 1  # Low confidence is also a risk
                
                # Categorize risk
                if score >= 5:
                    risk_level = 'critical'
                elif score >= 3:
                    risk_level = 'high'
                elif score >= 2:
                    risk_level = 'medium'
                else:
                    risk_level = 'low'
                
                risk_scores[risk_level] += 1
                
                if factors:
                    risk_factors.append({
                        'target': target['value'],
                        'type': target['type'],
                        'score': score,
                        'level': risk_level,
                        'factors': factors
                    })
            
            return {
                'risk_distribution': risk_scores,
                'total_targets': len(targets),
                'risk_factors': risk_factors[:10],  # Limit to first 10
                'overall_risk': self._calculate_overall_risk(risk_scores)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_overall_risk(self, risk_scores):
        """Calculate overall risk score"""
        total = sum(risk_scores.values())
        if total == 0:
            return 'low'
        
        # Weighted score
        weighted = (
            risk_scores['low'] * 1 +
            risk_scores['medium'] * 3 +
            risk_scores['high'] * 5 +
            risk_scores['critical'] * 10
        ) / total
        
        if weighted >= 7:
            return 'critical'
        elif weighted >= 5:
            return 'high'
        elif weighted >= 3:
            return 'medium'
        else:
            return 'low'
    
    def _analyze_sentiment(self):
        """Analyze sentiment in text data"""
        try:
            # Get text data from various sources
            texts = []
            
            # Check database for text fields
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT bio FROM social_profiles WHERE bio IS NOT NULL AND bio != ''")
            bios = cursor.fetchall()
            texts.extend([bio[0] for bio in bios])
            
            cursor.execute("SELECT notes FROM investigations WHERE notes IS NOT NULL AND notes != ''")
            notes = cursor.fetchall()
            texts.extend([note[0] for note in notes])
            
            # Analyze sentiment
            sentiments = []
            for text in texts:
                try:
                    blob = TextBlob(text)
                    sentiments.append({
                        'text': text[:100] + '...' if len(text) > 100 else text,
                        'polarity': blob.sentiment.polarity,
                        'subjectivity': blob.sentiment.subjectivity,
                        'sentiment': 'positive' if blob.sentiment.polarity > 0 else 
                                    'negative' if blob.sentiment.polarity < 0 else 'neutral'
                    })
                except Exception:
                    pass
            
            # Calculate overall sentiment
            if sentiments:
                avg_polarity = sum(s['polarity'] for s in sentiments) / len(sentiments)
                avg_subjectivity = sum(s['subjectivity'] for s in sentiments) / len(sentiments)
                
                overall = 'positive' if avg_polarity > 0.1 else \
                         'negative' if avg_polarity < -0.1 else 'neutral'
                
                return {
                    'total_texts': len(texts),
                    'analyzed': len(sentiments),
                    'avg_polarity': round(avg_polarity, 3),
                    'avg_subjectivity': round(avg_subjectivity, 3),
                    'overall_sentiment': overall,
                    'sample_sentiments': sentiments[:5]
                }
            
            return {'message': 'No text data available for sentiment analysis'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _update_analytics_results(self, analysis_type, results):
        """Update analytics results in UI"""
        result_text = f"""
=== {analysis_type} Results ===

Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        if 'error' in results:
            result_text += f"\nError: {results['error']}"
        elif 'message' in results:
            result_text += f"\n{results['message']}"
        else:
            # Format results based on analysis type
            if analysis_type == "Target Correlation":
                result_text += f"""
Total Targets: {results.get('total_targets', 'N/A')}

Type Distribution:
"""
                for ttype, count in results.get('type_distribution', {}).items():
                    result_text += f"  • {ttype}: {count}\n"
                
                if results.get('patterns'):
                    result_text += f"\nPatterns Found: {results.get('patterns_found', 0)}\n"
                    for pattern, values in list(results.get('patterns', {}).items())[:5]:
                        result_text += f"\nPattern: {pattern}\n"
                        for value in list(set(values))[:3]:  # Show first 3 unique values
                            result_text += f"  • {value}\n"
            
            elif analysis_type == "Timeline Analysis":
                result_text += f"""
Timeline Analysis:
• Earliest Event: {results.get('earliest', 'N/A')}
• Latest Event: {results.get('latest', 'N/A')}
• Total Events: {results.get('total_events', 'N/A')}
• Date Range: {results.get('date_range_days', 'N/A')} days

Activity by Month:
"""
                for month, count in results.get('activity_by_month', {}).items():
                    result_text += f"  • {month}: {count} events\n"
            
            elif analysis_type == "Pattern Detection":
                result_text += "\nDetected Patterns:\n"
                for key, value in results.items():
                    result_text += f"  • {key}: {value}\n"
            
            elif analysis_type == "Risk Assessment":
                result_text += f"""
Risk Assessment:

Overall Risk: {results.get('overall_risk', 'N/A').upper()}
Total Targets: {results.get('total_targets', 'N/A')}

Risk Distribution:
• Low: {results.get('risk_distribution', {}).get('low', 0)}
• Medium: {results.get('risk_distribution', {}).get('medium', 0)}
• High: {results.get('risk_distribution', {}).get('high', 0)}
• Critical: {results.get('risk_distribution', {}).get('critical', 0)}

Top Risk Factors:
"""
                for factor in results.get('risk_factors', [])[:5]:
                    result_text += f"\n• {factor.get('target', 'N/A')} ({factor.get('type', 'N/A')}):\n"
                    result_text += f"  Risk Level: {factor.get('level', 'N/A').upper()}\n"
                    result_text += f"  Factors: {', '.join(factor.get('factors', []))}\n"
            
            elif analysis_type == "Sentiment Analysis":
                result_text += f"""
Sentiment Analysis:

Total Texts: {results.get('total_texts', 'N/A')}
Analyzed: {results.get('analyzed', 'N/A')}
Average Polarity: {results.get('avg_polarity', 'N/A')}
Average Subjectivity: {results.get('avg_subjectivity', 'N/A')}
Overall Sentiment: {results.get('overall_sentiment', 'N/A').upper()}

Sample Sentiments:
"""
                for sentiment in results.get('sample_sentiments', [])[:3]:
                    result_text += f"\n• Text: {sentiment.get('text', 'N/A')}\n"
                    result_text += f"  Sentiment: {sentiment.get('sentiment', 'N/A').upper()}\n"
                    result_text += f"  Polarity: {sentiment.get('polarity', 'N/A')}\n"
        
        self.analytics_results_text.delete(1.0, 'end')
        self.analytics_results_text.insert(1.0, result_text)
    
    def generate_report_action(self):
        """Generate report"""
        report_type = self.report_type_var.get()
        content_type = self.report_content_var.get()
        
        self.status_label.config(text=f"Generating {report_type} report...")
        self.progress_bar.start()
        
        thread = threading.Thread(target=self._generate_report_thread, args=(report_type, content_type))
        thread.daemon = True
        thread.start()
    
    def _generate_report_thread(self, report_type, content_type):
        """Thread function for report generation"""
        try:
            # Prepare data based on content type
            data = self._prepare_report_data(content_type)
            
            # Generate report
            os.makedirs("data/reports", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if report_type == "HTML":
                filename = f"data/reports/report_{timestamp}.html"
                success = self.report_generator.generate_html_report(data, filename)
                report_content = f"HTML report generated: {filename}\n\nOpen file to view report."
                
            elif report_type == "CSV":
                filename = f"data/reports/report_{timestamp}.csv"
                success = self.report_generator.generate_csv_report(data, filename)
                report_content = f"CSV report generated: {filename}"
            
            # Update UI
            if success:
                self.root.after(0, self.report_preview_text.delete, 1.0, 'end')
                self.root.after(0, self.report_preview_text.insert, 1.0, report_content)
                
                # Ask if user wants to open the report
                self.root.after(0, self._ask_open_report, filename)
            
            self.root.after(0, lambda: self.status_label.config(text="Report generation complete"))
            
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            self.root.after(0, lambda: self._show_error(f"Report generation failed: {str(e)}"))
        finally:
            self.root.after(0, self.progress_bar.stop)
    
    def _prepare_report_data(self, content_type):
        """Prepare data for report"""
        data = {
            'report_type': content_type,
            'generated_at': datetime.now().isoformat(),
            'summary': {}
        }
        
        if content_type == "Current Analysis":
            # Get data from current tabs
            data['current_data'] = {
                'ip_analysis': {},
                'domain_analysis': {},
                'email_analysis': {}
            }
            
        elif content_type == "All Investigations":
            # Get all investigations
            investigations = self.db.get_investigations()
            data['investigations'] = [
                {
                    'id': inv['id'],
                    'name': inv['name'],
                    'created_at': inv['created_at'],
                    'status': inv['status']
                }
                for inv in investigations
            ]
            data['summary']['total_investigations'] = len(investigations)
            
        elif content_type == "Selected Targets":
            # Get targets from current investigation
            if self.current_investigation:
                targets = self.db.get_targets(self.current_investigation)
                data['targets'] = [
                    {
                        'type': t['type'],
                        'value': t['value'],
                        'first_seen': t['first_seen'],
                        'last_seen': t['last_seen']
                    }
                    for t in targets
                ]
                data['summary']['total_targets'] = len(targets)
        
        return data
    
    def _ask_open_report(self, filename):
        """Ask user if they want to open the report"""
        if messagebox.askyesno("Report Generated", f"Report saved to {filename}\n\nDo you want to open it?"):
            try:
                if sys.platform == 'win32':
                    os.startfile(filename)
                elif sys.platform == 'darwin':
                    subprocess.run(['open', filename])
                else:
                    subprocess.run(['xdg-open', filename])
            except Exception as e:
                logger.error(f"Failed to open report: {e}")
    
    def save_settings(self):
        """Save application settings"""
        try:
            # Update config
            config = configparser.ConfigParser()
            
            config['API'] = {
                'virustotal': self.api_virustotal.get(),
                'abuseipdb': self.api_abuseipdb.get(),
                'hunterio': self.api_hunterio.get(),
                'ipinfo': self.api_ipinfo.get()
            }
            
            config['Settings'] = {
                'use_proxy': str(self.setting_proxy.get()),
                'max_threads': str(self.setting_max_threads.get())
            }
            
            # Write config file
            with open('config.ini', 'w') as f:
                config.write(f)
            
            # Update analyzers with new API keys
            self.analyzers['ip'].api_keys = {
                'virustotal': self.api_virustotal.get(),
                'abuseipdb': self.api_abuseipdb.get(),
                'ipinfo': self.api_ipinfo.get()
            }
            
            self.analyzers['email'].api_keys = {
                'hunterio': self.api_hunterio.get()
            }
            
            self.status_label.config(text="Settings saved successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def load_settings(self):
        """Load application settings"""
        try:
            config = configparser.ConfigParser()
            config.read('config.ini')
            
            if 'API' in config:
                self.api_virustotal.delete(0, 'end')
                self.api_virustotal.insert(0, config['API'].get('virustotal', ''))
                
                self.api_abuseipdb.delete(0, 'end')
                self.api_abuseipdb.insert(0, config['API'].get('abuseipdb', ''))
                
                self.api_hunterio.delete(0, 'end')
                self.api_hunterio.insert(0, config['API'].get('hunterio', ''))
                
                self.api_ipinfo.delete(0, 'end')
                self.api_ipinfo.insert(0, config['API'].get('ipinfo', ''))
            
            if 'Settings' in config:
                self.setting_proxy.set(config['Settings'].getboolean('use_proxy', False))
                self.setting_max_threads.set(int(config['Settings'].get('max_threads', '10')))
            
            self.status_label.config(text="Settings loaded successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load settings: {str(e)}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        if messagebox.askyesno("Reset Settings", "Are you sure you want to reset all settings to defaults?"):
            self.api_virustotal.delete(0, 'end')
            self.api_abuseipdb.delete(0, 'end')
            self.api_hunterio.delete(0, 'end')
            self.api_ipinfo.delete(0, 'end')
            
            self.setting_proxy.set(False)
            self.setting_auto_save.set(True)
            self.setting_max_threads.set(10)
            
            self.status_label.config(text="Settings reset to defaults")
    
    def new_investigation(self):
        """Create new investigation"""
        name = simpledialog.askstring("New Investigation", "Enter investigation name:")
        
        if name:
            try:
                investigation_id = self.db.add_investigation(name)
                self.current_investigation = investigation_id
                self.status_label.config(text=f"Created investigation: {name}")
                self.load_dashboard_data()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create investigation: {str(e)}")
    
    def open_investigation(self):
        """Open existing investigation"""
        investigations = self.db.get_investigations()
        
        if not investigations:
            messagebox.showinfo("No Investigations", "No investigations found.")
            return
        
        items = [f"{inv['id']}: {inv['name']} ({inv['created_at']})" for inv in investigations]
        
        selected = simpledialog.askstring("Open Investigation", "Enter investigation ID or select from list:\n" + "\n".join(items))
        
        if selected:
            try:
                # Try to extract ID
                if ':' in selected:
                    investigation_id = int(selected.split(':')[0])
                else:
                    investigation_id = int(selected)
                
                self.current_investigation = investigation_id
                self.status_label.config(text=f"Opened investigation: {selected}")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid investigation selection: {e}")
    
    def export_data(self):
        """Export data"""
        formats = ["CSV", "JSON", "HTML"]
        
        format_choice = simpledialog.askstring("Export Data", "Select export format (CSV, JSON, HTML):")
        
        if format_choice and format_choice.upper() in formats:
            filename = filedialog.asksaveasfilename(
                title="Export Data",
                defaultextension=f".{format_choice.lower()}",
                filetypes=[(f"{format_choice} Files", f"*.{format_choice.lower()}")]
            )
            
            if filename:
                self._export_data_to_file(filename, format_choice)
    
    def _export_data_to_file(self, filename, format_choice):
        """Export data to file"""
        try:
            if format_choice.upper() == "CSV":
                self._export_to_csv(filename)
            elif format_choice.upper() == "JSON":
                self._export_to_json(filename)
            elif format_choice.upper() == "HTML":
                self._export_to_html(filename)
            
            self.status_label.config(text=f"Data exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")
    
    def _export_to_csv(self, filename):
        """Export data to CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write investigations
            writer.writerow(['Investigations'])
            writer.writerow(['ID', 'Name', 'Created', 'Status'])
            
            investigations = self.db.get_investigations()
            for inv in investigations:
                writer.writerow([inv['id'], inv['name'], inv['created_at'], inv['status']])
            
            writer.writerow([])
            
            # Write targets
            writer.writerow(['Targets'])
            writer.writerow(['Type', 'Value', 'First Seen', 'Last Seen'])
            
            targets = self.db.get_targets()
            for target in targets:
                writer.writerow([target['type'], target['value'], target['first_seen'], target['last_seen']])
    
    def _export_to_json(self, filename):
        """Export data to JSON"""
        data = {
            'export_date': datetime.now().isoformat(),
            'investigations': [],
            'targets': []
        }
        
        # Add investigations
        investigations = self.db.get_investigations()
        for inv in investigations:
            data['investigations'].append(dict(inv))
        
        # Add targets
        targets = self.db.get_targets()
        for target in targets:
            data['targets'].append(dict(target))
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _export_to_html(self, filename):
        """Export data to HTML"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OSINT Data Export</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #2c3e50; }
                h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th { background: #34495e; color: white; padding: 10px; text-align: left; }
                td { padding: 10px; border-bottom: 1px solid #ddd; }
                tr:nth-child(even) { background: #f9f9f9; }
                .timestamp { color: #7f8c8d; font-size: 12px; }
            </style>
        </head>
        <body>
            <h1>OSINT Data Export</h1>
            <p class="timestamp">Exported: {timestamp}</p>
        """
        
        # Add investigations table
        investigations = self.db.get_investigations()
        if investigations:
            html += "<h2>Investigations</h2>"
            html += "<table>"
            html += "<tr><th>ID</th><th>Name</th><th>Created</th><th>Status</th></tr>"
            
            for inv in investigations:
                html += f"""
                <tr>
                    <td>{inv['id']}</td>
                    <td>{inv['name']}</td>
                    <td>{inv['created_at']}</td>
                    <td>{inv['status']}</td>
                </tr>
                """
            
            html += "</table>"
        
        # Add targets table
        targets = self.db.get_targets()
        if targets:
            html += "<h2>Targets</h2>"
            html += "<table>"
            html += "<tr><th>Type</th><th>Value</th><th>First Seen</th><th>Last Seen</th></tr>"
            
            for target in targets:
                html += f"""
                <tr>
                    <td>{target['type']}</td>
                    <td>{target['value']}</td>
                    <td>{target['first_seen']}</td>
                    <td>{target['last_seen']}</td>
                </tr>
                """
            
            html += "</table>"
        
        html += """
        </body>
        </html>
        """
        
        html = html.replace("{timestamp}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def quick_analyze(self):
        """Quick analyze based on current tab"""
        current_tab = self.notebook.index(self.notebook.select())
        
        if current_tab == 1:  # IP Analyzer
            self.analyze_ip_action()
        elif current_tab == 2:  # Domain Analyzer
            self.analyze_domain_action()
        elif current_tab == 3:  # Email Analyzer
            self.analyze_email_action()
        elif current_tab == 4:  # Social Media
            self.analyze_social_action()
        elif current_tab == 5:  # Network Scanner
            self.scan_network_action()
        elif current_tab == 6:  # Image Analyzer
            self.analyze_image_action()
    
    def quick_report(self):
        """Quick report generation"""
        self.notebook.select(9)  # Reporting tab
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        OSINT Analytics Suite v3.0
        
        A comprehensive Open Source Intelligence collection and analysis tool.
        
        Features:
        • IP Address Analysis & Geolocation
        • Domain Intelligence & WHOIS Lookup
        • Email Verification & Breach Checking
        • Social Media Profile Search
        • Network Port Scanning
        • Image Metadata Analysis
        • Geolocation Tracking & Mapping
        • Advanced Data Analytics
        • Report Generation (HTML/CSV)
        
        Disclaimer:
        This tool is for legitimate OSINT purposes only.
        Always ensure you have proper authorization for investigations.
        
        Version: 3.0.0
        License: MIT
        Author: OSINT Development Team
        """
        
        messagebox.showinfo("About OSINT Analytics Suite", about_text)
    
    def show_documentation(self):
        """Show documentation"""
        doc_text = """
        OSINT Analytics Suite Documentation
        
        Getting Started:
        1. Create a new investigation from File → New Investigation
        2. Use the various tabs to analyze different types of targets
        3. Save results to the current investigation
        4. Generate reports from the Reporting tab
        
        Features Guide:
        
        IP Analyzer:
        • Enter IP address and click Analyze
        • View geolocation, threat intelligence, and port scan results
        
        Domain Analyzer:
        • Enter domain name and click Analyze
        • View WHOIS information, DNS records, and SSL certificate details
        • Discover subdomains and check HTTP headers
        
        Email Analyzer:
        • Enter email address and click Analyze
        • Check email validity and breach status
        • Find associated social media profiles
        
        Social Media:
        • Enter username and click Search
        • Check availability across multiple platforms
        
        API Keys:
        For enhanced features, obtain API keys from:
        • VirusTotal: https://virustotal.com
        • AbuseIPDB: https://abuseipdb.com
        • Hunter.io: https://hunter.io
        • IPinfo.io: https://ipinfo.io
        
        Tips:
        • Always create an investigation first to organize your work
        • Use bulk import for analyzing multiple targets
        • Configure API keys in Settings for enhanced features
        • Export reports regularly to document findings
        """
        
        # Create documentation window
        doc_window = Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("600x700")
        
        text_widget = scrolledtext.ScrolledText(doc_window, wrap='word', padx=10, pady=10)
        text_widget.insert(1.0, doc_text)
        text_widget.config(state='disabled')
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        Button(doc_window, text="Close", command=doc_window.destroy).pack(pady=10)
    
    def bulk_import_ips(self):
        """Bulk import IPs from file"""
        filename = filedialog.askopenfilename(
            title="Import IPs",
            filetypes=[
                ("Text Files", "*.txt"),
                ("CSV Files", "*.csv"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    ips = []
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Try to extract IPs from the line
                            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                            found_ips = re.findall(ip_pattern, line)
                            ips.extend(found_ips)
                
                if ips:
                    # Ask how to handle the IPs
                    if messagebox.askyesno("Import IPs", f"Found {len(ips)} IP addresses. Analyze them now?"):
                        self._analyze_bulk_ips(ips)
                else:
                    messagebox.showinfo("No IPs Found", "No valid IP addresses found in the file.")
                    
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import IPs: {str(e)}")
    
    def _analyze_bulk_ips(self, ips):
        """Analyze multiple IPs"""
        self.progress_bar.config(maximum=len(ips), value=0)
        
        # Create results window
        results_window = Toplevel(self.root)
        results_window.title("Bulk IP Analysis Results")
        results_window.geometry("800x600")
        
        text_widget = scrolledtext.ScrolledText(results_window, wrap='word')
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        Button(results_window, text="Close", command=results_window.destroy).pack(pady=10)
        
        # Analyze IPs in thread
        thread = threading.Thread(target=self._analyze_bulk_ips_thread, args=(ips, text_widget))
        thread.daemon = True
        thread.start()
    
    def _analyze_bulk_ips_thread(self, ips, text_widget):
        """Thread function for bulk IP analysis"""
        results = []
        
        for i, ip in enumerate(ips):
            try:
                analyzer = self.analyzers['ip']
                geo = analyzer.get_geolocation(ip)
                
                result = {
                    'ip': ip,
                    'country': geo.get('country', 'Unknown'),
                    'city': geo.get('city', 'Unknown'),
                    'isp': geo.get('isp', 'Unknown'),
                    'threats': analyzer.basic_threat_checks(ip)
                }
                
                results.append(result)
                
                # Update progress
                self.root.after(0, self.progress_bar.config, {'value': i + 1})
                
                # Update results window
                text = f"Analyzed {i + 1}/{len(ips)} IPs\n\n"
                text += "Results:\n"
                for r in results[-min(10, len(results)):]:  # Show last 10 results
                    text += f"{r['ip']}: {r['country']}, {r['city']} ({r['isp']})\n"
                
                self.root.after(0, text_widget.delete, 1.0, 'end')
                self.root.after(0, text_widget.insert, 1.0, text)
                
            except Exception as e:
                logger.error(f"Bulk IP analysis error for {ip}: {e}")
        
        # Final update
        final_text = f"Analysis Complete\n\n"
        final_text += f"Total IPs analyzed: {len(results)}\n"
        final_text += f"Countries found: {len(set(r['country'] for r in results))}\n\n"
        
        # Group by country
        country_counts = {}
        for r in results:
            country = r['country']
            country_counts[country] = country_counts.get(country, 0) + 1
        
        final_text += "By Country:\n"
        for country, count in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            final_text += f"  {country}: {count}\n"
        
        self.root.after(0, text_widget.delete, 1.0, 'end')
        self.root.after(0, text_widget.insert, 1.0, final_text)
        
        self.root.after(0, self.progress_bar.config, {'value': 0})
    
    def _show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message)
    
    def on_closing(self):
        """Handle application close"""
        try:
            self.db.close()
            logger.info("Application closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
        
        self.root.quit()

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

def main():
    """Main application entry point"""
    root = Tk()
    
    # Create splash screen
    splash = Toplevel(root)
    splash.title("OSINT Analytics Suite")
    splash.geometry("400x200")
    
    Label(splash, text="OSINT Analytics Suite", font=('Arial', 20, 'bold')).pack(pady=20)
    Label(splash, text="Initializing...").pack(pady=10)
    
    progress = ttk.Progressbar(splash, mode='indeterminate', length=300)
    progress.pack(pady=20)
    progress.start()
    
    splash.update()
    
    # Create main application
    app = OSINTApp(root)
    
    # Set close handler
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Destroy splash screen
    splash.destroy()
    
    # Start main loop
    root.mainloop()

if __name__ == "__main__":
    main()
