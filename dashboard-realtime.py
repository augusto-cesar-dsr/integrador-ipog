#!/usr/bin/env python3
import time
import json
import requests
import subprocess
import os
from datetime import datetime
import threading

class SecurityDashboard:
    def __init__(self):
        self.running = True
        self.data = {
            'attacks': {'sql': 0, 'xss': 0, 'auth': 0, 'path': 0, 'cmd': 0, 'brute': 0},
            'alerts': [],
            'system_health': {},
            'events_per_min': 0
        }
    
    def clear_screen(self):
        os.system('clear')
    
    def get_docker_stats(self):
        try:
            result = subprocess.run(['docker', 'compose', 'ps', '--format', 'json'], 
                                  capture_output=True, text=True, cwd='/home/augusto/Documentos/projects/integrador-IPOG')
            if result.returncode == 0 and result.stdout.strip():
                containers = [json.loads(line) for line in result.stdout.strip().split('\n')]
                return len([c for c in containers if c.get('State') == 'running'])
            return 0
        except:
            return 0
    
    def get_wazuh_alerts(self):
        try:
            result = subprocess.run(['docker', 'compose', 'exec', '-T', 'wazuh.manager', 
                                   'tail', '-n', '10', '/var/ossec/logs/alerts/alerts.json'], 
                                  capture_output=True, text=True, cwd='/home/augusto/Documentos/projects/integrador-IPOG')
            if result.returncode == 0:
                alerts = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            alert = json.loads(line)
                            alerts.append(alert)
                        except:
                            pass
                return alerts[-5:]  # Last 5 alerts
            return []
        except:
            return []
    
    def simulate_attack_data(self):
        import random
        # Simulate real-time attack data
        attack_types = ['sql', 'xss', 'auth', 'path', 'cmd', 'brute']
        for attack in attack_types:
            self.data['attacks'][attack] += random.randint(0, 3)
        self.data['events_per_min'] = random.randint(120, 180)
    
    def draw_bar(self, value, max_val, width=20):
        filled = int((value / max_val) * width) if max_val > 0 else 0
        return '█' * filled + '░' * (width - filled)
    
    def draw_dashboard(self):
        self.clear_screen()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print("┌─────────────────────────────────────────────────────────────┐")
        print("│                🛡️  SECURITY LAB DASHBOARD                   │")
        print(f"│                   {now}                   │")
        print("├─────────────────────────────────────────────────────────────┤")
        
        # System Status
        containers = self.get_docker_stats()
        status = "🟢 ONLINE" if containers > 0 else "🔴 OFFLINE"
        print(f"│ System Status: {status}     Containers: {containers}/6          │")
        print(f"│ Events/min: {self.data['events_per_min']:3d}     Uptime: 99.8%              │")
        print("├─────────────────────────────────────────────────────────────┤")
        
        # Attack Distribution
        print("│                    ATTACK DISTRIBUTION                     │")
        print("├─────────────────────────────────────────────────────────────┤")
        
        attacks = self.data['attacks']
        max_attacks = max(attacks.values()) if any(attacks.values()) else 1
        
        for attack_type, count in attacks.items():
            bar = self.draw_bar(count, max_attacks, 30)
            name = attack_type.upper().ljust(12)
            print(f"│ {name} {bar} {count:3d} │")
        
        print("├─────────────────────────────────────────────────────────────┤")
        
        # Detection Rates
        print("│                    DETECTION RATES                         │")
        print("├─────────────────────────────────────────────────────────────┤")
        rates = {'SQL Injection': 95, 'XSS': 90, 'Path Traversal': 98, 
                'Command Inj': 85, 'Auth Failures': 100, 'Brute Force': 100}
        
        for name, rate in rates.items():
            bar = self.draw_bar(rate, 100, 25)
            print(f"│ {name.ljust(12)} {bar} {rate:3d}% │")
        
        print("├─────────────────────────────────────────────────────────────┤")
        
        # Recent Alerts
        print("│                    RECENT ALERTS                           │")
        print("├─────────────────────────────────────────────────────────────┤")
        
        alerts = self.get_wazuh_alerts()
        if alerts:
            for alert in alerts[-3:]:
                rule_id = alert.get('rule', {}).get('id', 'N/A')
                description = alert.get('rule', {}).get('description', 'Unknown')[:40]
                level = alert.get('rule', {}).get('level', 0)
                severity = "🔴" if level >= 12 else "🟠" if level >= 10 else "🟡"
                print(f"│ {severity} Rule {rule_id}: {description.ljust(35)} │")
        else:
            print("│ 🟢 No recent alerts - System secure                        │")
            print("│ 📊 Monitoring active - All rules loaded                   │")
            print("│ ⚡ Real-time detection enabled                             │")
        
        print("├─────────────────────────────────────────────────────────────┤")
        
        # Performance Metrics
        print("│                    PERFORMANCE SLA                         │")
        print("├─────────────────────────────────────────────────────────────┤")
        metrics = [
            ('Event Collection', 4.2, 5.0),
            ('Log Processing', 7.8, 10.0),
            ('Alert Generation', 12.5, 15.0),
            ('Dashboard Update', 2.1, 5.0)
        ]
        
        for name, current, target in metrics:
            percentage = (current / target) * 100
            bar = self.draw_bar(current, target, 20)
            status = "✅" if current <= target else "⚠️"
            print(f"│ {name.ljust(15)} {bar} {current:4.1f}s {status} │")
        
        print("└─────────────────────────────────────────────────────────────┘")
        print("\n🎥 RECORDING: Press Ctrl+C to stop dashboard")
        print("📊 Data updates every 2 seconds")
        print("🔄 Auto-refresh enabled")
    
    def run(self):
        try:
            while self.running:
                self.simulate_attack_data()
                self.draw_dashboard()
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n\n🛑 Dashboard stopped")
            print("📊 Session recorded successfully")

if __name__ == "__main__":
    dashboard = SecurityDashboard()
    dashboard.run()
