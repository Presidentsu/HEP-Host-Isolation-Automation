#!/usr/bin/env python3
"""
HEP-Infinity Events Automation Script
Monitors Harmony Endpoint forensics logs and triggers host isolation when threats detected
"""

import requests
import json
import time
import datetime
import re
import sys
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

# Configure logging with file output
def setup_logging():
    """Setup logging to both console and file"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"hep_automation_{timestamp}.log"
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # File handler
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, console_handler])
    
    return log_filename

logger = logging.getLogger(__name__)

@dataclass
class Config:
    """Configuration class for the automation script"""
    infinity_client_id: str
    infinity_secret_key: str
    hep_client_id: str
    hep_secret_key: str
    infinity_gateway: str
    hep_gateway: str
    automation_mode: bool
    time_window_hours: Optional[int]
    custom_timeframe: Optional[Dict]
    recurring: bool
    interval_hours: Optional[int]
    use_system_scheduler: bool
    filter_query: str
    approval_required: bool

@dataclass
class ExecutionSummary:
    """Summary of script execution for reporting"""
    start_time: str
    end_time: str
    alerts_found: int
    unique_machines: int
    machines_selected: int
    isolation_successful: bool
    isolation_job_id: str
    errors: List[str]
    machines_processed: List[Dict]

class InfinityEventsAPI:
    """Handler for Infinity Events API operations"""
    
    def __init__(self, client_id: str, secret_key: str, gateway: str):
        self.client_id = client_id
        self.secret_key = secret_key
        self.gateway = gateway
        self.token = None
        self.base_url = f"{gateway}/app/laas-logs-api/api"
        
    def authenticate(self) -> bool:
        """Authenticate with Infinity Portal"""
        auth_url = f"{self.gateway}/auth/external"
        payload = {
            "clientId": self.client_id,
            "accessKey": self.secret_key
        }
        
        try:
            response = requests.post(auth_url, json=payload)
            if response.status_code == 200:
                self.token = response.json()["data"]["token"]
                logger.info("Infinity Events authentication successful")
                return True
            else:
                logger.error(f"Authentication failed: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def search_logs(self, filter_query: str, timeframe: Dict) -> Optional[str]:
        """Create a search task for forensics logs"""
        if not self.token:
            logger.error("Not authenticated")
            return None
            
        url = f"{self.base_url}/logs_query"
        headers = {"Authorization": f"Bearer {self.token}"}
        
        payload = {
            "filter": filter_query,
            "limit": 1000,
            "pageLimit": 100,
            "timeframe": timeframe
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                task_id = response.json()["data"]["taskId"]
                logger.info(f"Search task created: {task_id}")
                return task_id
            else:
                logger.error(f"Search failed: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Search error: {e}")
            return None
    
    def check_task_status(self, task_id: str) -> Optional[Dict]:
        """Check the status of a search task"""
        url = f"{self.base_url}/logs_query/{task_id}"
        headers = {"Authorization": f"Bearer {self.token}"}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()["data"]
            else:
                logger.error(f"Status check failed: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Status check error: {e}")
            return None
    
    def retrieve_logs(self, task_id: str, page_token: str) -> Optional[Dict]:
        """Retrieve logs from a specific page"""
        url = f"{self.base_url}/logs_query/retrieve"
        headers = {"Authorization": f"Bearer {self.token}"}
        
        payload = {
            "taskId": task_id,
            "pageToken": page_token
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                return response.json()["data"]
            else:
                logger.error(f"Retrieve failed: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Retrieve error: {e}")
            return None

class HarmonyEndpointAPI:
    """Handler for Harmony Endpoint API operations"""
    
    def __init__(self, client_id: str, secret_key: str, gateway: str):
        self.client_id = client_id
        self.secret_key = secret_key
        self.gateway = gateway
        self.ci_token = None
        self.api_token = None
        
    def authenticate(self) -> bool:
        """Two-step authentication for HEP"""
        # Step 1: Get CloudInfra token
        auth_url = f"{self.gateway}/auth/external"
        payload = {
            "clientId": self.client_id,
            "accessKey": self.secret_key
        }
        
        try:
            response = requests.post(auth_url, json=payload)
            if response.status_code == 200:
                self.ci_token = response.json()["data"]["token"]
                logger.info("HEP CloudInfra authentication successful")
            else:
                logger.error(f"HEP CI authentication failed: {response.text}")
                return False
        except Exception as e:
            logger.error(f"HEP CI authentication error: {e}")
            return False
        
        # Step 2: Get API session token
        login_url = f"{self.gateway}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/session/login/cloud"
        headers = {"Authorization": f"Bearer {self.ci_token}"}
        
        try:
            response = requests.post(login_url, headers=headers)
            if response.status_code == 201:
                self.api_token = response.json()["apiToken"]
                logger.info("HEP API session created")
                return True
            else:
                logger.error(f"HEP API login failed: {response.text}")
                return False
        except Exception as e:
            logger.error(f"HEP API login error: {e}")
            return False
    
    def get_computer_id_by_hostname(self, hostname: str) -> Optional[str]:
        """Get computer ID from hostname using asset management API"""
        url = f"{self.gateway}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/asset-management/computers/filtered"
        headers = {
            "Authorization": f"Bearer {self.ci_token}",
            "x-mgmt-api-token": self.api_token,
            "x-mgmt-run-as-job": "on"
        }
        
        payload = {
            "filters": [
                {
                    "columnName": "computerName",
                    "filterValues": [hostname],
                    "filterType": "Exact"
                }
            ],
            "paging": {"pageSize": 10, "offset": 0}
        }
        
        logger.info(f"Looking up computer ID for hostname: {hostname}")
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            logger.info(f"Asset lookup response status: {response.status_code}")
            logger.info(f"Asset lookup response: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                if 'jobId' in data:
                    return self._wait_for_asset_job(data['jobId'], hostname)
                else:
                    computers = data.get('computers', [])
                    if computers:
                        computer_id = computers[0]['computerId']
                        logger.info(f"Found computer ID {computer_id} for hostname {hostname}")
                        return computer_id
                    else:
                        logger.warning(f"No computer found for hostname: {hostname}")
                        return None
            else:
                logger.error(f"Asset lookup failed for {hostname}: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error getting computer ID for {hostname}: {e}")
            return None
    
    def _wait_for_asset_job(self, job_id: str, hostname: str) -> Optional[str]:
        """Wait for asset management job completion"""
        job_url = f"{self.gateway}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/jobs/{job_id}"
        headers = {
            "Authorization": f"Bearer {self.ci_token}",
            "x-mgmt-api-token": self.api_token
        }
        
        for attempt in range(30):
            try:
                response = requests.get(job_url, headers=headers)
                if response.status_code == 200:
                    job_data = response.json()
                    status = job_data.get('status')
                    
                    if status == 'DONE':
                        computers = job_data.get('data', {}).get('computers', [])
                        if computers:
                            computer_id = computers[0]['computerId']
                            logger.info(f"Found computer ID {computer_id} for hostname {hostname}")
                            return computer_id
                        else:
                            logger.warning(f"No computer found for hostname: {hostname}")
                            return None
                    elif status == 'FAILED':
                        logger.error(f"Asset lookup job failed for {hostname}")
                        return None
                    
                    logger.info(f"Asset lookup job in progress for {hostname}...")
                    time.sleep(2)
                else:
                    logger.error(f"Failed to check job status: {response.text}")
                    return None
            except Exception as e:
                logger.error(f"Error checking asset job: {e}")
                return None
        
        logger.error(f"Asset lookup job timed out for {hostname}")
        return None
    
    def check_isolation_job_status(self, job_id: str) -> Dict:
        """Check isolation job status"""
        job_url = f"{self.gateway}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/remediation/{job_id}/status"
        headers = {
            "Authorization": f"Bearer {self.ci_token}",
            "x-mgmt-api-token": self.api_token,
            "x-mgmt-run-as-job": "on"
        }
        
        try:
            response = requests.get(job_url, headers=headers)
            logger.info(f"Job status check response: {response.status_code}")
            logger.info(f"Job status response: {response.text}")
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to check job status: {response.text}")
                return {}
        except Exception as e:
            logger.error(f"Error checking job status: {e}")
            return {}
    
    def check_isolation_status(self, computer_ids: List[str]) -> Dict[str, str]:
        """Check current isolation status of computers"""
        if not computer_ids:
            return {}
            
        url = f"{self.gateway}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/asset-management/computers/filtered"
        headers = {
            "Authorization": f"Bearer {self.ci_token}",
            "x-mgmt-api-token": self.api_token,
            "x-mgmt-run-as-job": "on"
        }
        
        payload = {
            "filters": [
                {
                    "columnName": "computerId",
                    "filterValues": computer_ids,
                    "filterType": "Exact"
                }
            ],
            "paging": {"pageSize": min(len(computer_ids), 50), "offset": 0}
        }
        
        logger.info(f"Checking isolation status for {len(computer_ids)} computers")
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            logger.info(f"Isolation status check response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                
                # Handle job response
                if 'jobId' in data:
                    return self._wait_for_isolation_status_job(data['jobId'], computer_ids)
                else:
                    computers = data.get('computers', [])
                    status_map = {}
                    for computer in computers:
                        computer_id = computer.get('computerId')
                        isolation_status = computer.get('isolationStatus', 'Unknown')
                        status_map[computer_id] = isolation_status
                        logger.info(f"Computer {computer_id}: isolation status = {isolation_status}")
                    
                    return status_map
            else:
                logger.error(f"Failed to check isolation status: {response.text}")
                return {}
        except Exception as e:
            logger.error(f"Error checking isolation status: {e}")
            return {}
    
    def _wait_for_isolation_status_job(self, job_id: str, computer_ids: List[str]) -> Dict[str, str]:
        """Wait for isolation status check job completion"""
        job_url = f"{self.gateway}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/jobs/{job_id}"
        headers = {
            "Authorization": f"Bearer {self.ci_token}",
            "x-mgmt-api-token": self.api_token
        }
        
        for attempt in range(30):
            try:
                response = requests.get(job_url, headers=headers)
                if response.status_code == 200:
                    job_data = response.json()
                    status = job_data.get('status')
                    
                    if status == 'DONE':
                        computers = job_data.get('data', {}).get('computers', [])
                        status_map = {}
                        for computer in computers:
                            computer_id = computer.get('computerId')
                            isolation_status = computer.get('isolationStatus', 'Unknown')
                            status_map[computer_id] = isolation_status
                            logger.info(f"Computer {computer_id}: isolation status = {isolation_status}")
                        
                        return status_map
                    elif status == 'FAILED':
                        logger.error("Isolation status check job failed")
                        return {}
                    
                    logger.info("Isolation status check job in progress...")
                    time.sleep(2)
                else:
                    logger.error(f"Failed to check job status: {response.text}")
                    return {}
            except Exception as e:
                logger.error(f"Error checking isolation status job: {e}")
                return {}
        
        logger.error("Isolation status check job timed out")
        return {}
    
    def isolate_host(self, hostnames: List[str], comment: str = "Automated isolation due to forensics alert") -> Tuple[bool, str]:
        """Isolate hosts using hostnames (converts to computer IDs first and checks current status)"""
        # First, get computer IDs from hostnames
        computer_ids = []
        failed_lookups = []
        
        for hostname in hostnames:
            computer_id = self.get_computer_id_by_hostname(hostname)
            if computer_id:
                computer_ids.append(computer_id)
            else:
                failed_lookups.append(hostname)
        
        if failed_lookups:
            logger.warning(f"Failed to find computer IDs for: {failed_lookups}")
        
        if not computer_ids:
            return False, "No valid computer IDs found for isolation"
        
        logger.info(f"Found {len(computer_ids)} computer IDs for isolation: {computer_ids}")
        
        # Check current isolation status to avoid duplicates
        isolation_statuses = self.check_isolation_status(computer_ids)
        already_isolated = []
        non_isolated_ids = []
        
        for computer_id in computer_ids:
            status = isolation_statuses.get(computer_id, 'Unknown').lower()
            if status in ['isolated', 'restricted']:
                already_isolated.append(computer_id)
                logger.info(f"Computer {computer_id} already isolated (status: {status})")
            else:
                non_isolated_ids.append(computer_id)
                logger.info(f"Computer {computer_id} not isolated (status: {status})")
        
        if already_isolated:
            logger.warning(f"Skipping {len(already_isolated)} already isolated machines: {already_isolated}")
        
        if not non_isolated_ids:
            return True, f"All {len(computer_ids)} machines already isolated"
        
        logger.info(f"Proceeding to isolate {len(non_isolated_ids)} non-isolated machines: {non_isolated_ids}")
        
        # Proceed with isolation for non-isolated machines
        url = f"{self.gateway}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/remediation/isolate"
        headers = {
            "Authorization": f"Bearer {self.ci_token}",
            "x-mgmt-api-token": self.api_token,
            "x-mgmt-run-as-job": "on"
        }
        
        payload = {
            "comment": f"{comment} (Skipped {len(already_isolated)} already isolated)",
            "targets": {
                "include": {
                    "computers": [{"id": cid} for cid in non_isolated_ids]
                }
            }
        }
        
        logger.info(f"Isolation request payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            logger.info(f"Isolation response status: {response.status_code}")
            logger.info(f"Isolation response headers: {dict(response.headers)}")
            logger.info(f"Isolation response body: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                if 'jobId' in result:
                    job_id = result['jobId']
                    logger.info(f"Isolation job created: {job_id}")
                    
                    # Check job status after a brief delay
                    time.sleep(3)
                    job_status = self.check_isolation_job_status(job_id)
                    if job_status:
                        logger.info(f"Initial job status: {job_status}")
                    
                    summary_msg = f"Job {job_id}: {len(non_isolated_ids)} new isolations, {len(already_isolated)} already isolated"
                    return True, summary_msg
                else:
                    summary_msg = f"Isolation initiated: {len(non_isolated_ids)} new, {len(already_isolated)} already isolated"
                    return True, summary_msg
            else:
                logger.error(f"Isolation failed: {response.text}")
                return False, response.text
        except Exception as e:
            logger.error(f"Isolation error: {e}")
            return False, str(e)

class LogAnalyzer:
    """Analyzes logs and extracts machine information"""
    
    @staticmethod
    def extract_machine_info(records: List[Dict]) -> List[Dict]:
        """Extract machine information from log records"""
        machines = []
        
        # Common field names that might contain hostname/machine info
        hostname_fields = [
            'src_machine_name', 'hostname', 'computerName', 'computer_name', 'device_name', 
            'machine_name', 'endpoint_name', 'host', 'src_host',
            'computer', 'device', 'endpoint'
        ]
        
        user_fields = [
            'username', 'user', 'user_name', 'account', 'login_name'
        ]
        
        for record in records:
            machine_info = {}
            
            # Debug: Print available fields for troubleshooting
            if not machines:  # Only print for first record
                logger.info(f"Available fields in log record: {list(record.keys())}")
            
            # Extract hostname
            for field in hostname_fields:
                if field in record and record[field]:
                    machine_info['hostname'] = record[field]
                    break
            
            # Extract username
            for field in user_fields:
                if field in record and record[field]:
                    machine_info['username'] = record[field]
                    break
            
            # Extract other relevant info
            machine_info.update({
                'severity': record.get('severity', 'Unknown'),
                'timestamp': record.get('timestamp', record.get('time', 'Unknown')),
                'event_type': record.get('event_type', record.get('blade', 'Unknown')),
                'raw_record': record  # Keep for troubleshooting
            })
            
            if machine_info.get('hostname'):
                machines.append(machine_info)
        
        return machines
    
    @staticmethod
    def summarize_machines(machines: List[Dict]) -> Dict[str, Dict]:
        """Summarize machines by hostname with occurrence counts"""
        summary = {}
        
        for machine in machines:
            hostname = machine.get('hostname')
            if not hostname:
                continue
                
            if hostname not in summary:
                summary[hostname] = {
                    'count': 0,
                    'severities': set(),
                    'users': set(),
                    'events': set(),
                    'first_seen': machine.get('timestamp'),
                    'last_seen': machine.get('timestamp'),
                    'sample_record': machine
                }
            
            entry = summary[hostname]
            entry['count'] += 1
            entry['severities'].add(machine.get('severity', 'Unknown'))
            entry['users'].add(machine.get('username', 'Unknown'))
            entry['events'].add(machine.get('event_type', 'Unknown'))
            
            # Update timestamps
            if machine.get('timestamp') > entry['last_seen']:
                entry['last_seen'] = machine.get('timestamp')
            if machine.get('timestamp') < entry['first_seen']:
                entry['first_seen'] = machine.get('timestamp')
        
        return summary

def get_gateway_selection() -> str:
    """Get gateway selection from user"""
    print("\nSelect your region:")
    print("1. Europe (Dublin)")
    print("2. US (North Virginia)")
    print("3. Australia (Sydney)")
    print("4. India (Mumbai)")
    
    while True:
        choice = input("Enter choice (1-4): ").strip()
        if choice == "1":
            return "https://cloudinfra-gw.portal.checkpoint.com"
        elif choice == "2":
            return "https://cloudinfra-gw-us.portal.checkpoint.com"
        elif choice == "3":
            return "https://cloudinfra-gw.ap.portal.checkpoint.com"
        elif choice == "4":
            return "https://cloudinfra-gw.in.portal.checkpoint.com"
        else:
            print("Invalid choice. Please enter 1-4.")

def get_timeframe_config() -> Tuple[bool, Optional[int], Optional[Dict]]:
    """Get timeframe configuration from user"""
    print("\nTimeframe Configuration:")
    print("1. Automated mode (predefined intervals)")
    print("2. Custom timeframe")
    
    choice = input("Select mode (1-2): ").strip()
    
    if choice == "1":
        print("\nSelect time window:")
        print("1. Last 1 hour")
        print("2. Last 6 hours") 
        print("3. Last 12 hours")
        
        while True:
            time_choice = input("Enter choice (1-3): ").strip()
            if time_choice in ["1", "2", "3"]:
                hours = [1, 6, 12][int(time_choice) - 1]
                return True, hours, None
            else:
                print("Invalid choice.")
    
    elif choice == "2":
        print("\nEnter custom timeframe:")
        time_unit = input("Time unit (hours/days/weeks/months): ").strip().lower()
        time_value = int(input(f"Number of {time_unit}: "))
        
        # Calculate start time
        now = datetime.datetime.utcnow()
        if time_unit.startswith('hour'):
            start_time = now - datetime.timedelta(hours=time_value)
        elif time_unit.startswith('day'):
            start_time = now - datetime.timedelta(days=time_value)
        elif time_unit.startswith('week'):
            start_time = now - datetime.timedelta(weeks=time_value)
        elif time_unit.startswith('month'):
            start_time = now - datetime.timedelta(days=time_value * 30)
        else:
            start_time = now - datetime.timedelta(hours=time_value)
        
        timeframe = {
            "startTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        return False, None, timeframe
    
    return True, 1, None

def get_filter_config() -> str:
    """Get filter configuration from user"""
    print("\nFilter Configuration:")
    print("Default filter: ci_app_name:\"Harmony Endpoint\" AND blade:\"Forensics\" AND (severity:\"High\" OR severity:\"Critical\")")
    
    use_default = input("Use default filter? (y/n): ").strip().lower()
    
    if use_default == 'y':
        return "ci_app_name:\"Harmony Endpoint\" AND blade:\"Forensics\" AND (severity:\"High\" OR severity:\"Critical\")"
    else:
        print("\nEnter custom filter (Lucene syntax):")
        print("Examples:")
        print("- ci_app_name:\"Harmony Endpoint\" AND severity:\"Critical\" AND blade:\"Forensics\"")
        print("- ci_app_name:\"Harmony Endpoint\" AND src_machine_name:\"hostname\" AND severity:\"High\"")
        return input("Filter: ").strip()

def get_execution_config() -> Tuple[bool, bool, Optional[int], bool]:
    """Get execution configuration"""
    print("\nExecution Configuration:")
    
    # Automation mode
    auto_isolate = input("Enable automatic host isolation? (y/n): ").strip().lower() == 'y'
    
    # Recurring execution
    recurring = input("Run continuously? (y/n): ").strip().lower() == 'y'
    
    interval_hours = None
    use_scheduler = False
    
    if recurring:
        print("\nRecurring execution options:")
        print("1. Built-in scheduler (sleep loops)")
        print("2. System scheduler (cron/Task Scheduler)")
        
        sched_choice = input("Select option (1-2): ").strip()
        
        if sched_choice == "1":
            interval_hours = int(input("Check interval (hours): "))
        else:
            use_scheduler = True
            print("\nTo use system scheduler:")
            print("Linux/Mac: Add to crontab - */30 * * * * /path/to/script.py --scheduled")
            print("Windows: Use Task Scheduler to run script with --scheduled flag")
    
    return auto_isolate, recurring, interval_hours, use_scheduler

def get_config() -> Config:
    """Interactive configuration setup"""
    print("=== HEP-Infinity Events Automation Setup ===")
    
    # Gateway selection
    gateway = get_gateway_selection()
    
    # Credentials
    print("\nInfinity Events Credentials:")
    infinity_client_id = input("Client ID: ").strip()
    infinity_secret_key = input("Secret Key: ").strip()
    
    print("\nHarmony Endpoint Credentials:")
    hep_client_id = input("Client ID: ").strip()
    hep_secret_key = input("Secret Key: ").strip()
    
    # Filter configuration
    filter_query = get_filter_config()
    
    # Timeframe configuration
    automation_mode, time_window_hours, custom_timeframe = get_timeframe_config()
    
    # Execution configuration
    auto_isolate, recurring, interval_hours, use_scheduler = get_execution_config()
    
    return Config(
        infinity_client_id=infinity_client_id,
        infinity_secret_key=infinity_secret_key,
        hep_client_id=hep_client_id,
        hep_secret_key=hep_secret_key,
        infinity_gateway=gateway,
        hep_gateway=gateway,
        automation_mode=automation_mode,
        time_window_hours=time_window_hours,
        custom_timeframe=custom_timeframe,
        recurring=recurring,
        interval_hours=interval_hours,
        use_system_scheduler=use_scheduler,
        filter_query=filter_query,
        approval_required=not auto_isolate
    )

def create_execution_report(summary: ExecutionSummary, config: Config) -> str:
    """Create detailed execution report"""
    report_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"hep_execution_report_{report_timestamp}.json"
    
    report_data = {
        "execution_summary": {
            "start_time": summary.start_time,
            "end_time": summary.end_time,
            "duration_minutes": (datetime.datetime.fromisoformat(summary.end_time.replace('Z', '+00:00')) - 
                               datetime.datetime.fromisoformat(summary.start_time.replace('Z', '+00:00'))).total_seconds() / 60,
            "alerts_found": summary.alerts_found,
            "unique_machines": summary.unique_machines,
            "machines_selected_for_isolation": summary.machines_selected,
            "isolation_successful": summary.isolation_successful,
            "isolation_job_id": summary.isolation_job_id,
            "errors": summary.errors
        },
        "configuration": {
            "filter_query": config.filter_query,
            "automation_mode": config.automation_mode,
            "approval_required": config.approval_required,
            "time_window_hours": config.time_window_hours,
            "gateway": config.infinity_gateway
        },
        "machines_processed": summary.machines_processed,
        "recommendations": generate_recommendations(summary)
    }
    
    with open(report_filename, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    logger.info(f"Execution report saved to: {report_filename}")
    return report_filename

def generate_recommendations(summary: ExecutionSummary) -> List[str]:
    """Generate recommendations based on execution results"""
    recommendations = []
    
    if summary.alerts_found == 0:
        recommendations.append("No threats detected. Consider reviewing filter criteria if threats are expected.")
    
    if summary.alerts_found > 10:
        recommendations.append("High number of alerts detected. Consider refining filters to reduce false positives.")
    
    if summary.errors:
        recommendations.append("Errors encountered during execution. Review logs and consider adjusting configuration.")
    
    if not summary.isolation_successful and summary.machines_selected > 0:
        recommendations.append("Isolation failed. Verify HEP permissions and network connectivity.")
    
    if summary.unique_machines != summary.machines_selected and summary.machines_selected > 0:
        recommendations.append("Not all detected machines were isolated. Review selection criteria.")
    
    return recommendations
    """Wait for user approval and selection for isolation"""
    machine_summary = LogAnalyzer.summarize_machines(machines)
    
    print("\n=== THREAT DETECTED ===")
    print(f"Found {len(machines)} total alerts across {len(machine_summary)} unique machines:")
    
    # Display summary
    machine_list = []
    for i, (hostname, info) in enumerate(machine_summary.items(), 1):
        machine_list.append(hostname)
        print(f"\n{i}. Machine: {hostname}")
        print(f"   Alert Count: {info['count']}")
        print(f"   Severities: {', '.join(info['severities'])}")
        print(f"   Users: {', '.join(info['users'])}")
        print(f"   Event Types: {', '.join(info['events'])}")
        print(f"   Time Range: {info['first_seen']} to {info['last_seen']}")
    
    print("\nAvailable actions:")
    print("1. Select specific machines to isolate")
    print("2. Isolate all machines")
    print("3. Show verbose log details")
    print("4. Show raw log data")
    print("5. Skip this round")
    print("6. Exit program")
    
    while True:
        choice = input("\nEnter choice (1-6): ").strip()
        
        if choice == "1":
            print("\nEnter machine numbers to isolate (comma-separated, e.g., 1,3,5):")
            selection = input("Machines to isolate: ").strip()
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_machines = [machine_list[i] for i in indices if 0 <= i < len(machine_list)]
                if selected_machines:
                    return selected_machines
                else:
                    print("Invalid selection.")
            except ValueError:
                print("Invalid input format.")
            continue
        elif choice == "2":
            return machine_list
        elif choice == "3":
            # Show verbose details for each machine
            for hostname, info in machine_summary.items():
                print(f"\n--- Verbose Details for {hostname} ---")
                sample = info['sample_record']
                print(f"Sample Record Fields:")
                for key, value in sample['raw_record'].items():
                    if isinstance(value, str) and len(value) > 100:
                        print(f"  {key}: {value[:100]}...")
                    else:
                        print(f"  {key}: {value}")
            continue
        elif choice == "4":
            # Show raw data
            for i, (hostname, info) in enumerate(machine_summary.items(), 1):
                print(f"\n--- Machine {i} ({hostname}) Raw Data ---")
                print(json.dumps(info['sample_record']['raw_record'], indent=2))
            continue
        elif choice == "5":
            return []
        elif choice == "6":
            sys.exit(0)
        else:
            print("Invalid choice.")

def generate_cron_example(config: Config) -> str:
    """Generate cron/scheduler examples"""
    script_path = os.path.abspath(__file__)
    
    examples = f"""
System Scheduler Setup:

Linux/Mac (crontab):
# Run every hour
0 * * * * cd {os.path.dirname(script_path)} && python3 {script_path} --scheduled

# Run every 6 hours
0 */6 * * * cd {os.path.dirname(script_path)} && python3 {script_path} --scheduled

Windows Task Scheduler:
1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (hourly/daily)
4. Set action: python.exe {script_path} --scheduled
5. Set start in: {os.path.dirname(script_path)}

Configuration will be saved to config.json and reused for scheduled runs.
"""
    return examples

def save_config(config: Config):
    """Save configuration to file"""
    config_dict = {
        'infinity_client_id': config.infinity_client_id,
        'infinity_secret_key': config.infinity_secret_key,
        'hep_client_id': config.hep_client_id,
        'hep_secret_key': config.hep_secret_key,
        'infinity_gateway': config.infinity_gateway,
        'hep_gateway': config.hep_gateway,
        'automation_mode': config.automation_mode,
        'time_window_hours': config.time_window_hours,
        'custom_timeframe': config.custom_timeframe,
        'recurring': config.recurring,
        'interval_hours': config.interval_hours,
        'use_system_scheduler': config.use_system_scheduler,
        'filter_query': config.filter_query,
        'approval_required': config.approval_required
    }
    
    with open('config.json', 'w') as f:
        json.dump(config_dict, f, indent=2)
    
    logger.info("Configuration saved to config.json")

def load_config() -> Optional[Config]:
    """Load configuration from file"""
    try:
        with open('config.json', 'r') as f:
            config_dict = json.load(f)
        
        return Config(**config_dict)
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return None

def wait_for_approval(machines: List[Dict]) -> List[str]:
    """Wait for user approval and selection for isolation"""
    machine_summary = LogAnalyzer.summarize_machines(machines)
    
    print("\n=== THREAT DETECTED ===")
    print(f"Found {len(machines)} total alerts across {len(machine_summary)} unique machines:")
    
    # Display summary
    machine_list = []
    for i, (hostname, info) in enumerate(machine_summary.items(), 1):
        machine_list.append(hostname)
        print(f"\n{i}. Machine: {hostname}")
        print(f"   Alert Count: {info['count']}")
        print(f"   Severities: {', '.join(info['severities'])}")
        print(f"   Users: {', '.join(info['users'])}")
        print(f"   Event Types: {', '.join(info['events'])}")
        print(f"   Time Range: {info['first_seen']} to {info['last_seen']}")
    
    print("\nAvailable actions:")
    print("1. Select specific machines to isolate")
    print("2. Isolate all machines")
    print("3. Show verbose log details")
    print("4. Show raw log data")
    print("5. Skip this round")
    print("6. Exit program")
    
    while True:
        choice = input("\nEnter choice (1-6): ").strip()
        
        if choice == "1":
            print("\nEnter machine numbers to isolate (comma-separated, e.g., 1,3,5):")
            selection = input("Machines to isolate: ").strip()
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_machines = [machine_list[i] for i in indices if 0 <= i < len(machine_list)]
                if selected_machines:
                    return selected_machines
                else:
                    print("Invalid selection.")
            except ValueError:
                print("Invalid input format.")
            continue
        elif choice == "2":
            return machine_list
        elif choice == "3":
            # Show verbose details for each machine
            for hostname, info in machine_summary.items():
                print(f"\n--- Verbose Details for {hostname} ---")
                sample = info['sample_record']
                print(f"Sample Record Fields:")
                for key, value in sample['raw_record'].items():
                    if isinstance(value, str) and len(value) > 100:
                        print(f"  {key}: {value[:100]}...")
                    else:
                        print(f"  {key}: {value}")
            continue
        elif choice == "4":
            # Show raw data
            for i, (hostname, info) in enumerate(machine_summary.items(), 1):
                print(f"\n--- Machine {i} ({hostname}) Raw Data ---")
                print(json.dumps(info['sample_record']['raw_record'], indent=2))
            continue
        elif choice == "5":
            return []
        elif choice == "6":
            sys.exit(0)
        else:
            print("Invalid choice.")

def auto_select_machines(machines: List[Dict], config: Config) -> List[str]:
    """Automatically select machines for isolation based on configuration"""
    machine_summary = LogAnalyzer.summarize_machines(machines)
    
    # Log automated decision
    logger.info(f"AUTOMATED MODE: Found {len(machines)} alerts across {len(machine_summary)} unique machines")
    
    for hostname, info in machine_summary.items():
        logger.info(f"Machine: {hostname} - Alerts: {info['count']} - Severities: {list(info['severities'])}")
    
    # Auto-select all unique machines in automated mode
    selected_machines = list(machine_summary.keys())
    logger.info(f"AUTOMATED SELECTION: All {len(selected_machines)} machines selected for isolation")
    
    return selected_machines

def run_search_and_isolate(config: Config) -> ExecutionSummary:
    """Main execution logic with comprehensive tracking"""
    start_time = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors = []
    
    # Initialize summary
    summary = ExecutionSummary(
        start_time=start_time,
        end_time="",
        alerts_found=0,
        unique_machines=0,
        machines_selected=0,
        isolation_successful=False,
        isolation_job_id="",
        errors=[],
        machines_processed=[]
    )
    
    try:
        # Initialize APIs
        infinity_api = InfinityEventsAPI(
            config.infinity_client_id,
            config.infinity_secret_key,
            config.infinity_gateway
        )
        
        hep_api = HarmonyEndpointAPI(
            config.hep_client_id,
            config.hep_secret_key,
            config.hep_gateway
        )
        
        # Authenticate
        if not infinity_api.authenticate():
            error_msg = "Failed to authenticate with Infinity Events"
            logger.error(error_msg)
            errors.append(error_msg)
            summary.errors = errors
            return summary
        
        if not hep_api.authenticate():
            error_msg = "Failed to authenticate with Harmony Endpoint"
            logger.error(error_msg)
            errors.append(error_msg)
            summary.errors = errors
            return summary
        
        # Prepare timeframe
        if config.automation_mode and config.time_window_hours:
            now = datetime.datetime.now(datetime.UTC)
            start_time_search = now - datetime.timedelta(hours=config.time_window_hours)
            timeframe = {
                "startTime": start_time_search.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        else:
            timeframe = config.custom_timeframe
        
        logger.info(f"Searching logs from {timeframe['startTime']} to {timeframe['endTime']}")
        
        # Search logs
        task_id = infinity_api.search_logs(config.filter_query, timeframe)
        if not task_id:
            error_msg = "Failed to create search task"
            errors.append(error_msg)
            summary.errors = errors
            return summary
        
        # Wait for task completion
        max_attempts = 30
        for attempt in range(max_attempts):
            status = infinity_api.check_task_status(task_id)
            if not status:
                error_msg = "Failed to check task status"
                errors.append(error_msg)
                summary.errors = errors
                return summary
            
            logger.info(f"Task status check {attempt + 1}/{max_attempts}:")
            logger.info(f"  State: {status.get('state', 'Unknown')}")
            logger.info(f"  Page tokens available: {len(status.get('pageTokens', []))}")
            if status.get('errors'):
                logger.warning(f"  Errors: {status.get('errors')}")
            
            if status['state'] == 'Ready':
                logger.info("Search completed successfully")
                break
            elif status['state'] == 'Failed':
                error_msg = f"Search failed: {status.get('errors', [])}"
                logger.error(error_msg)
                errors.append(error_msg)
                summary.errors = errors
                return summary
            elif status['state'] in ['Processing', 'InProgress', 'Running']:
                logger.info(f"Search still in progress, waiting 10 seconds...")
            else:
                logger.warning(f"Unknown state: {status['state']}")
            
            time.sleep(10)
        else:
            error_msg = "Search timed out after 5 minutes"
            logger.error(error_msg)
            errors.append(error_msg)
            summary.errors = errors
            return summary
        
        # Retrieve results
        page_tokens = status.get('pageTokens', [])
        if not page_tokens:
            logger.info("No forensics alerts found")
            summary.end_time = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            return summary
        
        all_machines = []
        for page_token in page_tokens:
            logs_data = infinity_api.retrieve_logs(task_id, page_token)
            if logs_data and logs_data.get('records'):
                machines = LogAnalyzer.extract_machine_info(logs_data['records'])
                all_machines.extend(machines)
        
        if not all_machines:
            logger.info("No machines found in forensics alerts")
            summary.end_time = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            return summary
        
        # Update summary with findings
        summary.alerts_found = len(all_machines)
        machine_summary = LogAnalyzer.summarize_machines(all_machines)
        summary.unique_machines = len(machine_summary)
        
        # Process machines for summary
        for hostname, info in machine_summary.items():
            summary.machines_processed.append({
                "hostname": hostname,
                "alert_count": info['count'],
                "severities": list(info['severities']),
                "users": list(info['users']),
                "events": list(info['events']),
                "first_seen": info['first_seen'],
                "last_seen": info['last_seen']
            })
        
        logger.info(f"Found {len(all_machines)} alerts across {len(machine_summary)} unique machines")
        
        # Handle selection (automated vs manual)
        selected_machines = []
        if config.approval_required:
            selected_machines = wait_for_approval(all_machines)
        else:
            selected_machines = auto_select_machines(all_machines, config)
        
        summary.machines_selected = len(selected_machines)
        
        if not selected_machines:
            logger.info("No machines selected for isolation")
            summary.end_time = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            return summary
        
        # Perform isolation
        logger.info(f"Attempting to isolate {len(selected_machines)} machines: {selected_machines}")
        success, result = hep_api.isolate_host(selected_machines, f"Automated isolation - {len(selected_machines)} machines")
        
        summary.isolation_successful = success
        summary.isolation_job_id = result if success else ""
        
        if success:
            logger.info(f"Successfully initiated isolation for {len(selected_machines)} machines. Job ID: {result}")
        else:
            error_msg = f"Failed to initiate isolation: {result}"
            logger.error(error_msg)
            errors.append(error_msg)
        
        summary.errors = errors
        summary.end_time = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return summary
        
    except Exception as e:
        error_msg = f"Unexpected error in execution: {str(e)}"
        logger.error(error_msg)
        errors.append(error_msg)
        summary.errors = errors
        summary.end_time = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return summary

def main():
    """Main function"""
    # Setup logging first
    log_filename = setup_logging()
    logger.info(f"Logging to file: {log_filename}")
    
    # Check for scheduled run
    if len(sys.argv) > 1 and sys.argv[1] == '--scheduled':
        config = load_config()
        if not config:
            logger.error("No saved configuration found for scheduled run")
            sys.exit(1)
        
        logger.info("=== SCHEDULED EXECUTION START ===")
        summary = run_search_and_isolate(config)
        report_file = create_execution_report(summary, config)
        logger.info(f"=== SCHEDULED EXECUTION END - Report: {report_file} ===")
        sys.exit(0)
    
    # Interactive setup
    config = get_config()
    save_config(config)
    
    if config.use_system_scheduler:
        print(generate_cron_example(config))
        print("Setup complete. Configure your system scheduler and run with --scheduled flag.")
        return
    
    # Run once or with built-in scheduler
    try:
        if config.recurring and config.interval_hours:
            logger.info(f"Starting continuous monitoring (every {config.interval_hours} hours)")
            while True:
                logger.info("=== EXECUTION CYCLE START ===")
                summary = run_search_and_isolate(config)
                report_file = create_execution_report(summary, config)
                logger.info(f"=== EXECUTION CYCLE END - Report: {report_file} ===")
                logger.info(f"Waiting {config.interval_hours} hours until next check...")
                time.sleep(config.interval_hours * 3600)
        else:
            logger.info("=== SINGLE EXECUTION START ===")
            summary = run_search_and_isolate(config)
            report_file = create_execution_report(summary, config)
            logger.info(f"=== SINGLE EXECUTION END - Report: {report_file} ===")
    except KeyboardInterrupt:
        logger.info("Script interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

# Additional validation for automated mode
def validate_automated_execution(config: Config) -> List[str]:
    """Validate configuration for automated execution"""
    warnings = []
    
    if config.automation_mode and not config.approval_required:
        if not config.time_window_hours or config.time_window_hours > 24:
            warnings.append("Large time windows may generate excessive alerts")
        
        if "Critical" not in config.filter_query and "High" not in config.filter_query:
            warnings.append("Filter may capture low-severity events, causing unnecessary isolations")
    
    return warnings

if __name__ == "__main__":
    main()
