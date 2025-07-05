# HEP HOST Isolation Automation Script

## Overview

Automated threat response system that monitors Harmony Endpoint logs via Infinity Events API and triggers host isolation when Critical/High severity (or based on ones requirement) threats are detected.

## Features

- **Dual API Integration**: Infinity Events for log monitoring, Harmony Endpoint for remediation
- **Automated Host Isolation**: Real-time response to forensics alerts
- **Flexible Execution**: Manual approval, full automation, or scheduled runs
- **Comprehensive Logging**: Timestamped logs and JSON execution reports
- **Machine Deduplication**: Groups multiple alerts by hostname
- **Multi-Region Support**: Europe, US, Australia, India gateways

## Prerequisites

- Python 3.8+
- Required packages: `requests`
- Infinity Portal API keys for both services
- Harmony Endpoint with isolation permissions

## Installation

```bash
# Clone or download the script
python -m pip install requests

# Make executable (Linux/Mac)
chmod +x hep_automation.py
```

## Configuration

### API Keys Setup

1. **Infinity Portal**: Create API keys at Global Settings > API Keys
   - Service: "Logs as a Service" (for Events API)
   - Service: "Endpoint" (for HEP API)

2. **Permissions Required**:
   - Events: None as it is in read-only mode.
   - HEP: Admin.

### Interactive Configuration

Run script for first-time setup:
```bash
python hep_automation.py
```

Configuration prompts:
- Gateway region selection
- API credentials
- Filter configuration
- Execution mode (manual/auto)
- Scheduling options

## Usage

### One-Time Execution
```bash
python hep_automation.py
```

### Scheduled Execution
```bash
# System scheduler mode
python hep_automation.py --scheduled
```

### Built-in Recurring
Configure during setup for continuous monitoring with sleep intervals.

## Filter Configuration

### Default Filter
```
ci_app_name:"Harmony Endpoint" AND blade:"Forensics" AND (severity:"High" OR severity:"Critical")
```

### Custom Filters
Lucene syntax examples:
```
# Specific machine
ci_app_name:"Harmony Endpoint" AND src_machine_name:"hostname" AND severity:"Critical"

# Time-based
ci_app_name:"Harmony Endpoint" AND blade:"Forensics" AND severity:"High"
```

## Execution Modes

### Manual Approval Mode
- Displays threat summary with alert counts
- Interactive machine selection
- Options to view verbose/raw log data
- Skip or exit capabilities

### Automated Mode
- Auto-selects all detected machines
- Comprehensive logging of decisions
- Immediate isolation without user input

## Scheduling Options

### Built-in Scheduler
```bash
# During setup, choose intervals:
# - 1 hour, 6 hours, 12 hours
# Uses Python sleep loops
```

### System Scheduler

**Linux/Mac (crontab):**
```bash
# Every hour
0 * * * * cd /path/to/script && python3 hep_automation.py --scheduled

# Every 6 hours
0 */6 * * * cd /path/to/script && python3 hep_automation.py --scheduled
```

**Windows Task Scheduler:**
1. Create Basic Task
2. Set trigger frequency
3. Action: `python.exe hep_automation.py --scheduled`
4. Start in: script directory

## Output Files

### Log Files
```
hep_automation_YYYYMMDD_HHMMSS.log
```
Contains timestamped execution logs with API calls, decisions, and errors.

### Execution Reports
```
hep_execution_report_YYYYMMDD_HHMMSS.json
```

Report structure:
```json
{
  "execution_summary": {
    "start_time": "2025-07-01T00:30:19Z",
    "alerts_found": 47,
    "unique_machines": 1,
    "machines_selected_for_isolation": 1,
    "isolation_successful": true,
    "isolation_job_id": "uuid"
  },
  "machines_processed": [{
    "hostname": "machine-name",
    "alert_count": 47,
    "severities": ["Critical", "High"],
    "users": ["user1", "user2"]
  }],
  "recommendations": ["..."]
}
```

## API Workflow

### Infinity Events Flow
1. Authenticate with CloudInfra token
2. Create search task with filters
3. Poll task status until 'Ready'
4. Retrieve paginated results
5. Extract machine information

### Harmony Endpoint Flow
1. CloudInfra authentication
2. Create API session
3. Query asset management for computer IDs
4. Submit isolation request
5. Monitor job status

## Machine Detection Logic

### Field Mapping
Primary hostname field: `src_machine_name`
Fallback fields: `hostname`, `computerName`, `computer_name`, etc.

### Deduplication
Groups alerts by hostname with aggregated:
- Alert counts
- Severity levels
- Associated users
- Event types
- Time ranges

## Error Handling

### Common Issues
- **Authentication failures**: Check API keys and permissions
- **No computer ID found**: Verify hostname exists in HEP asset management
- **Isolation job created but not executing**: Check computer ID validity

### Troubleshooting
1. Review log files for API responses
2. Check execution reports for error details
3. Verify machine exists in HEP console
4. Confirm isolation permissions

## Security Considerations

### API Key Protection
- Store credentials securely
- Use environment variables for production
- Rotate keys regularly

### Isolation Impact
- Test with non-critical machines first
- Have de-isolation procedures ready
- Monitor for false positives

## Configuration File

Saved as `config.json` after initial setup:
```json
{
  "infinity_client_id": "...",
  "hep_client_id": "...",
  "filter_query": "...",
  "automation_mode": true,
  "approval_required": false
}
```

## Monitoring & Maintenance

### Health Checks
- Monitor log files for errors
- Review execution reports regularly
- Validate isolation job success

### Performance Tuning
- Adjust time windows for alert volume
- Refine filters to reduce false positives
- Consider rate limiting for high-volume environments

## Advanced Configuration

### Custom Time Windows
- Hours: `1`, `6`, `12` (automated)
- Custom: Days, weeks, months (manual input)

### Filter Customization
Use Lucene syntax for complex queries combining:
- Application names
- Severity levels
- Machine names
- Time ranges
- Event types

## Support

For issues or questions:
1. Check log files and execution reports
2. Review API documentation
3. Verify permissions and connectivity
4. Test with simplified configurations

## Version History

- **v1.0**: Initial release with basic automation
- **v2.0**: Added comprehensive reporting and logging
- **v2.1**: Added support for checking of endpoint status if its either isolated or not isolated, if already isolated it will automatically skip the isolation push operation. 
## Version History
Features in roadmap:
-   Send alert via email.
-   Enrichment of detections by verfiying with VT 
