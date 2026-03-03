# Email Automation System

Automated email generation system for security release notifications with JIRA integration, ATT&CK framework coverage analysis, and JFrog artifact management.

## Features

- **Automated Email Generation**: Generate release notification emails for DS, DSRU, IVP, TMVP, and VP releases
- **JIRA Integration**: Create and manage JIRA tables for release tracking
- **ATT&CK Coverage**: Analyze and report MITRE ATT&CK framework coverage
- **JFrog Management**: Download and upload artifacts to JFrog repositories
- **Slack Notifications**: Send automated notifications to Slack channels
- **Docker Support**: Containerized deployment with Docker
- **CI/CD Ready**: Jenkins pipeline configuration included

## Project Structure

```
├── src/                          # Source code
│   ├── generate_all_mails.py    # Main email generation orchestrator
│   ├── get_ds_email.py          # Deep Security email generator
│   ├── get_dsru_email.py        # DSRU email generator
│   ├── get_ivp_email.py         # IVP email generator
│   ├── get_tmvp_email.py        # TMVP email generator
│   ├── get_vp_email.py          # VP email generator
│   ├── create_table_jira.py     # JIRA table creation
│   ├── att_ck_coverage.py       # ATT&CK coverage analysis
│   ├── jfrog_download.py        # JFrog download utility
│   ├── jfrog_upload.py          # JFrog upload utility
│   ├── slack_notify.py          # Slack notification handler
│   ├── mail_common.py           # Common email utilities
│   ├── parse_update.py          # Update parser with zip
│   └── parse_update_wo_zip.py   # Update parser without zip
├── docker_files/                # Docker configurations
├── jenkins_files/               # Jenkins pipeline files
└── README.md                    # This file

## Usage

### Generate All Emails
```bash
python src/generate_all_mails.py
```

### Individual Email Generation
```bash
python src/get_ds_email.py      # Deep Security
python src/get_dsru_email.py    # DSRU
python src/get_ivp_email.py     # IVP
python src/get_tmvp_email.py    # TMVP
python src/get_vp_email.py      # VP
```

### JIRA Table Management
```bash
python src/create_table_jira.py
```

### ATT&CK Coverage Analysis
```bash
python src/att_ck_coverage.py
```

## Docker Deployment

```bash
docker build -f docker_files/DockerfileMail -t email-automation .
docker run email-automation
```

## Configuration

Ensure you have the necessary credentials and configuration files:
- JIRA API credentials
- JFrog repository access
- Slack webhook URL (if using Slack notifications)
- SMTP server configuration for email sending

## License

MIT License - feel free to use this project for your own purposes.

## Author

Amit Verma (amyvrm@gmail.com)
