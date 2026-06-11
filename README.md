# CloudWatch MCP Server

A standalone MCP (Model Context Protocol) HTTP server that connects AWS CloudWatch to VERA AI — or any MCP-compatible AI orchestrator.

Runs on your infrastructure server, talks directly to AWS CloudWatch APIs, and exposes 7 ready-to-use tools over HTTP.

---

## Tools Available

| Tool | Description |
|------|-------------|
| `get_active_alarms` | List currently firing CloudWatch alarms |
| `get_alarm_history` | State change history for a specific alarm (for RCA) |
| `get_metric_data` | Metric values over a time window (CPU, latency, errors, etc.) |
| `list_metrics` | Discover available metrics for a namespace |
| `describe_log_groups` | List available CloudWatch log groups |
| `execute_log_insights_query` | Run a Logs Insights query — returns a query_id |
| `get_logs_insight_query_results` | Fetch results of a running Logs Insights query |

---

## Quick Start

### 1. Clone this repo on your infrastructure server

```bash
git clone https://github.com/VectorParkarDevOrg/CloudWatch-MCP.git
cd CloudWatch-MCP
```

### 2. Configure credentials

```bash
cp .env.example .env
nano .env
```

```env
# Option A — hardcoded keys
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-east-1

# Option B — EC2 with IAM role: leave keys blank, uses instance profile automatically

PORT=8091

# Shared secret — VERA sends this as Bearer token to authenticate
BEARER_TOKEN=change-me-to-a-random-secret
```

### 3. Start

```bash
docker compose up -d
```

### 4. Verify

```bash
curl http://localhost:8091/health
# {"ok": true, "service": "cloudwatch-mcp-server", "tools": 7}
```

---

## Connect to VERA AI

1. Open VERA → **Settings** → **Integrations**
2. Under **Observability** → click **AWS CloudWatch**
3. Enter:
   - **MCP URL**: `http://<this-server-ip>:8091/mcp`
   - **Bearer Token**: the `BEARER_TOKEN` from your `.env`
4. Click **Test Connection** → should show ✅
5. Enable → Save

---

## Required AWS IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeAlarmHistory",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "logs:StopQuery"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Network Setup

The VERA server must reach port `8091` on this server.

- **Same AWS VPC**: Add a security group inbound rule allowing VERA's security group on TCP 8091
- **Outside AWS**: Restrict port 8091 to VERA's IP only, or put it behind a reverse proxy with HTTPS

---

## Updating

```bash
git pull
docker compose up -d --build
```

No VERA restart needed.

---

## Part of the VERA AI ecosystem

This server is built and maintained as part of the [VERA AI 2.0](https://github.com/VectorParkarDevOrg/vera-ai-2.0) platform.
