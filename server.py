"""
CloudWatch MCP HTTP Server for VERA AI

Speaks MCP Streamable HTTP / SSE (JSON-RPC over HTTP).
AWS credentials come from the server environment (IAM role or env vars).

Tools:
  get_active_alarms              — currently firing CloudWatch alarms
  get_alarm_history              — state change history for RCA
  get_metric_data                — retrieve metric values over a time window
  list_metrics                   — discover available metrics for a namespace
  describe_log_groups            — list available log groups
  describe_log_streams           — list log streams within a log group
  get_log_events                 — fetch raw log lines from a log stream
  execute_log_insights_query     — run a Logs Insights query (returns query_id)
  get_logs_insight_query_results — retrieve results of a running query
  list_dashboards                — list available CloudWatch dashboards
  get_dashboard                  — get widgets/body of a specific dashboard
  list_s3_buckets                — list all S3 buckets in the account
  get_s3_storage_metrics         — storage size and object count for an S3 bucket
  list_ec2_instances             — list EC2 instances with state, type, IPs
  get_ec2_instance_status        — system/instance status checks for EC2
  list_rds_instances             — list RDS DB instances with engine and endpoint
  get_rds_events                 — failovers, restarts, backup events for RDS
  list_lambda_functions          — list Lambda functions with runtime/memory/timeout
  list_ecs_clusters              — list ECS clusters with service/task counts
  list_ecs_services              — list services in an ECS cluster with task health
  list_sqs_queues                — list SQS queues in the account/region
  get_sqs_queue_stats            — queue depth, in-flight, delayed message counts
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3
import botocore.exceptions
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse

logger = logging.getLogger("cloudwatch-mcp")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
)

app = FastAPI(title="CloudWatch MCP Server", docs_url=None, redoc_url=None)

# ── MCP tool definitions ─────────────────────────────────────────────────────

TOOLS: list[dict] = [
    {
        "name": "get_active_alarms",
        "description": (
            "List CloudWatch alarms in ALARM (or any) state. "
            "Use for incident triage — shows which alarms are currently firing, "
            "the metric they watch, and the reason text."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "enum": ["ALARM", "OK", "INSUFFICIENT_DATA"],
                    "default": "ALARM",
                    "description": "Filter by alarm state. Default: ALARM.",
                },
                "alarm_name_prefix": {
                    "type": "string",
                    "description": "Optional prefix to narrow results.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_alarm_history",
        "description": (
            "Retrieve state-change history for a specific CloudWatch alarm. "
            "Useful for root cause analysis — shows when it first triggered, "
            "how long it stayed in ALARM, and any OK→ALARM transitions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "alarm_name": {
                    "type": "string",
                    "description": "Exact name of the CloudWatch alarm.",
                },
                "hours": {
                    "type": "integer",
                    "default": 24,
                    "description": "How many hours back to search. Default: 24.",
                },
            },
            "required": ["alarm_name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_metric_data",
        "description": (
            "Retrieve CloudWatch metric data over a time window. "
            "Use for performance analysis, e.g. CPU utilisation, request latency, "
            "error rate. Specify namespace, metric name, and optional dimensions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "e.g. AWS/EC2, AWS/RDS, AWS/Lambda, AWS/ApplicationELB",
                },
                "metric_name": {
                    "type": "string",
                    "description": "e.g. CPUUtilization, NetworkIn, Latency",
                },
                "dimensions": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": 'e.g. [{"Name":"InstanceId","Value":"i-0abc123"}]',
                    "default": [],
                },
                "period": {
                    "type": "integer",
                    "default": 300,
                    "description": "Aggregation period in seconds. Default: 300 (5 min).",
                },
                "hours": {
                    "type": "integer",
                    "default": 1,
                    "description": "Time window in hours. Default: 1.",
                },
                "stat": {
                    "type": "string",
                    "default": "Average",
                    "description": "Statistic: Average, Sum, Maximum, Minimum, SampleCount.",
                },
            },
            "required": ["namespace", "metric_name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_metrics",
        "description": (
            "List available CloudWatch metrics. Leave namespace empty to discover "
            "all namespaces. Filter by metric_name or dimensions to narrow results. "
            "Returns up to 500 unique metric names with their dimensions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "e.g. AWS/EC2, AWS/Lambda, AWS/RDS. Leave empty to list all.",
                },
                "metric_name": {
                    "type": "string",
                    "description": "Optional metric name filter, e.g. CPUUtilization.",
                },
                "dimensions": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": 'Optional dimension filter, e.g. [{"Name":"InstanceId","Value":"i-0abc"}]',
                    "default": [],
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Max unique metrics to return (up to 500). Default: 100.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "describe_log_groups",
        "description": (
            "List available CloudWatch log groups. "
            "Use to discover which log groups exist before running a query."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "description": "Optional prefix filter, e.g. /aws/lambda/.",
                },
                "limit": {
                    "type": "integer",
                    "default": 20,
                    "description": "Maximum results. Default: 20.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "execute_log_insights_query",
        "description": (
            "Start a CloudWatch Logs Insights query. Returns a query_id — "
            "pass it to get_logs_insight_query_results to retrieve the data. "
            "Example query: 'fields @timestamp, @message | filter @message like /ERROR/ | limit 50'"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_group_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "One or more log groups to query.",
                },
                "query_string": {
                    "type": "string",
                    "description": "Logs Insights query string.",
                },
                "hours": {
                    "type": "integer",
                    "default": 1,
                    "description": "Time range in hours. Default: 1.",
                },
            },
            "required": ["log_group_names", "query_string"],
            "additionalProperties": False,
        },
    },
    {
        "name": "filter_log_events",
        "description": (
            "Search for log events matching a pattern across an entire log group "
            "(all streams). Faster than Insights for simple keyword/pattern searches. "
            "Use for 'find ERROR logs', 'find logs containing X in last N minutes'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_group_name": {
                    "type": "string",
                    "description": "Log group to search, e.g. /aws/lambda/my-function.",
                },
                "filter_pattern": {
                    "type": "string",
                    "description": 'CloudWatch filter pattern, e.g. "ERROR", "?Exception ?error", "[level=ERROR]".',
                },
                "minutes": {
                    "type": "integer",
                    "default": 30,
                    "description": "How many minutes back to search. Default: 30.",
                },
                "limit": {
                    "type": "integer",
                    "default": 50,
                    "description": "Maximum events to return. Default: 50.",
                },
                "log_stream_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional: limit search to specific streams.",
                    "default": [],
                },
            },
            "required": ["log_group_name", "filter_pattern"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_logs_insight_query_results",
        "description": (
            "Retrieve results of a CloudWatch Logs Insights query started with "
            "execute_log_insights_query. Set wait=true (default) to poll until complete."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query_id": {
                    "type": "string",
                    "description": "Query ID from execute_log_insights_query.",
                },
                "wait": {
                    "type": "boolean",
                    "default": True,
                    "description": "Poll until complete (up to 30 s). Default: true.",
                },
            },
            "required": ["query_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "describe_log_streams",
        "description": (
            "List log streams within a CloudWatch log group, ordered by last event time. "
            "Use to find the specific stream to tail with get_log_events."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_group_name": {
                    "type": "string",
                    "description": "Exact log group name, e.g. /aws/lambda/my-function.",
                },
                "prefix": {
                    "type": "string",
                    "description": "Optional stream name prefix filter.",
                },
                "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum streams to return. Default: 10.",
                },
            },
            "required": ["log_group_name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_log_events",
        "description": (
            "Fetch raw log lines from a specific CloudWatch log stream. "
            "Use for real-time tailing or fetching the latest lines from a Lambda, "
            "ECS task, or EC2 application log."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_group_name": {
                    "type": "string",
                    "description": "Log group name, e.g. /aws/lambda/my-function.",
                },
                "log_stream_name": {
                    "type": "string",
                    "description": "Log stream name from describe_log_streams.",
                },
                "limit": {
                    "type": "integer",
                    "default": 50,
                    "description": "Maximum log events to return. Default: 50.",
                },
                "start_from_head": {
                    "type": "boolean",
                    "default": False,
                    "description": "If false (default), returns the most recent events.",
                },
            },
            "required": ["log_group_name", "log_stream_name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_dashboards",
        "description": (
            "List available CloudWatch dashboards. "
            "Use to discover dashboard names before calling get_dashboard."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "description": "Optional dashboard name prefix filter.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_dashboard",
        "description": (
            "Retrieve the widgets and layout of a specific CloudWatch dashboard. "
            "Returns the dashboard body as JSON — useful for understanding which "
            "metrics and alarms the team is actively monitoring."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dashboard_name": {
                    "type": "string",
                    "description": "Exact dashboard name from list_dashboards.",
                },
            },
            "required": ["dashboard_name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_s3_buckets",
        "description": (
            "List all S3 buckets in the AWS account with their creation date and region. "
            "Use this first to discover bucket names before fetching S3 metrics."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "get_s3_storage_metrics",
        "description": (
            "Get storage size (BucketSizeBytes) and object count (NumberOfObjects) "
            "for an S3 bucket from CloudWatch. Note: these metrics update once per day "
            "and must be enabled in S3 bucket properties → Metrics. "
            "For request metrics (errors, latency), use get_metric_data with "
            "namespace=AWS/S3 and the bucket's request metric FilterId dimension."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "bucket_name": {
                    "type": "string",
                    "description": "S3 bucket name.",
                },
                "days": {
                    "type": "integer",
                    "default": 7,
                    "description": "How many days back to look. Default: 7 (metrics update daily).",
                },
            },
            "required": ["bucket_name"],
            "additionalProperties": False,
        },
    },
    # ── EC2 ──────────────────────────────────────────────────────────────────
    {
        "name": "list_ec2_instances",
        "description": (
            "List EC2 instances in the account/region with their state, type, "
            "name tag, private/public IP, and launch time. Use for inventory, "
            "incident triage, and identifying which instance to pull metrics for."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "enum": ["running", "stopped", "all"],
                    "default": "running",
                    "description": "Filter by instance state. Default: running.",
                },
                "name_filter": {
                    "type": "string",
                    "description": "Optional substring to filter by Name tag.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_ec2_instance_status",
        "description": (
            "Get system and instance status checks for one or more EC2 instances. "
            "Shows failed status checks, reachability, and impaired state. "
            "Use when an alarm fired and you want to know if the instance itself is healthy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of instance IDs, e.g. ['i-0abc123', 'i-0def456']. Leave empty for all.",
                    "default": [],
                },
            },
            "additionalProperties": False,
        },
    },
    # ── RDS ──────────────────────────────────────────────────────────────────
    {
        "name": "list_rds_instances",
        "description": (
            "List RDS database instances with their engine, status, class, "
            "endpoint, and multi-AZ configuration. Use to discover DB identifiers "
            "before fetching RDS CloudWatch metrics."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status_filter": {
                    "type": "string",
                    "description": "Optional status filter, e.g. available, stopped, backing-up.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_rds_events",
        "description": (
            "Get recent RDS events for a DB instance (failovers, restarts, "
            "parameter changes, backup completions). Essential for RCA on DB incidents."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_instance_identifier": {
                    "type": "string",
                    "description": "RDS DB instance identifier.",
                },
                "hours": {
                    "type": "integer",
                    "default": 24,
                    "description": "How many hours back to search. Default: 24.",
                },
            },
            "required": ["db_instance_identifier"],
            "additionalProperties": False,
        },
    },
    # ── Lambda ───────────────────────────────────────────────────────────────
    {
        "name": "list_lambda_functions",
        "description": (
            "List Lambda functions with their runtime, memory, timeout, "
            "last modified time, and code size. Use to discover function names "
            "before querying Lambda CloudWatch metrics or logs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name_filter": {
                    "type": "string",
                    "description": "Optional substring to filter function names.",
                },
            },
            "additionalProperties": False,
        },
    },
    # ── ECS ──────────────────────────────────────────────────────────────────
    {
        "name": "list_ecs_clusters",
        "description": (
            "List ECS clusters and their active service/task counts. "
            "Use to get cluster names before querying ECS service details or metrics."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "list_ecs_services",
        "description": (
            "List ECS services in a cluster with their desired/running/pending task counts "
            "and status. Use to detect services with task count mismatches or unhealthy state."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cluster": {
                    "type": "string",
                    "description": "ECS cluster name or ARN.",
                },
            },
            "required": ["cluster"],
            "additionalProperties": False,
        },
    },
    # ── SQS ──────────────────────────────────────────────────────────────────
    {
        "name": "get_sqs_queue_stats",
        "description": (
            "Get SQS queue depth and message stats: visible messages, "
            "in-flight messages, and delayed messages. Use to detect "
            "queue backlogs or processing failures."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "queue_url": {
                    "type": "string",
                    "description": "Full SQS queue URL.",
                },
            },
            "required": ["queue_url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_sqs_queues",
        "description": (
            "List all SQS queues in the account/region. "
            "Use to discover queue URLs before calling get_sqs_queue_stats."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "description": "Optional queue name prefix filter.",
                },
            },
            "additionalProperties": False,
        },
    },
]

# Inject optional region override into every tool schema
for _tool in TOOLS:
    _tool["inputSchema"]["properties"]["region"] = {
        "type": "string",
        "description": (
            "AWS region override, e.g. ap-south-2, eu-west-1. "
            "Defaults to the server's AWS_DEFAULT_REGION env var."
        ),
    }

# ── Credential helpers ───────────────────────────────────────────────────────

_BEARER_TOKEN = os.getenv("BEARER_TOKEN", "")


def _auth_ok(request: Request) -> bool:
    """Validate Bearer token if BEARER_TOKEN env var is set."""
    if not _BEARER_TOKEN:
        return True  # no token configured — open access (use on private networks only)
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip() == _BEARER_TOKEN
    return False


def _parse_creds(request: Request) -> dict:
    """AWS credentials come from the server's environment (IAM role or env vars)."""
    return {}


def _client(service: str, creds: dict, region_override: str | None = None):
    region = (
        region_override
        or creds.get("region")
        or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    )
    kwargs: dict[str, Any] = {"region_name": region}
    ak = creds.get("ak") or os.getenv("AWS_ACCESS_KEY_ID")
    sk = creds.get("sk") or os.getenv("AWS_SECRET_ACCESS_KEY")
    if ak and sk:
        kwargs["aws_access_key_id"] = ak
        kwargs["aws_secret_access_key"] = sk
    return boto3.client(service, **kwargs)


# ── Tool implementations ─────────────────────────────────────────────────────

async def _get_active_alarms(args: dict, creds: dict) -> str:
    cw = _client("cloudwatch", creds, args.get("region"))
    state = args.get("state", "ALARM")
    kwargs: dict[str, Any] = {"StateValue": state}
    if args.get("alarm_name_prefix"):
        kwargs["AlarmNamePrefix"] = args["alarm_name_prefix"]

    resp = cw.describe_alarms(**kwargs)
    alarms = resp.get("MetricAlarms", [])
    if not alarms:
        return f"No alarms in {state} state."

    lines = [f"{len(alarms)} alarm(s) in {state} state:\n"]
    for a in alarms:
        lines.append(f"  [{a['StateValue']}] {a['AlarmName']}")
        ns = a.get("Namespace", "")
        mn = a.get("MetricName", "")
        if ns or mn:
            lines.append(f"    Metric: {ns}/{mn}")
        reason = a.get("StateReason", "")
        if reason:
            lines.append(f"    Reason: {reason[:300]}")
        updated = a.get("StateUpdatedTimestamp")
        if updated:
            lines.append(f"    Since:  {updated.isoformat()}")
        lines.append("")
    return "\n".join(lines)


async def _get_alarm_history(args: dict, creds: dict) -> str:
    cw = _client("cloudwatch", creds, args.get("region"))
    hours = max(1, int(args.get("hours", 24)))
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    resp = cw.describe_alarm_history(
        AlarmName=args["alarm_name"],
        StartDate=start,
        EndDate=end,
        HistoryItemType="StateUpdate",
        ScanBy="TimestampDescending",
    )
    items = resp.get("AlarmHistoryItems", [])
    if not items:
        return f"No state changes for '{args['alarm_name']}' in the last {hours}h."

    lines = [f"State changes for '{args['alarm_name']}' (last {hours}h):\n"]
    for item in items:
        ts = item.get("Timestamp")
        ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        lines.append(f"  {ts_str}  {item.get('HistorySummary', '')}")
    return "\n".join(lines)


async def _get_metric_data(args: dict, creds: dict) -> str:
    cw = _client("cloudwatch", creds, args.get("region"))
    hours = max(1, int(args.get("hours", 1)))
    period = max(60, int(args.get("period", 300)))
    stat = args.get("stat", "Average")
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    resp = cw.get_metric_statistics(
        Namespace=args["namespace"],
        MetricName=args["metric_name"],
        Dimensions=args.get("dimensions") or [],
        StartTime=start,
        EndTime=end,
        Period=period,
        Statistics=[stat],
    )
    points = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
    if not points:
        return (
            f"No data for {args['namespace']}/{args['metric_name']} "
            f"in the last {hours}h (period={period}s)."
        )

    unit = points[0].get("Unit", "")
    lines = [f"{args['namespace']}/{args['metric_name']} — {stat} (last {hours}h, {period}s periods):\n"]
    for pt in points[-30:]:
        ts = pt["Timestamp"].strftime("%H:%M")
        val = pt.get(stat, pt.get("Average", "?"))
        try:
            lines.append(f"  {ts}  {val:>10.3f} {unit}")
        except (TypeError, ValueError):
            lines.append(f"  {ts}  {val} {unit}")
    return "\n".join(lines)


async def _list_metrics(args: dict, creds: dict) -> str:
    cw = _client("cloudwatch", creds, args.get("region"))
    limit = min(500, max(1, int(args.get("limit", 100))))

    kwargs: dict[str, Any] = {}
    if args.get("namespace"):
        kwargs["Namespace"] = args["namespace"]
    if args.get("metric_name"):
        kwargs["MetricName"] = args["metric_name"]
    if args.get("dimensions"):
        kwargs["Dimensions"] = args["dimensions"]

    metrics: list[dict] = []
    next_token = None
    while len(metrics) < limit:
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cw.list_metrics(**kwargs)
        metrics.extend(resp.get("Metrics", []))
        next_token = resp.get("NextToken")
        if not next_token or len(metrics) >= limit:
            break

    metrics = metrics[:limit]
    if not metrics:
        return "No metrics found."

    # Group by namespace for readability
    by_ns: dict[str, list[str]] = {}
    for m in metrics:
        ns = m["Namespace"]
        mn = m["MetricName"]
        dims = ", ".join(f"{d['Name']}={d['Value']}" for d in m.get("Dimensions", []))
        entry = f"    {mn}" + (f"  [{dims}]" if dims else "")
        by_ns.setdefault(ns, []).append(entry)

    lines = [f"Metrics found ({len(metrics)}):\n"]
    for ns in sorted(by_ns):
        lines.append(f"  {ns}:")
        for e in sorted(set(by_ns[ns])):
            lines.append(e)
        lines.append("")
    return "\n".join(lines)


async def _describe_log_groups(args: dict, creds: dict) -> str:
    logs = _client("logs", creds, args.get("region"))
    kwargs: dict[str, Any] = {"limit": min(50, max(1, int(args.get("limit", 20))))}
    if args.get("prefix"):
        kwargs["logGroupNamePrefix"] = args["prefix"]

    resp = logs.describe_log_groups(**kwargs)
    groups = resp.get("logGroups", [])
    if not groups:
        return "No log groups found."

    lines = [f"Log groups ({len(groups)}):\n"]
    for g in groups:
        name = g["logGroupName"]
        stored = g.get("storedBytes", 0)
        retention = g.get("retentionInDays", "Never expires")
        lines.append(f"  {name}")
        lines.append(f"    Stored: {stored:,} bytes  |  Retention: {retention}")
    return "\n".join(lines)


async def _execute_log_insights_query(args: dict, creds: dict) -> str:
    logs = _client("logs", creds, args.get("region"))
    hours = max(1, int(args.get("hours", 1)))
    end_ts = int(datetime.now(timezone.utc).timestamp())
    start_ts = end_ts - hours * 3600

    resp = logs.start_query(
        logGroupNames=args["log_group_names"],
        startTime=start_ts,
        endTime=end_ts,
        queryString=args["query_string"],
    )
    qid = resp["queryId"]
    return (
        f"Query started.\n"
        f"Query ID: {qid}\n\n"
        f"Call get_logs_insight_query_results with this query_id to retrieve results."
    )


async def _get_logs_insight_query_results(args: dict, creds: dict) -> str:
    logs = _client("logs", creds, args.get("region"))
    qid = args["query_id"]
    wait = args.get("wait", True)

    if wait:
        for _ in range(15):
            resp = logs.get_query_results(queryId=qid)
            if resp.get("status") in ("Complete", "Failed", "Cancelled"):
                break
            await asyncio.sleep(2)
    else:
        resp = logs.get_query_results(queryId=qid)

    status = resp.get("status", "Unknown")
    results = resp.get("results", [])

    if status == "Failed":
        return f"Query {qid} failed."
    if status in ("Running", "Scheduled"):
        return f"Query {qid} is still {status}. Call again or use wait=true."
    if not results:
        return f"Query {qid} completed with no results."

    lines = [f"Query results — {len(results)} row(s) (status: {status}):\n"]
    for row in results[:50]:
        row_dict = {f["field"]: f["value"] for f in row if not f["field"].startswith("@ptr")}
        lines.append("  " + "  |  ".join(f"{k}: {v}" for k, v in row_dict.items()))
    if len(results) > 50:
        lines.append(f"  … and {len(results) - 50} more rows")
    return "\n".join(lines)


async def _filter_log_events(args: dict, creds: dict) -> str:
    logs = _client("logs", creds, args.get("region"))
    minutes = max(1, int(args.get("minutes", 30)))
    limit = min(200, max(1, int(args.get("limit", 50))))
    end_ts = int(datetime.now(timezone.utc).timestamp() * 1000)
    start_ts = end_ts - minutes * 60 * 1000

    kwargs: dict[str, Any] = {
        "logGroupName": args["log_group_name"],
        "filterPattern": args["filter_pattern"],
        "startTime": start_ts,
        "endTime": end_ts,
        "limit": limit,
    }
    if args.get("log_stream_names"):
        kwargs["logStreamNames"] = args["log_stream_names"]

    resp = logs.filter_log_events(**kwargs)
    events = resp.get("events", [])
    if not events:
        return (
            f"No events matching '{args['filter_pattern']}' in "
            f"'{args['log_group_name']}' (last {minutes} min)."
        )

    lines = [
        f"{len(events)} event(s) matching '{args['filter_pattern']}' "
        f"in {args['log_group_name']} (last {minutes} min):\n"
    ]
    for e in events:
        ts = e.get("timestamp", 0)
        ts_str = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        stream = e.get("logStreamName", "")
        message = e.get("message", "").rstrip("\n")
        lines.append(f"  [{ts_str}] ({stream}) {message}")

    if resp.get("searchedLogStreams"):
        searched = len(resp["searchedLogStreams"])
        lines.append(f"\nSearched {searched} log stream(s).")
    return "\n".join(lines)


async def _describe_log_streams(args: dict, creds: dict) -> str:
    logs = _client("logs", creds, args.get("region"))
    kwargs: dict[str, Any] = {
        "logGroupName": args["log_group_name"],
        "orderBy": "LastEventTime",
        "descending": True,
        "limit": min(50, max(1, int(args.get("limit", 10)))),
    }
    if args.get("prefix"):
        kwargs["logStreamNamePrefix"] = args["prefix"]

    resp = logs.describe_log_streams(**kwargs)
    streams = resp.get("logStreams", [])
    if not streams:
        return f"No log streams found in '{args['log_group_name']}'."

    lines = [f"Log streams in {args['log_group_name']} ({len(streams)}):\n"]
    for s in streams:
        name = s["logStreamName"]
        last = s.get("lastEventTimestamp")
        last_str = (
            datetime.fromtimestamp(last / 1000, tz=timezone.utc).isoformat()
            if last else "no events"
        )
        lines.append(f"  {name}")
        lines.append(f"    Last event: {last_str}")
    return "\n".join(lines)


async def _get_log_events(args: dict, creds: dict) -> str:
    logs = _client("logs", creds, args.get("region"))
    limit = min(200, max(1, int(args.get("limit", 50))))
    resp = logs.get_log_events(
        logGroupName=args["log_group_name"],
        logStreamName=args["log_stream_name"],
        limit=limit,
        startFromHead=args.get("start_from_head", False),
    )
    events = resp.get("events", [])
    if not events:
        return (
            f"No log events in '{args['log_stream_name']}' "
            f"(group: {args['log_group_name']})."
        )

    lines = [
        f"Log events from {args['log_group_name']} / {args['log_stream_name']} "
        f"({len(events)} events):\n"
    ]
    for e in events:
        ts = e.get("timestamp", 0)
        ts_str = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        message = e.get("message", "").rstrip("\n")
        lines.append(f"  [{ts_str}] {message}")
    return "\n".join(lines)


async def _list_dashboards(args: dict, creds: dict) -> str:
    cw = _client("cloudwatch", creds, args.get("region"))
    kwargs: dict[str, Any] = {}
    if args.get("prefix"):
        kwargs["DashboardNamePrefix"] = args["prefix"]

    resp = cw.list_dashboards(**kwargs)
    entries = resp.get("DashboardEntries", [])
    if not entries:
        return "No CloudWatch dashboards found."

    lines = [f"CloudWatch dashboards ({len(entries)}):\n"]
    for d in entries:
        name = d.get("DashboardName", "")
        size = d.get("Size", 0)
        modified = d.get("LastModified")
        modified_str = modified.isoformat() if hasattr(modified, "isoformat") else str(modified)
        lines.append(f"  {name}  (size: {size} bytes, modified: {modified_str})")
    return "\n".join(lines)


async def _get_dashboard(args: dict, creds: dict) -> str:
    cw = _client("cloudwatch", creds, args.get("region"))
    resp = cw.get_dashboard(DashboardName=args["dashboard_name"])
    body = resp.get("DashboardBody", "{}")

    try:
        parsed = json.loads(body)
        widgets = parsed.get("widgets", [])
        lines = [f"Dashboard '{args['dashboard_name']}' — {len(widgets)} widget(s):\n"]
        for i, w in enumerate(widgets, 1):
            wtype = w.get("type", "unknown")
            props = w.get("properties", {})
            title = props.get("title", "(no title)")
            lines.append(f"  [{i}] {wtype}: {title}")
            if wtype == "metric" and props.get("metrics"):
                for m in props["metrics"][:3]:
                    lines.append(f"       metric: {m}")
            elif wtype == "alarm" and props.get("alarms"):
                for a in props["alarms"][:3]:
                    lines.append(f"       alarm: {a}")
        return "\n".join(lines)
    except (json.JSONDecodeError, TypeError):
        return f"Dashboard body (raw):\n{body[:2000]}"


async def _list_s3_buckets(args: dict, creds: dict) -> str:
    # S3 ListBuckets is global — no regional endpoint needed
    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    resp = s3.list_buckets()
    buckets = resp.get("Buckets", [])
    if not buckets:
        return "No S3 buckets found in this AWS account."

    # Get bucket locations in parallel-ish (sequential is fine for small counts)
    lines = [f"S3 buckets in this account ({len(buckets)}):\n"]
    for b in buckets:
        name = b["Name"]
        created = b.get("CreationDate")
        created_str = created.strftime("%Y-%m-%d") if hasattr(created, "strftime") else str(created)
        try:
            loc_resp = s3.get_bucket_location(Bucket=name)
            region = loc_resp.get("LocationConstraint") or "us-east-1"
        except Exception:
            region = "unknown"
        lines.append(f"  {name}  (region: {region}, created: {created_str})")
    return "\n".join(lines)


async def _get_s3_storage_metrics(args: dict, creds: dict) -> str:
    cw = _client("cloudwatch", creds, "us-east-1")  # S3 metrics always in us-east-1
    bucket_name = args["bucket_name"]
    days = max(1, int(args.get("days", 7)))
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    period = 86400  # daily

    results = {}
    for metric, storage_type in [
        ("BucketSizeBytes", "StandardStorage"),
        ("NumberOfObjects", "AllStorageTypes"),
    ]:
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/S3",
                MetricName=metric,
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "StorageType", "Value": storage_type},
                ],
                StartTime=start,
                EndTime=end,
                Period=period,
                Statistics=["Average"],
            )
            points = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
            results[metric] = points
        except Exception as exc:
            results[metric] = str(exc)

    lines = [f"S3 storage metrics for bucket '{bucket_name}' (last {days} days):\n"]

    size_points = results.get("BucketSizeBytes", [])
    if isinstance(size_points, list) and size_points:
        latest = size_points[-1]
        bytes_val = latest.get("Average", 0)
        gb = bytes_val / (1024 ** 3)
        ts = latest["Timestamp"].strftime("%Y-%m-%d")
        lines.append(f"  Storage size:   {gb:.3f} GB  (as of {ts})")
    elif isinstance(size_points, list):
        lines.append("  Storage size:   No data — enable storage metrics in S3 bucket → Properties → Metrics")
    else:
        lines.append(f"  Storage size:   Error — {size_points}")

    obj_points = results.get("NumberOfObjects", [])
    if isinstance(obj_points, list) and obj_points:
        latest = obj_points[-1]
        count = int(latest.get("Average", 0))
        ts = latest["Timestamp"].strftime("%Y-%m-%d")
        lines.append(f"  Object count:   {count:,} objects  (as of {ts})")
    elif isinstance(obj_points, list):
        lines.append("  Object count:   No data — enable storage metrics in S3 bucket → Properties → Metrics")
    else:
        lines.append(f"  Object count:   Error — {obj_points}")

    lines.append(
        "\nNote: S3 storage metrics update once per day. "
        "For request metrics (errors, latency), request metrics must be enabled per bucket."
    )
    return "\n".join(lines)


async def _list_ec2_instances(args: dict, creds: dict) -> str:
    ec2 = _client("ec2", creds, args.get("region"))
    kwargs: dict[str, Any] = {}
    state = args.get("state", "running")
    if state != "all":
        kwargs["Filters"] = [{"Name": "instance-state-name", "Values": [state]}]

    resp = ec2.describe_instances(**kwargs)
    instances = [i for r in resp.get("Reservations", []) for i in r.get("Instances", [])]
    if not instances:
        return f"No EC2 instances found (state={state})."

    name_filter = (args.get("name_filter") or "").lower()
    lines = []
    for inst in instances:
        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        name = tags.get("Name", "(no name)")
        if name_filter and name_filter not in name.lower():
            continue
        iid = inst["InstanceId"]
        itype = inst.get("InstanceType", "")
        istate = inst.get("State", {}).get("Name", "")
        priv_ip = inst.get("PrivateIpAddress", "")
        pub_ip = inst.get("PublicIpAddress", "")
        launch = inst.get("LaunchTime")
        launch_str = launch.strftime("%Y-%m-%d") if hasattr(launch, "strftime") else ""
        lines.append(
            f"  {iid}  [{istate}]  {itype}  {name}\n"
            f"    Private: {priv_ip}  Public: {pub_ip}  Launched: {launch_str}"
        )

    if not lines:
        return f"No instances matching filter '{args.get('name_filter')}'."
    return f"EC2 instances ({len(lines)}):\n\n" + "\n".join(lines)


async def _get_ec2_instance_status(args: dict, creds: dict) -> str:
    ec2 = _client("ec2", creds, args.get("region"))
    kwargs: dict[str, Any] = {}
    if args.get("instance_ids"):
        kwargs["InstanceIds"] = args["instance_ids"]

    resp = ec2.describe_instance_status(IncludeAllInstances=True, **kwargs)
    statuses = resp.get("InstanceStatuses", [])
    if not statuses:
        return "No instance status data found."

    lines = [f"EC2 instance status ({len(statuses)} instances):\n"]
    for s in statuses:
        iid = s["InstanceId"]
        istate = s.get("InstanceState", {}).get("Name", "")
        sys_chk = s.get("SystemStatus", {}).get("Status", "unknown")
        inst_chk = s.get("InstanceStatus", {}).get("Status", "unknown")
        flag = "⚠️ " if "impaired" in (sys_chk + inst_chk) or "failed" in (sys_chk + inst_chk) else ""
        lines.append(f"  {flag}{iid}  state={istate}  system={sys_chk}  instance={inst_chk}")
    return "\n".join(lines)


async def _list_rds_instances(args: dict, creds: dict) -> str:
    rds = _client("rds", creds, args.get("region"))
    resp = rds.describe_db_instances()
    instances = resp.get("DBInstances", [])
    if not instances:
        return "No RDS instances found."

    status_filter = args.get("status_filter", "").lower()
    lines = [f"RDS instances ({len(instances)}):\n"]
    for db in instances:
        status = db.get("DBInstanceStatus", "")
        if status_filter and status_filter not in status.lower():
            continue
        dbid = db["DBInstanceIdentifier"]
        engine = f"{db.get('Engine', '')} {db.get('EngineVersion', '')}"
        cls = db.get("DBInstanceClass", "")
        multi_az = "multi-AZ" if db.get("MultiAZ") else "single-AZ"
        endpoint = db.get("Endpoint", {}).get("Address", "")
        lines.append(f"  {dbid}  [{status}]  {engine}  {cls}  {multi_az}")
        if endpoint:
            lines.append(f"    Endpoint: {endpoint}")
    return "\n".join(lines)


async def _get_rds_events(args: dict, creds: dict) -> str:
    rds = _client("rds", creds, args.get("region"))
    hours = max(1, int(args.get("hours", 24)))
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    resp = rds.describe_events(
        SourceIdentifier=args["db_instance_identifier"],
        SourceType="db-instance",
        StartTime=start,
        EndTime=end,
    )
    events = resp.get("Events", [])
    if not events:
        return f"No RDS events for '{args['db_instance_identifier']}' in the last {hours}h."

    lines = [f"RDS events for '{args['db_instance_identifier']}' (last {hours}h):\n"]
    for e in events:
        ts = e.get("Date")
        ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        msg = e.get("Message", "")
        lines.append(f"  [{ts_str}] {msg}")
    return "\n".join(lines)


async def _list_lambda_functions(args: dict, creds: dict) -> str:
    lmb = _client("lambda", creds, args.get("region"))
    functions: list[dict] = []
    marker = None
    while True:
        kwargs: dict[str, Any] = {"MaxItems": 50}
        if marker:
            kwargs["Marker"] = marker
        resp = lmb.list_functions(**kwargs)
        functions.extend(resp.get("Functions", []))
        marker = resp.get("NextMarker")
        if not marker:
            break

    if not functions:
        return "No Lambda functions found."

    name_filter = (args.get("name_filter") or "").lower()
    lines = [f"Lambda functions ({len(functions)}):\n"]
    for fn in functions:
        name = fn["FunctionName"]
        if name_filter and name_filter not in name.lower():
            continue
        runtime = fn.get("Runtime", "")
        memory = fn.get("MemorySize", 0)
        timeout = fn.get("Timeout", 0)
        modified = fn.get("LastModified", "")[:10]
        lines.append(f"  {name}  {runtime}  {memory}MB  timeout={timeout}s  modified={modified}")
    return "\n".join(lines)


async def _list_ecs_clusters(args: dict, creds: dict) -> str:
    ecs = _client("ecs", creds, args.get("region"))
    arns_resp = ecs.list_clusters()
    arns = arns_resp.get("clusterArns", [])
    if not arns:
        return "No ECS clusters found."

    desc = ecs.describe_clusters(clusters=arns, include=["STATISTICS"])
    clusters = desc.get("clusters", [])
    lines = [f"ECS clusters ({len(clusters)}):\n"]
    for c in clusters:
        name = c.get("clusterName", "")
        status = c.get("status", "")
        services = c.get("activeServicesCount", 0)
        tasks = c.get("runningTasksCount", 0)
        lines.append(f"  {name}  [{status}]  services={services}  running_tasks={tasks}")
    return "\n".join(lines)


async def _list_ecs_services(args: dict, creds: dict) -> str:
    ecs = _client("ecs", creds, args.get("region"))
    cluster = args["cluster"]

    arns_resp = ecs.list_services(cluster=cluster)
    arns = arns_resp.get("serviceArns", [])
    if not arns:
        return f"No services found in cluster '{cluster}'."

    desc = ecs.describe_services(cluster=cluster, services=arns)
    services = desc.get("services", [])
    lines = [f"ECS services in '{cluster}' ({len(services)}):\n"]
    for s in services:
        name = s.get("serviceName", "")
        status = s.get("status", "")
        desired = s.get("desiredCount", 0)
        running = s.get("runningCount", 0)
        pending = s.get("pendingCount", 0)
        flag = "⚠️ " if running < desired else ""
        lines.append(
            f"  {flag}{name}  [{status}]  desired={desired}  running={running}  pending={pending}"
        )
    return "\n".join(lines)


async def _list_sqs_queues(args: dict, creds: dict) -> str:
    sqs = _client("sqs", creds, args.get("region"))
    kwargs: dict[str, Any] = {}
    if args.get("prefix"):
        kwargs["QueueNamePrefix"] = args["prefix"]

    resp = sqs.list_queues(**kwargs)
    urls = resp.get("QueueUrls", [])
    if not urls:
        return "No SQS queues found."

    lines = [f"SQS queues ({len(urls)}):\n"]
    for url in urls:
        lines.append(f"  {url}")
    return "\n".join(lines)


async def _get_sqs_queue_stats(args: dict, creds: dict) -> str:
    sqs = _client("sqs", creds, args.get("region"))
    attrs = [
        "ApproximateNumberOfMessages",
        "ApproximateNumberOfMessagesNotVisible",
        "ApproximateNumberOfMessagesDelayed",
        "CreatedTimestamp",
        "QueueArn",
    ]
    resp = sqs.get_queue_attributes(QueueUrl=args["queue_url"], AttributeNames=attrs)
    a = resp.get("Attributes", {})

    visible = int(a.get("ApproximateNumberOfMessages", 0))
    inflight = int(a.get("ApproximateNumberOfMessagesNotVisible", 0))
    delayed = int(a.get("ApproximateNumberOfMessagesDelayed", 0))
    arn = a.get("QueueArn", "")

    lines = [f"SQS queue stats for {args['queue_url'].split('/')[-1]}:\n"]
    lines.append(f"  Visible (waiting):  {visible:,}")
    lines.append(f"  In-flight:          {inflight:,}")
    lines.append(f"  Delayed:            {delayed:,}")
    lines.append(f"  ARN:                {arn}")

    if visible > 1000:
        lines.append(f"\n⚠️  High queue depth ({visible:,} messages) — possible consumer backlog.")
    return "\n".join(lines)


# ── Tool dispatch ────────────────────────────────────────────────────────────

_HANDLERS = {
    "get_active_alarms":              _get_active_alarms,
    "get_alarm_history":              _get_alarm_history,
    "get_metric_data":                _get_metric_data,
    "list_metrics":                   _list_metrics,
    "describe_log_groups":            _describe_log_groups,
    "describe_log_streams":           _describe_log_streams,
    "get_log_events":                 _get_log_events,
    "filter_log_events":              _filter_log_events,
    "execute_log_insights_query":     _execute_log_insights_query,
    "get_logs_insight_query_results": _get_logs_insight_query_results,
    "list_dashboards":                _list_dashboards,
    "get_dashboard":                  _get_dashboard,
    "list_s3_buckets":                _list_s3_buckets,
    "get_s3_storage_metrics":         _get_s3_storage_metrics,
    "list_ec2_instances":             _list_ec2_instances,
    "get_ec2_instance_status":        _get_ec2_instance_status,
    "list_rds_instances":             _list_rds_instances,
    "get_rds_events":                 _get_rds_events,
    "list_lambda_functions":          _list_lambda_functions,
    "list_ecs_clusters":              _list_ecs_clusters,
    "list_ecs_services":              _list_ecs_services,
    "list_sqs_queues":                _list_sqs_queues,
    "get_sqs_queue_stats":            _get_sqs_queue_stats,
}


async def _call_tool(name: str, args: dict, creds: dict) -> str:
    handler = _HANDLERS.get(name)
    if not handler:
        return f"Unknown tool: {name}"
    try:
        return await handler(args, creds)
    except botocore.exceptions.ClientError as exc:
        code = exc.response["Error"]["Code"]
        msg  = exc.response["Error"]["Message"]
        return f"AWS error ({code}): {msg}"
    except botocore.exceptions.NoCredentialsError:
        return (
            "No AWS credentials configured. "
            "Please configure CloudWatch in VERA Settings → Integrations."
        )
    except botocore.exceptions.EndpointResolutionError as exc:
        return f"Invalid AWS region or endpoint: {exc}"
    except Exception as exc:
        logger.exception("Tool %s failed", name)
        return f"Error: {exc}"


# ── MCP HTTP endpoint ────────────────────────────────────────────────────────

def _respond(request: Request, data: dict):
    """Return SSE or JSON based on Accept header — matches VERA McpClient expectations."""
    if "text/event-stream" in request.headers.get("Accept", ""):
        payload = f"event: message\ndata: {json.dumps(data)}\n\n"
        return StreamingResponse(
            iter([payload]),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )
    return JSONResponse(data)


@app.post("/mcp")
async def mcp_handler(request: Request):
    if not _auth_ok(request):
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None,
             "error": {"code": -32000, "message": "Unauthorized"}},
            status_code=401,
        )
    creds = _parse_creds(request)

    try:
        body = await request.json()
    except Exception:
        return _respond(request, {
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32700, "message": "Parse error"},
        })

    method = body.get("method", "")
    req_id = body.get("id")

    if method == "initialize":
        result: Any = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "cloudwatch-mcp-server", "version": "1.0.0"},
        }

    elif method in ("notifications/initialized", "notifications/cancelled"):
        return JSONResponse({"ok": True})

    elif method == "tools/list":
        result = {"tools": TOOLS}

    elif method == "tools/call":
        params  = body.get("params", {})
        name    = params.get("name", "")
        args    = params.get("arguments", {})
        text    = await _call_tool(name, args, creds)
        result  = {"content": [{"type": "text", "text": text}]}

    else:
        return _respond(request, {
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        })

    return _respond(request, {"jsonrpc": "2.0", "id": req_id, "result": result})


@app.get("/health")
def health():
    return {"ok": True, "service": "cloudwatch-mcp-server", "tools": len(TOOLS)}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8091"))
    uvicorn.run("server:app", host="0.0.0.0", port=port, log_level="info")
