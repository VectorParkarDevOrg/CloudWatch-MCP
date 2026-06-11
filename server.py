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
