"""
CloudWatch MCP HTTP Server for VERA AI

Speaks MCP Streamable HTTP / SSE (JSON-RPC over HTTP).
AWS credentials are passed per-request in the Authorization Bearer token as JSON:
  {"ak": "ACCESS_KEY_ID", "sk": "SECRET_ACCESS_KEY", "region": "us-east-1"}

Tools:
  get_active_alarms              — currently firing CloudWatch alarms
  get_alarm_history              — state change history for RCA
  get_metric_data                — retrieve metric values over a time window
  list_metrics                   — discover available metrics for a namespace
  describe_log_groups            — list available log groups
  execute_log_insights_query     — run a Logs Insights query (returns query_id)
  get_logs_insight_query_results — retrieve results of a running query
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
            "List available CloudWatch metrics for a namespace. "
            "Use to discover what metrics exist before calling get_metric_data."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "e.g. AWS/EC2. Leave empty to list all namespaces.",
                },
                "metric_name": {
                    "type": "string",
                    "description": "Optional metric name filter.",
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
]

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


def _client(service: str, creds: dict):
    kwargs: dict[str, Any] = {
        "region_name": creds.get("region") or os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
    }
    ak = creds.get("ak") or os.getenv("AWS_ACCESS_KEY_ID")
    sk = creds.get("sk") or os.getenv("AWS_SECRET_ACCESS_KEY")
    if ak and sk:
        kwargs["aws_access_key_id"] = ak
        kwargs["aws_secret_access_key"] = sk
    return boto3.client(service, **kwargs)


# ── Tool implementations ─────────────────────────────────────────────────────

async def _get_active_alarms(args: dict, creds: dict) -> str:
    cw = _client("cloudwatch", creds)
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
    cw = _client("cloudwatch", creds)
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
    cw = _client("cloudwatch", creds)
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
    cw = _client("cloudwatch", creds)
    kwargs: dict[str, Any] = {}
    if args.get("namespace"):
        kwargs["Namespace"] = args["namespace"]
    if args.get("metric_name"):
        kwargs["MetricName"] = args["metric_name"]

    resp = cw.list_metrics(**kwargs)
    metrics = resp.get("Metrics", [])
    if not metrics:
        return "No metrics found."

    seen: set[str] = set()
    lines: list[str] = []
    for m in metrics[:100]:
        key = f"{m['Namespace']}/{m['MetricName']}"
        if key not in seen:
            seen.add(key)
            dims = ", ".join(f"{d['Name']}={d['Value']}" for d in m.get("Dimensions", []))
            lines.append(f"  {key}" + (f"  [{dims}]" if dims else ""))

    return f"Available metrics ({len(seen)} unique):\n\n" + "\n".join(lines)


async def _describe_log_groups(args: dict, creds: dict) -> str:
    logs = _client("logs", creds)
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
    logs = _client("logs", creds)
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
    logs = _client("logs", creds)
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


# ── Tool dispatch ────────────────────────────────────────────────────────────

_HANDLERS = {
    "get_active_alarms":              _get_active_alarms,
    "get_alarm_history":              _get_alarm_history,
    "get_metric_data":                _get_metric_data,
    "list_metrics":                   _list_metrics,
    "describe_log_groups":            _describe_log_groups,
    "execute_log_insights_query":     _execute_log_insights_query,
    "get_logs_insight_query_results": _get_logs_insight_query_results,
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
