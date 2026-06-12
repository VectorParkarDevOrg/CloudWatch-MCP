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
    # ── CloudTrail ───────────────────────────────────────────────────────────
    {
        "name": "lookup_cloudtrail_events",
        "description": (
            "Search CloudTrail audit events — who did what and when. "
            "Essential for RCA: find who stopped an EC2 instance, changed a security group, "
            "deleted an S3 bucket, modified an IAM policy, or deployed a Lambda. "
            "Filter by username, resource name, event name, or resource type."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "default": 24,
                    "description": "How many hours back to search. Default: 24. Max: 2160 (90 days).",
                },
                "event_name": {
                    "type": "string",
                    "description": "Filter by specific API action, e.g. StopInstances, DeleteBucket, ModifyDBInstance.",
                },
                "username": {
                    "type": "string",
                    "description": "Filter by IAM username or role name that performed the action.",
                },
                "resource_name": {
                    "type": "string",
                    "description": "Filter by resource name/ID, e.g. i-0abc123, my-bucket, sg-0def456.",
                },
                "resource_type": {
                    "type": "string",
                    "description": "Filter by resource type, e.g. AWS::EC2::Instance, AWS::S3::Bucket, AWS::RDS::DBInstance.",
                },
                "limit": {
                    "type": "integer",
                    "default": 50,
                    "description": "Maximum events to return. Default: 50.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "describe_trails",
        "description": (
            "List all CloudTrail trails configured in the account with their "
            "S3 destination, multi-region status, and log file validation setting."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "get_trail_status",
        "description": (
            "Check if a specific CloudTrail trail is actively logging. "
            "Returns latest delivery time, latest error, and whether logging is enabled."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trail_name": {
                    "type": "string",
                    "description": "Trail name or ARN from describe_trails.",
                },
            },
            "required": ["trail_name"],
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
    # ── ELB / Load Balancers ─────────────────────────────────────────────────
    {
        "name": "list_load_balancers",
        "description": "List ALB/NLB/CLB load balancers with DNS name, state, and type. Use to find load balancer ARNs before checking target health.",
        "inputSchema": {"type": "object", "properties": {"name_filter": {"type": "string", "description": "Optional name substring filter."}}, "additionalProperties": False},
    },
    {
        "name": "get_target_group_health",
        "description": "Get health of all targets (instances/IPs) in an ELB target group. Shows healthy/unhealthy/draining counts and failure reasons. Critical for incident triage.",
        "inputSchema": {"type": "object", "properties": {"load_balancer_arn": {"type": "string", "description": "Load balancer ARN from list_load_balancers. Leave empty to check all."}}, "additionalProperties": False},
    },
    # ── Auto Scaling ─────────────────────────────────────────────────────────
    {
        "name": "list_auto_scaling_groups",
        "description": "List Auto Scaling Groups with min/max/desired capacity, current instances, and health status. Use to detect capacity mismatches during incidents.",
        "inputSchema": {"type": "object", "properties": {"name_filter": {"type": "string", "description": "Optional ASG name substring filter."}}, "additionalProperties": False},
    },
    {
        "name": "get_scaling_activities",
        "description": "Get recent Auto Scaling events for an ASG — scale-in/out, instance launches/terminations, and reasons. Essential for RCA when instance count changed unexpectedly.",
        "inputSchema": {"type": "object", "properties": {"asg_name": {"type": "string", "description": "Auto Scaling Group name."}, "hours": {"type": "integer", "default": 24, "description": "Hours back to search. Default: 24."}}, "required": ["asg_name"], "additionalProperties": False},
    },
    # ── VPC / Networking ─────────────────────────────────────────────────────
    {
        "name": "list_vpcs",
        "description": "List VPCs with CIDR, name tag, and default status. Use to understand network topology.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "describe_security_group",
        "description": "Get inbound and outbound rules for a specific security group. Use to debug network connectivity issues.",
        "inputSchema": {"type": "object", "properties": {"sg_id": {"type": "string", "description": "Security group ID, e.g. sg-0abc123."}}, "required": ["sg_id"], "additionalProperties": False},
    },
    {
        "name": "list_subnets",
        "description": "List subnets with CIDR, AZ, available IPs, and VPC. Use to understand network layout and capacity.",
        "inputSchema": {"type": "object", "properties": {"vpc_id": {"type": "string", "description": "Optional VPC ID to filter by."}}, "additionalProperties": False},
    },
    # ── ElastiCache ──────────────────────────────────────────────────────────
    {
        "name": "list_elasticache_clusters",
        "description": "List ElastiCache clusters (Redis/Memcached) with engine, status, node type, and endpoint.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_elasticache_events",
        "description": "Get recent ElastiCache events — failovers, node replacements, parameter changes. Use for cache-related RCA.",
        "inputSchema": {"type": "object", "properties": {"hours": {"type": "integer", "default": 24, "description": "Hours back. Default: 24."}, "source_id": {"type": "string", "description": "Optional cluster/replication group ID filter."}}, "additionalProperties": False},
    },
    # ── DynamoDB ─────────────────────────────────────────────────────────────
    {
        "name": "list_dynamodb_tables",
        "description": "List all DynamoDB tables with their status.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "describe_dynamodb_table",
        "description": "Get DynamoDB table details — keys, GSIs, provisioned/on-demand capacity, item count, and size.",
        "inputSchema": {"type": "object", "properties": {"table_name": {"type": "string", "description": "Table name."}}, "required": ["table_name"], "additionalProperties": False},
    },
    # ── CloudFormation ───────────────────────────────────────────────────────
    {
        "name": "list_cloudformation_stacks",
        "description": "List CloudFormation stacks with status and last updated time. Use to see what was recently deployed.",
        "inputSchema": {"type": "object", "properties": {"status_filter": {"type": "string", "description": "Optional status filter, e.g. CREATE_COMPLETE, UPDATE_ROLLBACK_COMPLETE, ROLLBACK_COMPLETE."}}, "additionalProperties": False},
    },
    {
        "name": "get_stack_events",
        "description": "Get recent CloudFormation deployment events for a stack. Shows what changed, which resources failed, and why. Critical for deployment RCA.",
        "inputSchema": {"type": "object", "properties": {"stack_name": {"type": "string", "description": "Stack name or ARN."}, "limit": {"type": "integer", "default": 30, "description": "Max events. Default: 30."}}, "required": ["stack_name"], "additionalProperties": False},
    },
    # ── EKS ──────────────────────────────────────────────────────────────────
    {
        "name": "list_eks_clusters",
        "description": "List EKS (Kubernetes) clusters in the account/region.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "describe_eks_cluster",
        "description": "Get EKS cluster details — Kubernetes version, endpoint, status, VPC config, and logging configuration.",
        "inputSchema": {"type": "object", "properties": {"cluster_name": {"type": "string", "description": "EKS cluster name."}}, "required": ["cluster_name"], "additionalProperties": False},
    },
    {
        "name": "list_eks_nodegroups",
        "description": "List node groups in an EKS cluster with instance type, scaling config, and health status.",
        "inputSchema": {"type": "object", "properties": {"cluster_name": {"type": "string", "description": "EKS cluster name."}}, "required": ["cluster_name"], "additionalProperties": False},
    },
    # ── API Gateway ──────────────────────────────────────────────────────────
    {
        "name": "list_api_gateways",
        "description": "List REST APIs and HTTP APIs in API Gateway with their endpoint type and creation date.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_api_stages",
        "description": "Get deployment stages for an API Gateway REST API — stage name, throttling limits, caching, and last deployed time.",
        "inputSchema": {"type": "object", "properties": {"api_id": {"type": "string", "description": "REST API ID from list_api_gateways."}}, "required": ["api_id"], "additionalProperties": False},
    },
    # ── SNS ──────────────────────────────────────────────────────────────────
    {
        "name": "list_sns_topics",
        "description": "List SNS topics in the account/region.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_sns_topic_details",
        "description": "Get SNS topic attributes including subscriptions count, delivery policy, and KMS key.",
        "inputSchema": {"type": "object", "properties": {"topic_arn": {"type": "string", "description": "SNS topic ARN."}}, "required": ["topic_arn"], "additionalProperties": False},
    },
    # ── Route 53 ─────────────────────────────────────────────────────────────
    {
        "name": "list_hosted_zones",
        "description": "List Route 53 hosted zones (DNS zones) with record count and type (public/private).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "list_route53_health_checks",
        "description": "List Route 53 health checks with their status, target endpoint, and failure threshold.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    # ── SSM ──────────────────────────────────────────────────────────────────
    {
        "name": "list_ssm_managed_instances",
        "description": "List EC2 instances managed by SSM (Systems Manager) with ping status, OS, and last seen time. Use to check which instances are reachable via SSM.",
        "inputSchema": {"type": "object", "properties": {"ping_status": {"type": "string", "enum": ["Online", "Inactive", "ConnectionLost", "all"], "default": "all", "description": "Filter by ping status."}}, "additionalProperties": False},
    },
    # ── CloudFront ───────────────────────────────────────────────────────────
    {
        "name": "list_cloudfront_distributions",
        "description": "List CloudFront distributions with domain name, origin, status, and price class.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    # ── ECR ──────────────────────────────────────────────────────────────────
    {
        "name": "list_ecr_repositories",
        "description": "List ECR (Elastic Container Registry) repositories with URI and image count.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "describe_ecr_images",
        "description": "List images in an ECR repository with tags, digest, push date, and size. Use to see what container images are available and when they were pushed.",
        "inputSchema": {"type": "object", "properties": {"repository_name": {"type": "string", "description": "ECR repository name."}, "limit": {"type": "integer", "default": 20, "description": "Max images. Default: 20."}}, "required": ["repository_name"], "additionalProperties": False},
    },
    # ── Kinesis ──────────────────────────────────────────────────────────────
    {
        "name": "list_kinesis_streams",
        "description": "List Kinesis Data Streams with status and shard count.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "describe_kinesis_stream",
        "description": "Get Kinesis stream details — shards, retention period, encryption, and enhanced monitoring.",
        "inputSchema": {"type": "object", "properties": {"stream_name": {"type": "string", "description": "Kinesis stream name."}}, "required": ["stream_name"], "additionalProperties": False},
    },
    # ── Cost Explorer ────────────────────────────────────────────────────────
    {
        "name": "get_cost_and_usage",
        "description": "Get AWS spend broken down by service and region. Shows top cost drivers for a time period. Use to detect billing anomalies or understand monthly spend.",
        "inputSchema": {"type": "object", "properties": {"days": {"type": "integer", "default": 30, "description": "Days back to analyse. Default: 30."}, "group_by": {"type": "string", "enum": ["SERVICE", "REGION", "INSTANCE_TYPE"], "default": "SERVICE", "description": "Group spend by. Default: SERVICE."}}, "additionalProperties": False},
    },
    # ── AWS Health ───────────────────────────────────────────────────────────
    {
        "name": "get_aws_health_events",
        "description": "Get active AWS service health events — outages, degradations, and maintenance affecting your account. Use during incidents to check if AWS itself is having an issue.",
        "inputSchema": {"type": "object", "properties": {"region_filter": {"type": "string", "description": "Optional region to filter events, e.g. ap-south-1."}}, "additionalProperties": False},
    },
    # ── IAM ──────────────────────────────────────────────────────────────────
    {
        "name": "list_iam_users",
        "description": "List IAM users with creation date, last login, and whether MFA is enabled. Use for security audits.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "list_iam_roles",
        "description": "List IAM roles with trust policy summary and creation date.",
        "inputSchema": {"type": "object", "properties": {"name_filter": {"type": "string", "description": "Optional role name substring filter."}}, "additionalProperties": False},
    },
    # ── Secrets Manager ──────────────────────────────────────────────────────
    {
        "name": "list_secrets",
        "description": "List Secrets Manager secrets — names and last rotated date only, no values. Use to verify secrets exist and rotation is working.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    # ── Backup ───────────────────────────────────────────────────────────────
    {
        "name": "list_backup_jobs",
        "description": "List recent AWS Backup jobs with state (COMPLETED/FAILED/RUNNING) and resource type. Use to verify backups are succeeding.",
        "inputSchema": {"type": "object", "properties": {"state": {"type": "string", "enum": ["CREATED", "PENDING", "RUNNING", "ABORTED", "COMPLETED", "FAILED", "all"], "default": "all"}, "days": {"type": "integer", "default": 7, "description": "Days back. Default: 7."}}, "additionalProperties": False},
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


async def _lookup_cloudtrail_events(args: dict, creds: dict) -> str:
    ct = _client("cloudtrail", creds, args.get("region"))
    hours = min(2160, max(1, int(args.get("hours", 24))))
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    limit = min(200, max(1, int(args.get("limit", 50))))

    lookup_attrs = []
    if args.get("event_name"):
        lookup_attrs.append({"AttributeKey": "EventName", "AttributeValue": args["event_name"]})
    if args.get("username"):
        lookup_attrs.append({"AttributeKey": "Username", "AttributeValue": args["username"]})
    if args.get("resource_name"):
        lookup_attrs.append({"AttributeKey": "ResourceName", "AttributeValue": args["resource_name"]})
    if args.get("resource_type"):
        lookup_attrs.append({"AttributeKey": "ResourceType", "AttributeValue": args["resource_type"]})

    kwargs: dict[str, Any] = {
        "StartTime": start,
        "EndTime": end,
        "MaxResults": limit,
    }
    if lookup_attrs:
        # CloudTrail lookup supports only one attribute at a time
        kwargs["LookupAttributes"] = [lookup_attrs[0]]

    resp = ct.lookup_events(**kwargs)
    events = resp.get("Events", [])

    if not events:
        return f"No CloudTrail events found for the last {hours}h with the given filters."

    lines = [f"CloudTrail events — last {hours}h ({len(events)} results):\n"]
    for e in events:
        ts = e.get("EventTime")
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(ts, "strftime") else str(ts)
        name = e.get("EventName", "")
        user = e.get("Username", "unknown")
        source = e.get("EventSource", "")
        resources = e.get("Resources", [])
        res_str = ", ".join(
            f"{r.get('ResourceType','').split('::')[-1]}:{r.get('ResourceName','')}"
            for r in resources[:3]
        )
        lines.append(f"  [{ts_str}] {name} by {user} ({source})")
        if res_str:
            lines.append(f"    Resources: {res_str}")

    if resp.get("NextToken"):
        lines.append(f"\n  … more events available. Narrow the time range or add a filter.")
    return "\n".join(lines)


async def _describe_trails(args: dict, creds: dict) -> str:
    ct = _client("cloudtrail", creds, args.get("region"))
    resp = ct.describe_trails(includeShadowTrails=False)
    trails = resp.get("trailList", [])
    if not trails:
        return "No CloudTrail trails found. CloudTrail may not be enabled in this region/account."

    lines = [f"CloudTrail trails ({len(trails)}):\n"]
    for t in trails:
        name = t.get("Name", "")
        bucket = t.get("S3BucketName", "")
        multi = "multi-region" if t.get("IsMultiRegionTrail") else "single-region"
        validation = "log-validation=ON" if t.get("LogFileValidationEnabled") else "log-validation=OFF"
        home = t.get("HomeRegion", "")
        lines.append(f"  {name}  [{multi}]  [{validation}]  home={home}")
        lines.append(f"    S3: s3://{bucket}")
    return "\n".join(lines)


async def _get_trail_status(args: dict, creds: dict) -> str:
    ct = _client("cloudtrail", creds, args.get("region"))
    resp = ct.get_trail_status(Name=args["trail_name"])

    logging_on = resp.get("IsLogging", False)
    latest_delivery = resp.get("LatestDeliveryTime")
    latest_delivery_str = (
        latest_delivery.strftime("%Y-%m-%dT%H:%M:%SZ")
        if hasattr(latest_delivery, "strftime") else "never"
    )
    latest_error = resp.get("LatestDeliveryError", "")
    latest_digest = resp.get("LatestDigestDeliveryTime")
    latest_digest_str = (
        latest_digest.strftime("%Y-%m-%dT%H:%M:%SZ")
        if hasattr(latest_digest, "strftime") else "never"
    )

    status = "✅ LOGGING" if logging_on else "❌ NOT LOGGING"
    lines = [f"Trail '{args['trail_name']}': {status}\n"]
    lines.append(f"  Latest log delivery:    {latest_delivery_str}")
    lines.append(f"  Latest digest delivery: {latest_digest_str}")
    if latest_error:
        lines.append(f"  ⚠️  Latest error: {latest_error}")
    return "\n".join(lines)


# ── ELB handlers ─────────────────────────────────────────────────────────────

async def _list_load_balancers(args: dict, creds: dict) -> str:
    elb = _client("elbv2", creds, args.get("region"))
    resp = elb.describe_load_balancers()
    lbs = resp.get("LoadBalancers", [])
    name_filter = (args.get("name_filter") or "").lower()
    if name_filter:
        lbs = [lb for lb in lbs if name_filter in lb["LoadBalancerName"].lower()]
    if not lbs:
        return "No load balancers found."
    lines = [f"Found {len(lbs)} load balancer(s):\n"]
    for lb in lbs:
        lines.append(
            f"  {lb['LoadBalancerName']}  [{lb['Type']}]  {lb['State']['Code']}\n"
            f"    DNS: {lb['DNSName']}\n"
            f"    ARN: {lb['LoadBalancerArn']}"
        )
    return "\n".join(lines)


async def _get_target_group_health(args: dict, creds: dict) -> str:
    elb = _client("elbv2", creds, args.get("region"))
    lb_arn = args.get("load_balancer_arn")
    if lb_arn:
        tg_resp = elb.describe_target_groups(LoadBalancerArn=lb_arn)
    else:
        tg_resp = elb.describe_target_groups()
    tgs = tg_resp.get("TargetGroups", [])
    if not tgs:
        return "No target groups found."
    lines = []
    for tg in tgs:
        tg_arn = tg["TargetGroupArn"]
        tg_name = tg["TargetGroupName"]
        health = elb.describe_target_health(TargetGroupArn=tg_arn)
        targets = health.get("TargetHealthDescriptions", [])
        healthy = sum(1 for t in targets if t["TargetHealth"]["State"] == "healthy")
        unhealthy = sum(1 for t in targets if t["TargetHealth"]["State"] == "unhealthy")
        other = len(targets) - healthy - unhealthy
        lines.append(f"Target Group: {tg_name}")
        lines.append(f"  Targets: {len(targets)} total — ✅ {healthy} healthy, ❌ {unhealthy} unhealthy, ⏳ {other} other")
        for t in targets:
            state = t["TargetHealth"]["State"]
            reason = t["TargetHealth"].get("Description", "")
            port = t["Target"].get("Port", "")
            lines.append(f"    {t['Target']['Id']}:{port}  [{state}]  {reason}")
    return "\n".join(lines)


# ── Auto Scaling handlers ─────────────────────────────────────────────────────

async def _list_auto_scaling_groups(args: dict, creds: dict) -> str:
    asg = _client("autoscaling", creds, args.get("region"))
    resp = asg.describe_auto_scaling_groups()
    groups = resp.get("AutoScalingGroups", [])
    name_filter = (args.get("name_filter") or "").lower()
    if name_filter:
        groups = [g for g in groups if name_filter in g["AutoScalingGroupName"].lower()]
    if not groups:
        return "No Auto Scaling Groups found."
    lines = [f"Found {len(groups)} ASG(s):\n"]
    for g in groups:
        healthy = sum(1 for i in g.get("Instances", []) if i.get("HealthStatus") == "Healthy")
        total = len(g.get("Instances", []))
        lines.append(
            f"  {g['AutoScalingGroupName']}\n"
            f"    Desired: {g['DesiredCapacity']}  Min: {g['MinSize']}  Max: {g['MaxSize']}\n"
            f"    Instances: {total} total, {healthy} healthy\n"
            f"    Status: {g.get('Status', 'Active')}"
        )
    return "\n".join(lines)


async def _get_scaling_activities(args: dict, creds: dict) -> str:
    asg = _client("autoscaling", creds, args.get("region"))
    hours = min(720, max(1, int(args.get("hours", 24))))
    start = datetime.utcnow() - timedelta(hours=hours)
    resp = asg.describe_scaling_activities(
        AutoScalingGroupName=args["asg_name"],
        MaxRecords=50,
    )
    activities = [
        a for a in resp.get("Activities", [])
        if a.get("StartTime") and a["StartTime"].replace(tzinfo=None) >= start
    ]
    if not activities:
        return f"No scaling activities for '{args['asg_name']}' in the last {hours}h."
    lines = [f"Scaling activities for '{args['asg_name']}' (last {hours}h):\n"]
    for a in activities:
        ts = a["StartTime"].strftime("%Y-%m-%d %H:%M") if hasattr(a["StartTime"], "strftime") else str(a["StartTime"])
        lines.append(f"  [{ts}] {a['StatusCode']}  —  {a.get('Description', '')}")
        if a.get("Cause"):
            lines.append(f"    Cause: {a['Cause'][:200]}")
    return "\n".join(lines)


# ── VPC handlers ──────────────────────────────────────────────────────────────

async def _list_vpcs(args: dict, creds: dict) -> str:
    ec2 = _client("ec2", creds, args.get("region"))
    resp = ec2.describe_vpcs()
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        return "No VPCs found."
    lines = [f"Found {len(vpcs)} VPC(s):\n"]
    for v in vpcs:
        name = next((t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"), "(no name)")
        default = " [DEFAULT]" if v.get("IsDefault") else ""
        lines.append(f"  {v['VpcId']}  {v['CidrBlock']}  {name}{default}")
    return "\n".join(lines)


async def _describe_security_group(args: dict, creds: dict) -> str:
    ec2 = _client("ec2", creds, args.get("region"))
    resp = ec2.describe_security_groups(GroupIds=[args["sg_id"]])
    sgs = resp.get("SecurityGroups", [])
    if not sgs:
        return f"Security group {args['sg_id']} not found."
    sg = sgs[0]
    lines = [f"Security Group: {sg['GroupId']}  ({sg['GroupName']})\nDescription: {sg.get('Description', '')}"]

    def fmt_rule(rule, direction):
        proto = rule.get("IpProtocol", "-1")
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        port_str = "ALL" if proto == "-1" else (f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}")
        sources = [r["CidrIp"] for r in rule.get("IpRanges", [])]
        sources += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
        sources += [f"sg:{r['GroupId']}" for r in rule.get("UserIdGroupPairs", [])]
        return f"    {direction}  proto={proto}  port={port_str}  from={', '.join(sources) or 'all'}"

    lines.append("\nInbound:")
    for r in sg.get("IpPermissions", []):
        lines.append(fmt_rule(r, "ALLOW"))
    lines.append("\nOutbound:")
    for r in sg.get("IpPermissionsEgress", []):
        lines.append(fmt_rule(r, "ALLOW"))
    return "\n".join(lines)


async def _list_subnets(args: dict, creds: dict) -> str:
    ec2 = _client("ec2", creds, args.get("region"))
    kwargs = {}
    if args.get("vpc_id"):
        kwargs["Filters"] = [{"Name": "vpc-id", "Values": [args["vpc_id"]]}]
    resp = ec2.describe_subnets(**kwargs)
    subnets = resp.get("Subnets", [])
    if not subnets:
        return "No subnets found."
    lines = [f"Found {len(subnets)} subnet(s):\n"]
    for s in subnets:
        name = next((t["Value"] for t in s.get("Tags", []) if t["Key"] == "Name"), "(no name)")
        lines.append(
            f"  {s['SubnetId']}  {s['CidrBlock']}  AZ:{s['AvailabilityZone']}  "
            f"free_ips:{s['AvailableIpAddressCount']}  vpc:{s['VpcId']}  {name}"
        )
    return "\n".join(lines)


# ── ElastiCache handlers ──────────────────────────────────────────────────────

async def _list_elasticache_clusters(args: dict, creds: dict) -> str:
    ec = _client("elasticache", creds, args.get("region"))
    resp = ec.describe_cache_clusters(ShowCacheNodeInfo=True)
    clusters = resp.get("CacheClusters", [])
    if not clusters:
        return "No ElastiCache clusters found."
    lines = [f"Found {len(clusters)} ElastiCache cluster(s):\n"]
    for c in clusters:
        endpoint = ""
        if c.get("ConfigurationEndpoint"):
            endpoint = f"{c['ConfigurationEndpoint']['Address']}:{c['ConfigurationEndpoint']['Port']}"
        elif c.get("CacheNodes") and c["CacheNodes"][0].get("Endpoint"):
            endpoint = f"{c['CacheNodes'][0]['Endpoint']['Address']}:{c['CacheNodes'][0]['Endpoint']['Port']}"
        lines.append(
            f"  {c['CacheClusterId']}  [{c['Engine']} {c['EngineVersion']}]  "
            f"{c['CacheNodeType']}  {c['CacheClusterStatus']}\n"
            f"    Nodes: {c['NumCacheNodes']}  Endpoint: {endpoint}"
        )
    return "\n".join(lines)


async def _get_elasticache_events(args: dict, creds: dict) -> str:
    ec = _client("elasticache", creds, args.get("region"))
    hours = min(336, max(1, int(args.get("hours", 24))))
    start = datetime.utcnow() - timedelta(hours=hours)
    kwargs: dict = {"StartTime": start, "MaxRecords": 50}
    if args.get("source_id"):
        kwargs["SourceIdentifier"] = args["source_id"]
    resp = ec.describe_events(**kwargs)
    events = resp.get("Events", [])
    if not events:
        return f"No ElastiCache events in the last {hours}h."
    lines = [f"ElastiCache events (last {hours}h):\n"]
    for e in events:
        ts = e["Date"].strftime("%Y-%m-%d %H:%M") if hasattr(e["Date"], "strftime") else str(e["Date"])
        lines.append(f"  [{ts}]  {e.get('SourceIdentifier', '')}  —  {e['Message']}")
    return "\n".join(lines)


# ── DynamoDB handlers ─────────────────────────────────────────────────────────

async def _list_dynamodb_tables(args: dict, creds: dict) -> str:
    ddb = _client("dynamodb", creds, args.get("region"))
    tables = []
    kwargs: dict = {}
    while True:
        resp = ddb.list_tables(**kwargs)
        tables.extend(resp.get("TableNames", []))
        if not resp.get("LastEvaluatedTableName"):
            break
        kwargs["ExclusiveStartTableName"] = resp["LastEvaluatedTableName"]
    if not tables:
        return "No DynamoDB tables found."
    return f"DynamoDB tables ({len(tables)}):\n" + "\n".join(f"  {t}" for t in tables)


async def _describe_dynamodb_table(args: dict, creds: dict) -> str:
    ddb = _client("dynamodb", creds, args.get("region"))
    resp = ddb.describe_table(TableName=args["table_name"])
    t = resp["Table"]
    billing = t.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
    lines = [
        f"Table: {t['TableName']}  Status: {t['TableStatus']}",
        f"  Billing mode: {billing}",
        f"  Item count: {t.get('ItemCount', 'N/A')}",
        f"  Size bytes: {t.get('TableSizeBytes', 'N/A')}",
    ]
    for attr in t.get("AttributeDefinitions", []):
        lines.append(f"  Attribute: {attr['AttributeName']} ({attr['AttributeType']})")
    for key in t.get("KeySchema", []):
        lines.append(f"  Key: {key['AttributeName']} ({key['KeyType']})")
    for gsi in t.get("GlobalSecondaryIndexes", []):
        lines.append(f"  GSI: {gsi['IndexName']}  status:{gsi.get('IndexStatus', '?')}")
    return "\n".join(lines)


# ── CloudFormation handlers ───────────────────────────────────────────────────

async def _list_cloudformation_stacks(args: dict, creds: dict) -> str:
    cf = _client("cloudformation", creds, args.get("region"))
    all_statuses = [
        "CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE",
        "ROLLBACK_IN_PROGRESS", "ROLLBACK_FAILED", "ROLLBACK_COMPLETE",
        "DELETE_IN_PROGRESS", "DELETE_FAILED",
        "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
        "UPDATE_COMPLETE", "UPDATE_FAILED",
        "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE",
        "REVIEW_IN_PROGRESS", "IMPORT_IN_PROGRESS", "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_IN_PROGRESS", "IMPORT_ROLLBACK_FAILED", "IMPORT_ROLLBACK_COMPLETE",
    ]
    status_filter = args.get("status_filter")
    if status_filter and status_filter in all_statuses:
        resp = cf.list_stacks(StackStatusFilter=[status_filter])
    else:
        resp = cf.list_stacks(StackStatusFilter=[s for s in all_statuses if "DELETE" not in s])
    stacks = resp.get("StackSummaries", [])
    if not stacks:
        return "No CloudFormation stacks found."
    lines = [f"Found {len(stacks)} stack(s):\n"]
    for s in stacks:
        updated = s.get("LastUpdatedTime") or s.get("CreationTime")
        ts = updated.strftime("%Y-%m-%d %H:%M") if hasattr(updated, "strftime") else str(updated)
        lines.append(f"  {s['StackName']}  [{s['StackStatus']}]  last updated: {ts}")
    return "\n".join(lines)


async def _get_stack_events(args: dict, creds: dict) -> str:
    cf = _client("cloudformation", creds, args.get("region"))
    resp = cf.describe_stack_events(StackName=args["stack_name"])
    events = resp.get("StackEvents", [])[:int(args.get("limit", 30))]
    if not events:
        return f"No events found for stack '{args['stack_name']}'."
    lines = [f"CloudFormation events for '{args['stack_name']}':\n"]
    for e in events:
        ts = e["Timestamp"].strftime("%Y-%m-%d %H:%M") if hasattr(e["Timestamp"], "strftime") else str(e["Timestamp"])
        reason = f"  ⚠️  {e['ResourceStatusReason']}" if e.get("ResourceStatusReason") else ""
        lines.append(
            f"  [{ts}]  {e['ResourceType']}  {e['ResourceStatus']}{reason}"
        )
    return "\n".join(lines)


# ── EKS handlers ──────────────────────────────────────────────────────────────

async def _list_eks_clusters(args: dict, creds: dict) -> str:
    eks = _client("eks", creds, args.get("region"))
    resp = eks.list_clusters()
    clusters = resp.get("clusters", [])
    if not clusters:
        return "No EKS clusters found."
    return f"EKS clusters ({len(clusters)}):\n" + "\n".join(f"  {c}" for c in clusters)


async def _describe_eks_cluster(args: dict, creds: dict) -> str:
    eks = _client("eks", creds, args.get("region"))
    resp = eks.describe_cluster(name=args["cluster_name"])
    c = resp["cluster"]
    logging_types = [
        t["types"] for t in c.get("logging", {}).get("clusterLogging", []) if t.get("enabled")
    ]
    lines = [
        f"EKS Cluster: {c['name']}  Status: {c['status']}",
        f"  Kubernetes version: {c['version']}",
        f"  Endpoint: {c.get('endpoint', 'N/A')}",
        f"  VPC: {c.get('resourcesVpcConfig', {}).get('vpcId', 'N/A')}",
        f"  Logging: {logging_types if logging_types else 'none'}",
        f"  Created: {c['createdAt'].strftime('%Y-%m-%d') if hasattr(c.get('createdAt'), 'strftime') else 'N/A'}",
    ]
    return "\n".join(lines)


async def _list_eks_nodegroups(args: dict, creds: dict) -> str:
    eks = _client("eks", creds, args.get("region"))
    resp = eks.list_nodegroups(clusterName=args["cluster_name"])
    nodegroups = resp.get("nodegroups", [])
    if not nodegroups:
        return f"No node groups in cluster '{args['cluster_name']}'."
    lines = [f"Node groups in '{args['cluster_name']}':\n"]
    for ng_name in nodegroups:
        ng_resp = eks.describe_nodegroup(clusterName=args["cluster_name"], nodegroupName=ng_name)
        ng = ng_resp["nodegroup"]
        scaling = ng.get("scalingConfig", {})
        lines.append(
            f"  {ng_name}  [{ng['status']}]\n"
            f"    Instance type: {ng.get('instanceTypes', ['?'])[0]}\n"
            f"    Scaling: min={scaling.get('minSize')} desired={scaling.get('desiredSize')} max={scaling.get('maxSize')}\n"
            f"    Health: {ng.get('health', {}).get('issues', 'OK')}"
        )
    return "\n".join(lines)


# ── API Gateway handlers ──────────────────────────────────────────────────────

async def _list_api_gateways(args: dict, creds: dict) -> str:
    apigw = _client("apigateway", creds, args.get("region"))
    resp = apigw.get_rest_apis()
    apis = resp.get("items", [])
    if not apis:
        return "No REST APIs found in API Gateway."
    lines = [f"Found {len(apis)} REST API(s):\n"]
    for a in apis:
        endpoint_type = a.get("endpointConfiguration", {}).get("types", ["?"])[0]
        lines.append(f"  {a['id']}  {a['name']}  [{endpoint_type}]  created: {a.get('createdDate', '?')}")
    return "\n".join(lines)


async def _get_api_stages(args: dict, creds: dict) -> str:
    apigw = _client("apigateway", creds, args.get("region"))
    resp = apigw.get_stages(restApiId=args["api_id"])
    stages = resp.get("item", [])
    if not stages:
        return f"No stages found for API {args['api_id']}."
    lines = [f"Stages for API '{args['api_id']}':\n"]
    for s in stages:
        ts = s.get("lastUpdatedDate", "?")
        ts_str = ts.strftime("%Y-%m-%d %H:%M") if hasattr(ts, "strftime") else str(ts)
        throttle = s.get("defaultRouteSettings", {})
        lines.append(
            f"  {s['stageName']}  deployed: {s.get('deploymentId', '?')}  last updated: {ts_str}\n"
            f"    Throttle burst: {s.get('defaultRouteSettings', {}).get('throttlingBurstLimit', 'default')}  "
            f"rate: {s.get('defaultRouteSettings', {}).get('throttlingRateLimit', 'default')}"
        )
    return "\n".join(lines)


# ── SNS handlers ──────────────────────────────────────────────────────────────

async def _list_sns_topics(args: dict, creds: dict) -> str:
    sns = _client("sns", creds, args.get("region"))
    topics = []
    kwargs: dict = {}
    while True:
        resp = sns.list_topics(**kwargs)
        topics.extend(resp.get("Topics", []))
        if not resp.get("NextToken"):
            break
        kwargs["NextToken"] = resp["NextToken"]
    if not topics:
        return "No SNS topics found."
    return f"SNS topics ({len(topics)}):\n" + "\n".join(f"  {t['TopicArn']}" for t in topics)


async def _get_sns_topic_details(args: dict, creds: dict) -> str:
    sns = _client("sns", creds, args.get("region"))
    attrs = sns.get_topic_attributes(TopicArn=args["topic_arn"])["Attributes"]
    subs = sns.list_subscriptions_by_topic(TopicArn=args["topic_arn"])
    sub_list = subs.get("Subscriptions", [])
    lines = [
        f"SNS Topic: {args['topic_arn']}",
        f"  Display name: {attrs.get('DisplayName', '(none)')}",
        f"  Subscriptions confirmed: {attrs.get('SubscriptionsConfirmed', 0)}",
        f"  Subscriptions pending:   {attrs.get('SubscriptionsPending', 0)}",
        f"  KMS key: {attrs.get('KmsMasterKeyId', 'none')}",
        f"\nSubscriptions ({len(sub_list)}):",
    ]
    for s in sub_list[:20]:
        lines.append(f"  {s['Protocol']}  {s['Endpoint']}  [{s['SubscriptionArn'].split(':')[-1]}]")
    return "\n".join(lines)


# ── Route 53 handlers ─────────────────────────────────────────────────────────

async def _list_hosted_zones(args: dict, creds: dict) -> str:
    r53 = boto3.client("route53",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    resp = r53.list_hosted_zones()
    zones = resp.get("HostedZones", [])
    if not zones:
        return "No hosted zones found."
    lines = [f"Route 53 hosted zones ({len(zones)}):\n"]
    for z in zones:
        zone_type = "PRIVATE" if z["Config"].get("PrivateZone") else "PUBLIC"
        lines.append(f"  {z['Name']}  [{zone_type}]  records: {z['ResourceRecordSetCount']}  id: {z['Id'].split('/')[-1]}")
    return "\n".join(lines)


async def _list_route53_health_checks(args: dict, creds: dict) -> str:
    r53 = boto3.client("route53",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    resp = r53.list_health_checks()
    checks = resp.get("HealthChecks", [])
    if not checks:
        return "No Route 53 health checks found."
    lines = [f"Route 53 health checks ({len(checks)}):\n"]
    for hc in checks:
        cfg = hc.get("HealthCheckConfig", {})
        endpoint = f"{cfg.get('FullyQualifiedDomainName') or cfg.get('IPAddress', '?')}:{cfg.get('Port', '?')}"
        lines.append(f"  {hc['Id']}  {cfg.get('Type', '?')}  {endpoint}  threshold:{cfg.get('FailureThreshold', '?')}")
    return "\n".join(lines)


# ── SSM handler ───────────────────────────────────────────────────────────────

async def _list_ssm_managed_instances(args: dict, creds: dict) -> str:
    ssm = _client("ssm", creds, args.get("region"))
    ping_status = args.get("ping_status", "all")
    filters = []
    if ping_status and ping_status != "all":
        filters.append({"Key": "PingStatus", "Values": [ping_status]})
    kwargs: dict = {"Filters": filters} if filters else {}
    resp = ssm.describe_instance_information(**kwargs)
    instances = resp.get("InstanceInformationList", [])
    if not instances:
        return "No SSM-managed instances found."
    lines = [f"SSM managed instances ({len(instances)}):\n"]
    for i in instances:
        last_ping = i.get("LastPingDateTime")
        last_ping_str = last_ping.strftime("%Y-%m-%d %H:%M") if hasattr(last_ping, "strftime") else "?"
        lines.append(
            f"  {i['InstanceId']}  [{i['PingStatus']}]  {i.get('PlatformName', '?')} {i.get('PlatformVersion', '')}\n"
            f"    Agent: {i.get('AgentVersion', '?')}  Last ping: {last_ping_str}"
        )
    return "\n".join(lines)


# ── CloudFront handler ────────────────────────────────────────────────────────

async def _list_cloudfront_distributions(args: dict, creds: dict) -> str:
    cf = boto3.client("cloudfront",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    resp = cf.list_distributions()
    dist_list = resp.get("DistributionList", {}).get("Items", [])
    if not dist_list:
        return "No CloudFront distributions found."
    lines = [f"CloudFront distributions ({len(dist_list)}):\n"]
    for d in dist_list:
        origins = [o["DomainName"] for o in d.get("Origins", {}).get("Items", [])]
        lines.append(
            f"  {d['DomainName']}  [{d['Status']}]  {d.get('PriceClass', '?')}\n"
            f"    Origins: {', '.join(origins)}\n"
            f"    ID: {d['Id']}"
        )
    return "\n".join(lines)


# ── ECR handlers ──────────────────────────────────────────────────────────────

async def _list_ecr_repositories(args: dict, creds: dict) -> str:
    ecr = _client("ecr", creds, args.get("region"))
    resp = ecr.describe_repositories()
    repos = resp.get("repositories", [])
    if not repos:
        return "No ECR repositories found."
    lines = [f"ECR repositories ({len(repos)}):\n"]
    for r in repos:
        lines.append(f"  {r['repositoryName']}  URI: {r['repositoryUri']}")
    return "\n".join(lines)


async def _describe_ecr_images(args: dict, creds: dict) -> str:
    ecr = _client("ecr", creds, args.get("region"))
    resp = ecr.describe_images(
        repositoryName=args["repository_name"],
        filter={"tagStatus": "ANY"},
    )
    images = sorted(
        resp.get("imageDetails", []),
        key=lambda i: i.get("imagePushedAt", 0),
        reverse=True,
    )[:int(args.get("limit", 20))]
    if not images:
        return f"No images found in '{args['repository_name']}'."
    lines = [f"Images in '{args['repository_name']}' (newest first):\n"]
    for img in images:
        pushed = img.get("imagePushedAt")
        pushed_str = pushed.strftime("%Y-%m-%d %H:%M") if hasattr(pushed, "strftime") else "?"
        size_mb = round(img.get("imageSizeInBytes", 0) / 1024 / 1024, 1)
        tags = ", ".join(img.get("imageTags", [])) or "<untagged>"
        lines.append(f"  {tags}  pushed: {pushed_str}  size: {size_mb}MB  digest: {img['imageDigest'][:19]}…")
    return "\n".join(lines)


# ── Kinesis handlers ──────────────────────────────────────────────────────────

async def _list_kinesis_streams(args: dict, creds: dict) -> str:
    kin = _client("kinesis", creds, args.get("region"))
    resp = kin.list_streams()
    streams = resp.get("StreamNames", [])
    if not streams:
        return "No Kinesis streams found."
    return f"Kinesis streams ({len(streams)}):\n" + "\n".join(f"  {s}" for s in streams)


async def _describe_kinesis_stream(args: dict, creds: dict) -> str:
    kin = _client("kinesis", creds, args.get("region"))
    resp = kin.describe_stream(StreamName=args["stream_name"])
    desc = resp["StreamDescription"]
    lines = [
        f"Kinesis Stream: {desc['StreamName']}  Status: {desc['StreamStatus']}",
        f"  Shards: {len(desc.get('Shards', []))}",
        f"  Retention (hours): {desc.get('RetentionPeriodHours', '?')}",
        f"  Encryption: {desc.get('EncryptionType', 'NONE')}",
        f"  Enhanced monitoring: {[m['ShardLevelMetrics'] for m in desc.get('EnhancedMonitoring', [])]}",
    ]
    return "\n".join(lines)


# ── Cost Explorer handler ─────────────────────────────────────────────────────

async def _get_cost_and_usage(args: dict, creds: dict) -> str:
    ce = boto3.client("ce",
        region_name="us-east-1",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    days = min(365, max(1, int(args.get("days", 30))))
    end = datetime.utcnow().strftime("%Y-%m-%d")
    start = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    group_by = args.get("group_by", "SERVICE")
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": group_by}],
    )
    results = resp.get("ResultsByTime", [])
    if not results:
        return "No cost data found."
    total_by_group: dict = {}
    for period in results:
        for group in period.get("Groups", []):
            key = group["Keys"][0]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            total_by_group[key] = total_by_group.get(key, 0.0) + amount
    sorted_groups = sorted(total_by_group.items(), key=lambda x: x[1], reverse=True)
    total = sum(v for _, v in sorted_groups)
    lines = [f"AWS cost by {group_by} ({start} → {end}) — Total: ${total:.2f}\n"]
    for name, cost in sorted_groups[:25]:
        if cost > 0.01:
            lines.append(f"  {name:<40} ${cost:>10.2f}")
    return "\n".join(lines)


# ── AWS Health handler ────────────────────────────────────────────────────────

async def _get_aws_health_events(args: dict, creds: dict) -> str:
    health = boto3.client("health",
        region_name="us-east-1",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    filters: dict = {"eventStatusCodes": ["open", "upcoming"]}
    if args.get("region_filter"):
        filters["regions"] = [args["region_filter"]]
    resp = health.describe_events(filter=filters)
    events = resp.get("events", [])
    if not events:
        return "No active AWS Health events. All services appear healthy."
    lines = [f"Active AWS Health events ({len(events)}):\n"]
    for e in events:
        start = e.get("startTime")
        start_str = start.strftime("%Y-%m-%d %H:%M") if hasattr(start, "strftime") else "?"
        lines.append(
            f"  [{e['eventTypeCode']}]  {e.get('service', '?')}  region:{e.get('region', 'global')}\n"
            f"    Status: {e['statusCode']}  Since: {start_str}"
        )
    return "\n".join(lines)


# ── IAM handlers ──────────────────────────────────────────────────────────────

async def _list_iam_users(args: dict, creds: dict) -> str:
    iam = boto3.client("iam",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    resp = iam.list_users()
    users = resp.get("Users", [])
    if not users:
        return "No IAM users found."
    lines = [f"IAM users ({len(users)}):\n"]
    for u in users:
        last_login = u.get("PasswordLastUsed")
        last_login_str = last_login.strftime("%Y-%m-%d") if hasattr(last_login, "strftime") else "never"
        created = u.get("CreateDate")
        created_str = created.strftime("%Y-%m-%d") if hasattr(created, "strftime") else "?"
        lines.append(f"  {u['UserName']}  created:{created_str}  last_login:{last_login_str}")
    return "\n".join(lines)


async def _list_iam_roles(args: dict, creds: dict) -> str:
    iam = boto3.client("iam",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    resp = iam.list_roles()
    roles = resp.get("Roles", [])
    name_filter = (args.get("name_filter") or "").lower()
    if name_filter:
        roles = [r for r in roles if name_filter in r["RoleName"].lower()]
    if not roles:
        return "No IAM roles found."
    lines = [f"IAM roles ({len(roles)}):\n"]
    for r in roles[:50]:
        created = r.get("CreateDate")
        created_str = created.strftime("%Y-%m-%d") if hasattr(created, "strftime") else "?"
        lines.append(f"  {r['RoleName']}  created:{created_str}  path:{r.get('Path', '/')}")
    if len(roles) > 50:
        lines.append(f"  … and {len(roles) - 50} more (use name_filter to narrow results)")
    return "\n".join(lines)


# ── Secrets Manager handler ───────────────────────────────────────────────────

async def _list_secrets(args: dict, creds: dict) -> str:
    sm = _client("secretsmanager", creds, args.get("region"))
    secrets = []
    kwargs: dict = {}
    while True:
        resp = sm.list_secrets(**kwargs)
        secrets.extend(resp.get("SecretList", []))
        if not resp.get("NextToken"):
            break
        kwargs["NextToken"] = resp["NextToken"]
    if not secrets:
        return "No secrets found in Secrets Manager."
    lines = [f"Secrets Manager ({len(secrets)} secrets):\n"]
    for s in secrets:
        rotated = s.get("LastRotatedDate")
        rotated_str = rotated.strftime("%Y-%m-%d") if hasattr(rotated, "strftime") else "never rotated"
        lines.append(f"  {s['Name']}  last_rotated:{rotated_str}")
    return "\n".join(lines)


# ── Backup handler ────────────────────────────────────────────────────────────

async def _list_backup_jobs(args: dict, creds: dict) -> str:
    bk = _client("backup", creds, args.get("region"))
    days = min(90, max(1, int(args.get("days", 7))))
    start = datetime.utcnow() - timedelta(days=days)
    state = args.get("state", "all")
    kwargs: dict = {"ByCreatedAfter": start}
    if state and state != "all":
        kwargs["ByState"] = state
    resp = bk.list_backup_jobs(**kwargs)
    jobs = resp.get("BackupJobs", [])
    if not jobs:
        return f"No backup jobs found in the last {days} days."
    lines = [f"Backup jobs (last {days}d) — {len(jobs)} found:\n"]
    for j in jobs:
        created = j.get("CreationDate")
        created_str = created.strftime("%Y-%m-%d %H:%M") if hasattr(created, "strftime") else "?"
        lines.append(
            f"  [{j['State']}]  {j.get('ResourceType', '?')}  {created_str}\n"
            f"    Resource: {j.get('ResourceArn', '?')}"
        )
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
    "lookup_cloudtrail_events":       _lookup_cloudtrail_events,
    "describe_trails":                _describe_trails,
    "get_trail_status":               _get_trail_status,
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
    # ELB
    "list_load_balancers":            _list_load_balancers,
    "get_target_group_health":        _get_target_group_health,
    # Auto Scaling
    "list_auto_scaling_groups":       _list_auto_scaling_groups,
    "get_scaling_activities":         _get_scaling_activities,
    # VPC
    "list_vpcs":                      _list_vpcs,
    "describe_security_group":        _describe_security_group,
    "list_subnets":                   _list_subnets,
    # ElastiCache
    "list_elasticache_clusters":      _list_elasticache_clusters,
    "get_elasticache_events":         _get_elasticache_events,
    # DynamoDB
    "list_dynamodb_tables":           _list_dynamodb_tables,
    "describe_dynamodb_table":        _describe_dynamodb_table,
    # CloudFormation
    "list_cloudformation_stacks":     _list_cloudformation_stacks,
    "get_stack_events":               _get_stack_events,
    # EKS
    "list_eks_clusters":              _list_eks_clusters,
    "describe_eks_cluster":           _describe_eks_cluster,
    "list_eks_nodegroups":            _list_eks_nodegroups,
    # API Gateway
    "list_api_gateways":              _list_api_gateways,
    "get_api_stages":                 _get_api_stages,
    # SNS
    "list_sns_topics":                _list_sns_topics,
    "get_sns_topic_details":          _get_sns_topic_details,
    # Route 53
    "list_hosted_zones":              _list_hosted_zones,
    "list_route53_health_checks":     _list_route53_health_checks,
    # SSM
    "list_ssm_managed_instances":     _list_ssm_managed_instances,
    # CloudFront
    "list_cloudfront_distributions":  _list_cloudfront_distributions,
    # ECR
    "list_ecr_repositories":          _list_ecr_repositories,
    "describe_ecr_images":            _describe_ecr_images,
    # Kinesis
    "list_kinesis_streams":           _list_kinesis_streams,
    "describe_kinesis_stream":        _describe_kinesis_stream,
    # Cost Explorer
    "get_cost_and_usage":             _get_cost_and_usage,
    # AWS Health
    "get_aws_health_events":          _get_aws_health_events,
    # IAM
    "list_iam_users":                 _list_iam_users,
    "list_iam_roles":                 _list_iam_roles,
    # Secrets Manager
    "list_secrets":                   _list_secrets,
    # Backup
    "list_backup_jobs":               _list_backup_jobs,
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
