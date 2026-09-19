from prometheus_client import Counter, Histogram

HTTP_REQUESTS_TOTAL = Counter(
    "agentsentinel_http_requests_total",
    "Total AgentSentinel HTTP requests",
    ["method", "path", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "agentsentinel_http_request_duration_seconds",
    "AgentSentinel HTTP request duration",
    ["method", "path"],
)

POLICY_DECISIONS_TOTAL = Counter(
    "agentsentinel_policy_decisions_total",
    "Total zero-trust policy decisions",
    ["decision", "risk_level"],
)

THREATS_DETECTED_TOTAL = Counter(
    "agentsentinel_threats_detected_total",
    "Total runtime threats detected",
    ["threat_type", "severity"],
)

TOOL_EXECUTIONS_TOTAL = Counter(
    "agentsentinel_tool_executions_total",
    "Total sandbox tool execution results",
    ["status", "tool_name"],
)