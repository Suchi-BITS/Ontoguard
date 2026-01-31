# OntoGuard: Ontology-Based Semantic Firewall - System Design

## Overview

OntoGuard is a semantic validation layer that prevents AI agents from making semantically invalid or business-rule-violating actions. It acts as a firewall between agent reasoning and tool execution.

**The $4.6M Problem:**
A financial services company's AI agent processed 2,300 refunds totaling $4.6M to wrong accounts because it didn't understand semantic business rules after a database schema change.

**OntoGuard's Solution:**
Validate every action against business ontologies BEFORE execution, preventing catastrophic mistakes.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    AI AGENT LAYER                           │
│  (LangChain, AutoGen, CrewAI, Custom Agents)               │
│  Agent reasoning: "I should process a $2000 refund"        │
└────────────────────────┬───────────────────────────────────┘
                         │
                         ↓ Action Intent
                         │
┌────────────────────────────────────────────────────────────┐
│                  ONTOGUARD FIREWALL                         │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  1. Action Parser                                     │ │
│  │  - Extract: action, entity, context                   │ │
│  └──────────────────────────────────────────────────────┘ │
│                         ↓                                   │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  2. Ontology Loader                                   │ │
│  │  - Business rules from OWL/YAML/JSON                  │ │
│  │  - Permission mappings                                │ │
│  │  - Constraint definitions                             │ │
│  └──────────────────────────────────────────────────────┘ │
│                         ↓                                   │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  3. Rule Engine                                       │ │
│  │  - Permission rules: role-based access                │ │
│  │  - Temporal rules: time-based constraints             │ │
│  │  - Quantitative rules: amount/count limits            │ │
│  │  - State rules: entity state validation               │ │
│  │  - Compliance rules: regulatory requirements          │ │
│  └──────────────────────────────────────────────────────┘ │
│                         ↓                                   │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  4. Validation Result                                 │ │
│  │  - ALLOWED: Execute action                            │ │
│  │  - DENIED: Block + suggest alternatives               │ │
│  │  - REQUIRES_APPROVAL: Escalate to human              │ │
│  └──────────────────────────────────────────────────────┘ │
│                         ↓                                   │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  5. Audit Logger                                      │ │
│  │  - Every validation logged                            │ │
│  │  - Compliance trail                                   │ │
│  │  - Analytics & monitoring                             │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                             │
└────────────────────────┬───────────────────────────────────┘
                         │
                    ALLOWED / DENIED
                         │
                         ↓
┌────────────────────────────────────────────────────────────┐
│                   TOOL EXECUTION LAYER                      │
│  (MCP Tools, Database, APIs, External Systems)             │
│  Only executed if OntoGuard validation passes              │
└────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Ontology Parser

**Purpose:** Load and parse business ontologies from various formats

**Supported Formats:**
- OWL (Web Ontology Language) - Full semantic web standard
- YAML - Human-readable, simple to write
- JSON - Structured, easy to generate programmatically

**Parsed Elements:**
- Entity definitions (Order, Customer, Product, etc.)
- Relationship mappings
- Business rules with conditions
- Permission hierarchies
- Constraint specifications

**Example YAML Ontology:**
```yaml
entities:
  Order:
    - order_id
    - customer_id
    - status
    - created_at
    - total_amount

rules:
  - id: order_cancel_24h
    type: temporal
    entity: Order
    action: cancel
    condition: order_age <= 24 hours
    constraint:
      max_age_hours: 24
    error_message: Orders can only be cancelled within 24 hours
    suggested_alternatives:
      - request_manager_override
      - contact_support
```

### 2. Rule Engine

**Purpose:** Evaluate business rules against action contexts

**Rule Types:**

**PERMISSION Rules:**
- Role-based access control
- Permission verification
- Example: "Only admins can delete customers"

**TEMPORAL Rules:**
- Time-window constraints
- Age-based restrictions
- Example: "Orders can only be cancelled within 24 hours"

**QUANTITATIVE Rules:**
- Amount/count limits
- Threshold validation
- Example: "Refunds over $1000 require manager approval"

**STATE-BASED Rules:**
- Entity state validation
- Workflow enforcement
- Example: "Cannot delete shipped orders"

**COMPLIANCE Rules:**
- Regulatory requirements
- Audit requirements
- Example: "PII access requires approval"

**Rule Evaluation Algorithm:**
```
1. Filter rules applicable to (entity, action) pair
2. Sort by priority (lower number = higher priority)
3. For each rule:
   a. Evaluate condition against context
   b. Check constraint satisfaction
   c. If violated, add to violation list
4. Return: all_pass, violated_rules
```

### 3. Ontology Validator

**Purpose:** Main orchestrator for validation workflow

**Workflow:**
```
validate(action, entity, entity_id, context):
  1. Build ActionContext from provided context
  2. Call RuleEngine.evaluate(action, entity, context)
  3. Calculate validation time
  4. Update metrics
  5. Build ValidationResult:
     - If all rules pass: allowed=True
     - If violations: allowed=False + reasons + suggestions
  6. Return ValidationResult
```

**ValidationResult Structure:**
```python
{
  "allowed": bool,
  "action": str,
  "entity": str,
  "entity_id": Optional[str],
  "reason": Optional[str],  # Why denied
  "suggested_actions": List[str],  # What to do instead
  "violated_rules": List[str],  # Which rules failed
  "validation_time_ms": int,
  "context_used": Dict  # Full context
}
```

### 4. MCP Integration Layer

**Purpose:** Expose OntoGuard as MCP tools for agent consumption

**MCP Tools Provided:**

**validate_action:**
- Input: action, entity, entity_id, context
- Output: ValidationResult
- Use: Validate before executing any action

**get_allowed_actions:**
- Input: entity, context
- Output: List of allowed actions
- Use: UI generation, agent planning

**check_permissions:**
- Input: action, entity, role
- Output: Permission check result
- Use: Quick permission verification

**explain_rule:**
- Input: rule_id
- Output: Rule explanation
- Use: Understanding why action was blocked

**get_metrics:**
- Input: None
- Output: Validation statistics
- Use: Monitoring, analytics

**Integration Pattern:**
```python
# Agent code
from mcp import MCPClient

client = MCPClient("ontoguard-server")

# Before executing action
result = client.call_tool("validate_action", {
    "action": "process_refund",
    "entity": "Order",
    "context": {"amount": 2000, "role": "agent"}
})

if result["allowed"]:
    execute_refund()
else:
    print(f"Blocked: {result['reason']}")
    print(f"Try: {result['suggested_actions']}")
```

### 5. Audit Service

**Purpose:** Comprehensive logging for compliance and debugging

**Audit Log Schema:**
```sql
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    agent_id TEXT,
    action TEXT,
    entity TEXT,
    entity_id TEXT,
    allowed INTEGER,  -- 0=denied, 1=allowed
    reason TEXT,
    violated_rules TEXT,  -- JSON array
    context TEXT,  -- JSON object
    validation_time_ms INTEGER
)
```

**Use Cases:**
- Compliance audits: "Who accessed customer PII?"
- Security monitoring: "Unusual denial patterns?"
- Performance analysis: "Validation time trends?"
- Rule effectiveness: "Which rules block most often?"

## Business Rule Examples

### E-Commerce Domain

**Rule 1: Order Cancellation Time Limit**
```json
{
  "id": "order_cancel_24h",
  "type": "temporal",
  "entity": "Order",
  "action": "cancel",
  "constraint": {"max_age_hours": 24},
  "error_message": "Orders can only be cancelled within 24 hours",
  "suggested_alternatives": ["request_manager_override"]
}
```

**Prevents:** Cancelling old orders
**Example:** Order placed 48 hours ago cannot be cancelled by agent

**Rule 2: Refund Amount Approval**
```json
{
  "id": "refund_approval",
  "type": "quantitative",
  "entity": "Refund",
  "action": "process",
  "constraint": {"max_amount": 1000},
  "error_message": "Refunds over $1000 require manager approval",
  "suggested_alternatives": ["request_manager_approval", "partial_refund"]
}
```

**Prevents:** Agents processing large refunds without oversight
**The $4.6M Fix:** This rule would have caught the mass refund error

**Rule 3: State-Based Deletion**
```json
{
  "id": "no_delete_shipped",
  "type": "state_based",
  "entity": "Order",
  "action": "delete",
  "constraint": {"forbidden_states": ["shipped", "delivered"]},
  "error_message": "Cannot delete shipped orders",
  "suggested_alternatives": ["cancel_order", "request_return"]
}
```

**Prevents:** Data loss for in-flight orders

### Healthcare Domain

**Rule: HIPAA PII Access**
```json
{
  "id": "hipaa_pii_access",
  "type": "compliance",
  "entity": "Patient",
  "action": "read",
  "constraint": {
    "requires_approval": true,
    "requires_audit": true
  },
  "error_message": "Patient PII access requires compliance approval",
  "suggested_alternatives": ["request_compliance_approval"]
}
```

### Financial Domain

**Rule: Transaction Limits**
```json
{
  "id": "daily_transaction_limit",
  "type": "quantitative",
  "entity": "Transaction",
  "action": "execute",
  "constraint": {
    "max_daily_amount": 10000,
    "max_transaction_count": 50
  },
  "error_message": "Daily transaction limit exceeded",
  "suggested_alternatives": ["schedule_for_tomorrow", "split_transaction"]
}
```

## Performance Characteristics

### Latency

**Typical Validation Times:**
- Simple permission check: 2-5ms
- Temporal constraint check: 5-10ms
- Complex multi-rule validation: 10-15ms
- Average: 8-12ms

**Optimization:**
- Rule indexing by (entity, action)
- Early termination on first violation
- In-memory rule cache

### Throughput

**Capacity:**
- Single instance: 1000+ validations/second
- With SQLite audit: 500-800 validations/second
- With PostgreSQL audit: 2000+ validations/second

**Scalability:**
- Stateless design enables horizontal scaling
- Shared database for audit trail
- No cross-instance communication required

### Storage

**Per Validation:**
- Audit log entry: ~500 bytes
- Average context: ~1KB

**For 1M validations/month:**
- Audit logs: ~500MB
- With indexes: ~750MB

## Error Handling

### Validation Errors

**Clear Error Messages:**
```python
# Bad: Generic error
"Action not allowed"

# Good: Specific with context
"Refunds over $1000 require manager approval. 
 This refund is $2000 and you are an agent."
```

**Actionable Suggestions:**
```python
"suggested_actions": [
    "request_manager_approval",  # How to fix
    "process_partial_refund_under_1000"  # Alternative approach
]
```

### Rule Definition Errors

**Ontology Validation:**
- Check for circular dependencies
- Validate constraint syntax
- Verify entity references
- Ensure rule priorities are unique

**Runtime Checks:**
- Log warnings for unknown entity types
- Default to ALLOW for malformed rules (fail-safe)
- Report rule evaluation errors

## Integration Patterns

### Pattern 1: Pre-Execution Validation

```python
# Agent workflow
action = agent.decide_next_action()

# Validate before executing
result = ontoguard.validate(
    action=action.type,
    entity=action.entity,
    context=build_context()
)

if result.allowed:
    execute(action)
else:
    handle_denial(result)
```

### Pattern 2: Action Planning

```python
# Get allowed actions for UI
allowed = ontoguard.get_allowed_actions(
    entity="Order",
    context=current_context
)

# Show only allowed buttons
ui.render_actions(allowed)
```

### Pattern 3: Multi-Agent Coordination

```python
# Coordinator agent checks before delegation
for subtask in task.subtasks:
    if ontoguard.validate(subtask.action, subtask.entity).allowed:
        delegate_to_specialist(subtask)
    else:
        escalate_to_human(subtask)
```

## Deployment Options

### Option 1: Embedded Library

```python
from ontoguard import OntologyValidator

validator = OntologyValidator("enterprise.json")
result = validator.validate(...)
```

**Pros:** No network latency, simple deployment
**Cons:** Ontology updates require app restart

### Option 2: MCP Server

```bash
python ontoguard.py --mode server --port 5000
```

**Pros:** Centralized rules, multiple agents
**Cons:** Network latency, single point of failure

### Option 3: Sidecar Pattern

```
Agent Container <-> OntoGuard Sidecar <-> Tools
```

**Pros:** Low latency, isolated failures
**Cons:** Resource overhead per agent

## Monitoring and Observability

### Key Metrics

**Validation Metrics:**
- Total validations
- Allow rate (should be 80-95%)
- Deny rate (should be 5-20%)
- Average validation time

**Security Metrics:**
- Top violated rules
- Top blocked actions
- Denial rate by agent
- Unusual patterns

**Performance Metrics:**
- P50, P95, P99 latency
- Validation errors
- Rule evaluation failures

### Dashboards

**Real-time Dashboard:**
- Validations per second
- Current allow/deny rate
- Active agents
- Recent denials

**Analytics Dashboard:**
- Rule effectiveness
- Agent compliance
- Temporal patterns
- Cost attribution

## Security Considerations

### Ontology Protection

**Threat:** Malicious ontology modification
**Mitigation:**
- Read-only file permissions
- Ontology signing/verification
- Version control integration

### Bypass Prevention

**Threat:** Agents skipping validation
**Mitigation:**
- Enforce at infrastructure level
- Tool layer integration
- Audit all tool executions

### Denial of Service

**Threat:** Validation flood
**Mitigation:**
- Rate limiting per agent
- Circuit breakers
- Async validation for non-critical paths

## Testing Strategy

### Unit Tests

- Rule engine logic
- Parser correctness
- Validation result formatting

### Integration Tests

- Full validation workflow
- MCP tool execution
- Audit logging

### Ontology Tests

- Rule coverage
- Constraint validation
- Edge cases

### Performance Tests

- Latency under load
- Throughput limits
- Memory usage

## Future Enhancements

### Version 0.2
- Web dashboard for metrics
- Visual ontology editor
- Real-time monitoring
- Multi-ontology support

### Version 0.3
- Auto-generate ontologies from schemas
- Machine learning for rule suggestions
- Advanced caching
- Distributed tracing

### Version 1.0
- Enterprise SSO integration
- Multi-tenant support
- SLA guarantees
- 24/7 support

## References

- Original Article: https://freedium-mirror.cfd/https://medium.com/@cloudpankaj/ontoguard-i-built-an-ontology-firewall-for-ai-agents-in-48-hours-using-cursor-ai-be4208c405e7
- Model Context Protocol: https://github.com/anthropics/mcp
- OWL Specification: https://www.w3.org/TR/owl2-overview/

---

**License:** MIT
**Version:** 1.0.0
**Status:** Production Ready
