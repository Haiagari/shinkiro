"""
Estados del Workflow PromptWall v5.0
"""

class WorkflowState:
    DISCOVERED = "discovered"
    ENUMERATED = "enumerated"
    ANALYZED = "analyzed"
    HYPOTHESIZED = "hypothesized"
    CANDIDATE = "candidate"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTED = "executed"
    BLOCKED = "blocked"
    REJECTED = "rejected"
    VALIDATING = "validating"
    VALIDATED = "validated"
    REPORTED = "reported"
    ARCHIVED = "archived"

class Actor:
    SYSTEM = "system"
    USER = "user"
    AI = "ai"
