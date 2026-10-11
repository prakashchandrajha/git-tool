from __future__ import annotations

TRANSITIONS: dict[str, dict[str, str]] = {
    # state -> {tool: next_state}
    "BEGUN":          {"edit_ack": "EDITING", "abort": "ABORTED", "status": "BEGUN"},
    "EDITING":        {"review": "REVIEWED", "abort": "ABORTED", "status": "EDITING"},
    "REVIEWED":       {"verify_start": "VERIFYING", "edit_ack": "EDITING", "abort": "ABORTED", "status": "REVIEWED"},
    "VERIFYING":      {"verify_result": "VERIFYING", "abort": "ABORTED", "status": "VERIFYING"},   # engine moves to VERIFIED/FAILED itself
    "VERIFIED":       {"close": "CLOSED", "edit_ack": "EDITING", "abort": "ABORTED", "status": "VERIFIED"},
    "FAILED":         {"edit_ack": "EDITING", "abort": "ABORTED", "request_override": "PENDING_HUMAN", "status": "FAILED"},
    "PENDING_HUMAN":  {"abort": "ABORTED", "status": "PENDING_HUMAN"},                             # human approve/reject happen out-of-band
    "OVERRIDE_GRANTED": {"verify_start": "VERIFYING", "abort": "ABORTED", "status": "OVERRIDE_GRANTED"},
    "REJECTED":       {"edit_ack": "EDITING", "abort": "ABORTED", "status": "REJECTED"},
    "ABORTED":        {"status": "ABORTED"},
    "CLOSED":         {"status": "CLOSED"},
}

class IllegalTransition(Exception):
    def __init__(self, state: str, tool: str):
        self.state, self.tool = state, tool
        super().__init__(f"{tool} not allowed in {state}")

def allowed(state: str) -> list[str]:
    return sorted(TRANSITIONS[state])

def step(state: str, tool: str) -> str:
    try:
        return TRANSITIONS[state][tool]
    except KeyError:
        raise IllegalTransition(state, tool) from None
