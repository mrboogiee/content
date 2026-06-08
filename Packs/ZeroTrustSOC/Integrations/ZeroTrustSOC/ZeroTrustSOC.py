"""Zero Trust SOC integration for Cortex XSIAM/XSOAR.

The ON2IT public API (``https://api.on2it.net/v3``) wraps almost every list,
POST and PATCH payload in an ``{"items": [...]}`` envelope. This module hides
that quirk behind a small ``Client`` so command functions can deal with plain
dictionaries.
"""

import base64
import json
import mimetypes
import secrets
import time
from datetime import datetime, UTC
from typing import Any

import requests
import urllib3
from CommonServerPython import *  # noqa: F401, F403
from CommonServerUserPython import *  # noqa: F401, F403

urllib3.disable_warnings()


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

VENDOR = "ON2IT"

CONTENT_TYPES = (
    "azure_cloud",
    "aws_cloud",
    "gcp_cloud",
    "container",
    "hostname",
    "user_identity",
    "ipv4",
    "ipv6",
)

CASE_TYPES = (
    "securityincident",
    "incident",
    "change",
    "standardchange",
    "inforequest",
    "notification",
)

CASE_STATES = (
    "new",
    "in_progress",
    "awaiting_customer",
    "on_hold",
    "pending_engineering",
    "request_close",
    "request_close_by_customer",
    "closed",
)

# IP-flavoured content types use match_method="ip"; everything else uses "exact".
IP_CONTENT_TYPES = frozenset({"ipv4", "ipv6"})

# Mapping from ON2IT priority (1=critical .. 4=low) to XSIAM severity
# (4=critical, 3=high, 2=medium, 1=low).
_PRIORITY_TO_SEVERITY = {1: 4, 2: 3, 3: 2, 4: 1}

DEFAULT_FETCH_LIMIT = 50


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class Client(BaseClient):
    """Thin wrapper around the ON2IT v3 API."""

    def __init__(self, base_url: str, token: str, verify: bool = True, proxy: bool = False):
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        super().__init__(base_url=base_url.rstrip("/"), verify=verify, proxy=proxy, headers=headers)

    # -- error handling ----------------------------------------------------- #

    def _api_error_handler(self, resp: requests.Response) -> None:
        err_msg = f"Error in API call [{resp.status_code}] - {resp.reason}"
        try:
            body = resp.json()
            if detail := body.get("detail") or body.get("message") or body.get("error"):
                err_msg += f": {detail}"
        except ValueError:
            if resp.text:
                err_msg += f": {resp.text[:500]}"
        if resp.status_code == 401:
            err_msg += " — the API token is missing or invalid."
        elif resp.status_code == 403:
            err_msg += (
                " — the API token does not have permission for this resource."
                " Verify the token is correct and has the required scopes."
            )
        raise DemistoException(err_msg)

    def _http_request(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        kwargs.setdefault("error_handler", self._api_error_handler)
        return super()._http_request(*args, **kwargs)

    # -- envelope helpers --------------------------------------------------- #

    @staticmethod
    def _extract_items(response: Any) -> list[dict[str, Any]]:
        """Pull the ``items`` list out of an ON2IT response, defaulting to ``[]``."""
        if not isinstance(response, dict):
            return []
        items = response.get("items")
        return items if isinstance(items, list) else []

    def _first_item(self, response: Any) -> dict[str, Any] | None:
        items = self._extract_items(response)
        return items[0] if items else None

    def _post_items(self, suffix: str, item: dict[str, Any], method: str = "POST") -> dict[str, Any]:
        """POST/PATCH a single item wrapped in the ``{"items": [...]}`` envelope."""
        # Used for POST and PATCH endpoints — both share the {"items": [item]} envelope.
        return self._http_request(
            method=method,
            url_suffix=suffix,
            json_data={"items": [item]},
            ok_codes=(200, 201, 204),
        )

    # -- ZeroTrust ---------------------------------------------------------- #

    def list_protect_surfaces(self) -> list[dict[str, Any]]:
        return self._extract_items(self._http_request("GET", "/zerotrust/get-protectsurfaces"))

    def get_protect_surface(self, ps_id: str) -> dict[str, Any] | None:
        return self._first_item(self._http_request("GET", "/zerotrust/get-protectsurface", params={"id": ps_id}))

    def search_protect_surface(self, content_type: str, value: str) -> list[dict[str, Any]]:
        match_method = "ip" if content_type in IP_CONTENT_TYPES else "exact"
        params = {"match_type": content_type, "match_method": match_method, "match_value": value}
        return self._extract_items(
            self._http_request("GET", "/zerotrust/get-protectsurface-by-state-type-and-value-match", params=params)
        )

    def list_states_by_protect_surface(self, ps_id: str) -> list[dict[str, Any]]:
        return self._extract_items(self._http_request("GET", "/zerotrust/get-states-by-protectsurface", params={"id": ps_id}))

    def get_state(self, state_id: str) -> dict[str, Any] | None:
        return self._first_item(self._http_request("GET", "/zerotrust/get-state", params={"id": state_id}))

    def create_or_replace_state(self, state: dict[str, Any]) -> dict[str, Any]:
        """Create or replace a state. Returns the created/updated state."""
        result = self._first_item(self._post_items("/zerotrust/create-or-replace-state", state))
        if result is None:
            raise DemistoException("Failed to create or replace state: API returned no data")
        return result

    def remove_state(self, state_id: str) -> dict[str, Any]:
        """Remove a state by ID."""
        return self._http_request(
            "POST",
            "/zerotrust/remove-state",
            params={"id": state_id},
            ok_codes=(200, 204),
            return_empty_response=True,
        )

    def get_all_measures(self) -> dict[str, Any]:
        return self._http_request("GET", "/zerotrust/get-all-measures")

    # -- Assessments -------------------------------------------------------- #

    def get_base_questions(self) -> dict[str, Any]:
        """Get all base questions and answers for Zero Trust Readiness Assessments."""
        return self._http_request("GET", "/zerotrust/get-base-questions")

    def create_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]:
        """Create a new Zero Trust Readiness Assessment."""
        result = self._first_item(self._post_items("/zerotrust/create-assessment", assessment))
        if result is None:
            raise DemistoException("Failed to create assessment: API returned no data")
        return result

    def get_assessment_by_id(self, assessment_id: str) -> dict[str, Any] | None:
        """Get a specific assessment by ID."""
        return self._first_item(self._http_request("GET", "/zerotrust/get-assessment-by-id", params={"id": assessment_id}))

    def list_assessments(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """List all assessments with pagination support."""
        return self._extract_items(self._http_request("GET", "/zerotrust/get-assessments", params=params))

    def get_assessments_summary(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Get a summary of assessments with pagination support."""
        return self._extract_items(self._http_request("GET", "/zerotrust/get-assessments-summary", params=params))

    def remove_assessment_by_id(self, assessment_id: str) -> dict[str, Any]:
        """Remove an assessment by ID."""
        return self._http_request(
            "POST",
            "/zerotrust/remove-assessment-by-id",
            params={"id": assessment_id},
            ok_codes=(200, 204),
            return_empty_response=True,
        )

    # -- Cases -------------------------------------------------------------- #

    def list_cases(self) -> list[dict[str, Any]]:
        return self._extract_items(self._http_request("GET", "/case/integration/cases"))

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        return self._first_item(self._http_request("GET", f"/case/integration/{case_id}"))

    def create_case(self, case: dict[str, Any]) -> dict[str, Any]:
        return self._post_items("/case/integration", case)

    def add_case_note(self, case_id: str, note: str) -> dict[str, Any]:
        return self._post_items(f"/case/integration/{case_id}/notes", {"note": note})

    def add_case_attachment(self, case_id: str, data_uri: str) -> dict[str, Any]:
        return self._post_items(f"/case/integration/{case_id}/attachments", {"attachment": data_uri})

    def update_case_priority(self, case_id: str, priority: int) -> dict[str, Any]:
        return self._post_items(f"/case/integration/{case_id}/priority", {"priority": priority}, method="PATCH")

    def update_case_subject(self, case_id: str, subject: str) -> dict[str, Any]:
        return self._post_items(f"/case/integration/{case_id}/subject", {"subject": subject}, method="PATCH")

    def update_case_primary_contact(self, case_id: str, email: str) -> dict[str, Any]:
        return self._post_items(
            f"/case/integration/{case_id}/primary-contact",
            {"primary_contact_email": email},
            method="PATCH",
        )

    # Body-less endpoints — the HTTP verb itself carries the semantics (PATCH/DELETE = (de)escalate, POST = request close).
    def escalate_case(self, case_id: str) -> dict[str, Any]:
        return self._http_request(
            "PATCH",
            f"/case/integration/{case_id}/escalation-status",
            ok_codes=(200, 204),
            return_empty_response=True,
        )

    def deescalate_case(self, case_id: str) -> dict[str, Any]:
        return self._http_request(
            "DELETE",
            f"/case/integration/{case_id}/escalation-status",
            ok_codes=(200, 204),
            return_empty_response=True,
        )

    def request_close_case(self, case_id: str) -> dict[str, Any]:
        return self._http_request(
            "POST",
            f"/case/integration/{case_id}/request-close",
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )

    # -- Other -------------------------------------------------------------- #

    # -- EventFlow ------------------------------------------------------------- #

    def post_event(self, event_b64: str) -> None:
        """POST a base64-encoded event (or newline-separated batch) to the eventflow store-events endpoint."""
        self._http_request(
            "POST",
            "/eventflow/store-events",
            data=event_b64,
            headers={"Content-Type": "text/plain"},
            ok_codes=(200, 201, 204),
            return_empty_response=True,
        )

    # -- Other -------------------------------------------------------------- #

    def list_assets(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self._extract_items(self._http_request("GET", "/asset/get-assets", params=params))

    def search_people(self, email: str) -> list[dict[str, Any]]:
        return self._extract_items(self._http_request("GET", "/crm/get-people", params={"email": email}))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _priority_to_severity(priority: Any) -> int:
    """Map ON2IT priority (1..4) to XSIAM severity (4..1). Unknowns become 0 (informational)."""
    # 0 == "unknown" severity in XSIAM; we don't guess when ON2IT priority is missing/invalid.
    try:
        return _PRIORITY_TO_SEVERITY.get(int(priority), 0)
    except (TypeError, ValueError):
        return 0


def _unix_to_iso(value: Any) -> str | None:
    """Format a Unix epoch (seconds) as an ISO8601 UTC string. Returns ``None`` for falsy/invalid input."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return None


def _human_case_row(case: dict[str, Any]) -> dict[str, Any]:
    """Build a human-readable row for a case, with timestamps as ISO strings."""
    return {
        "id": case.get("id"),
        "case_number": case.get("case_number"),
        "subject": case.get("subject"),
        "case_type": case.get("case_type"),
        "state": case.get("state"),
        "resolution_state": case.get("resolution_state"),
        "primary_contact_email": case.get("primary_contact_email"),
        "creation_date": _unix_to_iso(case.get("creation_date")),
        "last_update": _unix_to_iso(case.get("last_update")),
    }


def _human_state_row(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": state.get("id"),
        "protectsurface_id": state.get("protectsurface_id"),
        "content_type": state.get("content_type"),
        "description": state.get("description"),
        "content_count": len(state.get("content") or []),
        "maintainer": state.get("maintainer"),
    }


def _human_protectsurface_row(ps: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": ps.get("id"),
        "name": ps.get("name"),
        "description": ps.get("description"),
        "in_control_boundary": ps.get("in_control_boundary"),
        "in_zero_trust_focus": ps.get("in_zero_trust_focus"),
        "uniqueness_key": ps.get("uniqueness_key"),
    }


def _file_to_data_uri(entry_id: str) -> str:
    """Resolve a war room entry, base64-encode the file, and return a ``data:<mime>;base64,...`` URI."""
    file_meta = demisto.getFilePath(entry_id)
    path = file_meta["path"]
    name = file_meta.get("name") or path
    mime, _ = mimetypes.guess_type(name)
    mime = mime or "application/octet-stream"
    with open(path, "rb") as fh:
        encoded = base64.b64encode(fh.read()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def _coerce_priority(value: Any, *, default: int = 3) -> int:
    """Coerce a priority arg to an int in the 1..4 range, raising a friendly error otherwise."""
    parsed = arg_to_number(value, arg_name="priority")
    if parsed is None:
        return default
    if parsed < 1 or parsed > 4:
        raise DemistoException("priority must be an integer between 1 and 4 (1 = most critical).")
    return parsed


def _multiselect_to_set(value: Any) -> set[str]:
    """Normalise a XSIAM multi-select param (CSV string or list) into a set of strings."""
    if not value:
        return set()
    items = argToList(value)
    return {str(item).strip() for item in items if str(item).strip()}


# --------------------------------------------------------------------------- #
# Command implementations - ZeroTrust
# --------------------------------------------------------------------------- #


def test_module(client: Client) -> str:
    """Verify connectivity by hitting a lightweight authed endpoint."""
    client.get_all_measures()
    return "ok"


def protectsurface_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or DEFAULT_FETCH_LIMIT
    surfaces = client.list_protect_surfaces()[:limit]
    rows = [_human_protectsurface_row(ps) for ps in surfaces]
    return CommandResults(
        outputs_prefix="On2IT.ProtectSurface",
        outputs_key_field="id",
        outputs=surfaces,
        readable_output=tableToMarkdown(
            f"ON2IT Protect Surfaces ({len(surfaces)})",
            rows,
            headers=["id", "name", "description", "in_control_boundary", "in_zero_trust_focus"],
        ),
    )


def protectsurface_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ps_id = args["id"]
    surface = client.get_protect_surface(ps_id)
    if not surface:
        return CommandResults(readable_output=f"No Protect Surface found with id `{ps_id}`.")
    return CommandResults(
        outputs_prefix="On2IT.ProtectSurface",
        outputs_key_field="id",
        outputs=surface,
        readable_output=tableToMarkdown(
            f"ON2IT Protect Surface `{ps_id}`",
            _human_protectsurface_row(surface),
            headers=["id", "name", "description", "in_control_boundary", "in_zero_trust_focus", "uniqueness_key"],
        ),
    )


def protectsurface_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    content_type = args["content_type"]
    value = args["value"]
    if content_type not in CONTENT_TYPES:
        raise DemistoException(f"content_type must be one of: {', '.join(CONTENT_TYPES)}")
    surfaces = client.search_protect_surface(content_type, value)
    rows = [_human_protectsurface_row(ps) for ps in surfaces]
    return CommandResults(
        outputs_prefix="On2IT.ProtectSurface",
        outputs_key_field="id",
        outputs=surfaces,
        readable_output=tableToMarkdown(
            f"Zero Trust SOC Protect Surfaces matching `{content_type}={value}` ({len(surfaces)})",
            rows,
            headers=["id", "name", "description", "in_control_boundary", "in_zero_trust_focus"],
        ),
    )


def protectsurface_states_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ps_id = args["protectsurface_id"]
    states = client.list_states_by_protect_surface(ps_id)
    rows = [_human_state_row(state) for state in states]
    return CommandResults(
        outputs_prefix="On2IT.ProtectSurfaceState",
        outputs_key_field="id",
        outputs=states,
        readable_output=tableToMarkdown(
            f"States for Protect Surface `{ps_id}` ({len(states)})",
            rows,
            headers=["id", "content_type", "description", "content_count", "maintainer"],
        ),
    )


def state_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create or replace a state."""
    state_data = {
        "id": args["id"],
        "protectsurface_id": args["protectsurface_id"],
        "content_type": args["content_type"],
        "content": argToList(args["content"]),
    }
    if "description" in args:
        state_data["description"] = args["description"]
    if "maintainer" in args:
        state_data["maintainer"] = args["maintainer"]

    result = client.create_or_replace_state(state_data)
    row = _human_state_row(result) if result else {}

    return CommandResults(
        outputs_prefix="On2IT.ProtectSurfaceState",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            f"State Created/Updated: `{state_data['id']}`",
            row,
            headers=["id", "content_type", "description", "content_count", "maintainer"],
        ),
    )


def state_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Remove a state by ID."""
    state_id = args["id"]
    client.remove_state(state_id)
    return CommandResults(readable_output=f"State `{state_id}` successfully removed.")


# --------------------------------------------------------------------------- #
# Command implementations - Assessments
# --------------------------------------------------------------------------- #


def assessment_questions_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get base questions for Zero Trust Readiness Assessments."""
    result = client.get_base_questions()
    items = result.get("items", [])

    return CommandResults(
        outputs_prefix="On2IT.AssessmentQuestions",
        outputs=result,
        readable_output=tableToMarkdown(
            f"Zero Trust Readiness Assessment Base Questions ({len(items)})",
            items if items else result,
        ),
    )


def assessment_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new Zero Trust Readiness Assessment."""
    assessment_data = {
        "assessment_timestamp": args.get("timestamp", int(datetime.now(UTC).timestamp())),
    }

    # Parse answers as JSON if provided
    if "answers" in args:
        try:
            assessment_data["answers"] = json.loads(args["answers"])
        except json.JSONDecodeError as e:
            raise DemistoException(f"Invalid JSON in answers parameter: {e}")

    result = client.create_assessment(assessment_data)

    return CommandResults(
        outputs_prefix="On2IT.Assessment",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            "Assessment Created",
            result,
            headers=["id", "assessment_timestamp"],
        ),
    )


def assessment_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a specific assessment by ID."""
    assessment_id = args["id"]
    result = client.get_assessment_by_id(assessment_id)

    if not result:
        return CommandResults(readable_output=f"No assessment found with id `{assessment_id}`.")

    return CommandResults(
        outputs_prefix="On2IT.Assessment",
        outputs_key_field="id",
        outputs=result,
        readable_output=tableToMarkdown(
            f"Assessment: {assessment_id}",
            result,
            headers=["id", "assessment_timestamp"],
        ),
    )


def assessment_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List Zero Trust Readiness Assessments with pagination."""
    params = {}

    if "page_number" in args:
        params["page_number"] = arg_to_number(args["page_number"], arg_name="page_number")
    if "page_size" in args:
        params["page_size"] = arg_to_number(args["page_size"], arg_name="page_size")
    if "sort" in args:
        params["sort"] = args["sort"]

    assessments = client.list_assessments(params)

    return CommandResults(
        outputs_prefix="On2IT.Assessment",
        outputs_key_field="id",
        outputs=assessments,
        readable_output=tableToMarkdown(
            f"Zero Trust Readiness Assessments ({len(assessments)})",
            assessments,
            headers=["id", "assessment_timestamp"],
        ),
    )


def assessment_summary_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get assessments summary with pagination."""
    params = {}

    if "page_number" in args:
        params["page_number"] = arg_to_number(args["page_number"], arg_name="page_number")
    if "page_size" in args:
        params["page_size"] = arg_to_number(args["page_size"], arg_name="page_size")
    if "sort" in args:
        params["sort"] = args["sort"]

    summaries = client.get_assessments_summary(params)

    return CommandResults(
        outputs_prefix="On2IT.AssessmentSummary",
        outputs=summaries,
        readable_output=tableToMarkdown(
            f"Assessment Summaries ({len(summaries)})",
            summaries,
        ),
    )


def assessment_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Remove an assessment by ID."""
    assessment_id = args["id"]
    client.remove_assessment_by_id(assessment_id)
    return CommandResults(readable_output=f"Assessment `{assessment_id}` successfully removed.")


# --------------------------------------------------------------------------- #
# Command implementations - Cases
# --------------------------------------------------------------------------- #


def case_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or DEFAULT_FETCH_LIMIT
    cases = client.list_cases()[:limit]
    rows = [_human_case_row(c) for c in cases]
    return CommandResults(
        outputs_prefix="On2IT.Case",
        outputs_key_field="id",
        outputs=cases,
        readable_output=tableToMarkdown(
            f"ON2IT Cases ({len(cases)})",
            rows,
            headers=[
                "id",
                "case_number",
                "subject",
                "case_type",
                "state",
                "resolution_state",
                "primary_contact_email",
                "creation_date",
                "last_update",
            ],
        ),
    )


def case_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    case = client.get_case(case_id)
    if not case:
        return CommandResults(readable_output=f"No ON2IT case found with id `{case_id}`.")
    # Detail view extends the summary row with priority and escalation status.
    row = _human_case_row(case) | {"priority": case.get("priority"), "escalated": case.get("escalated")}
    return CommandResults(
        outputs_prefix="On2IT.Case",
        outputs_key_field="id",
        outputs=case,
        readable_output=tableToMarkdown(
            f"ON2IT Case `{case_id}`",
            row,
            headers=[
                "id",
                "case_number",
                "subject",
                "case_type",
                "state",
                "resolution_state",
                "priority",
                "escalated",
                "primary_contact_email",
                "creation_date",
                "last_update",
            ],
        ),
    )


_EVENTFLOW_POLL_INTERVAL = 10  # seconds between list_cases polls
_EVENTFLOW_MAX_ATTEMPTS = 12  # 12 × 10 s = 120 s max wait


def case_create_command(client: Client, eventflow_client: Client, args: dict[str, Any]) -> CommandResults:
    vendor_event_id = secrets.token_hex(16)

    # Build an "other" event payload matching the go-auxo Other struct.
    event: dict[str, Any] = {
        "type": "other",
        "detection_timestamp": int(datetime.now(UTC).timestamp()),
        "message": args["subject"],
        "vendor": args.get("vendor", "Cortex XSIAM"),
        "vendor_event_id": vendor_event_id,
        "raw": {
            "note": args.get("note", ""),
            "case_type": args.get("case_type", "securityincident"),
            "priority": _coerce_priority(args.get("priority"), default=3),
            "primary_contact_email": args.get("primary_contact_email", ""),
        },
    }

    # Marshal → base64, matching PostEventQueue behaviour in go-auxo.
    event_b64 = base64.b64encode(json.dumps(event).encode()).decode("ascii")

    # Snapshot existing case IDs so we can detect the newly created one.
    existing_ids: set[str] = {str(c.get("id")) for c in client.list_cases()}

    # Post to eventflow — this triggers ON2IT to open a case asynchronously.
    eventflow_client.post_event(event_b64)

    subject = args["subject"]

    # Poll until the new case surfaces in the case list.
    new_case: dict[str, Any] | None = None
    for _ in range(_EVENTFLOW_MAX_ATTEMPTS):
        time.sleep(_EVENTFLOW_POLL_INTERVAL)  # pylint: disable=E9003
        cases = client.list_cases()
        fresh = [c for c in cases if str(c.get("id")) not in existing_ids and c.get("subject") == subject]
        if fresh:
            new_case = max(fresh, key=lambda c: c.get("last_update") or 0)
            break

    if new_case is None:
        raise DemistoException(
            f"Event posted (vendor_event_id={vendor_event_id}) but no new case appeared within "
            f"{_EVENTFLOW_MAX_ATTEMPTS * _EVENTFLOW_POLL_INTERVAL} seconds."
        )

    # Fetch full case detail to get all fields including the ON2IT case ID.
    case_id = str(new_case.get("id") or "")
    case = client.get_case(case_id) or new_case

    row = _human_case_row(case) | {"priority": case.get("priority"), "escalated": case.get("escalated")}
    return CommandResults(
        outputs_prefix="On2IT.Case",
        outputs_key_field="id",
        outputs=case,
        readable_output=tableToMarkdown(
            f"Created ON2IT Case `{case_id}`",
            row,
            headers=["id", "case_number", "subject", "case_type", "state", "priority", "primary_contact_email"],
        ),
    )


def case_link_command(client: Client, args: dict[str, Any]) -> CommandResults:
    on2it_case_id = args["on2it_case_id"]
    incident = demisto.incident() or {}
    xsiam_incident_id = args.get("xsiam_incident_id") or str(incident.get("id") or "")
    if not xsiam_incident_id:
        raise DemistoException(
            "Could not determine the XSIAM incident id. Pass `xsiam_incident_id` explicitly when running outside an incident."
        )
    silent = argToBoolean(args.get("silent", False))
    linked_at = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    linkage = {
        "on2it_case_id": on2it_case_id,
        "xsiam_incident_id": xsiam_incident_id,
        "linked_at": linked_at,
    }
    if not silent:
        client.add_case_note(on2it_case_id, f"Linked to Cortex XSIAM incident {xsiam_incident_id}.")
    note_status = "skipped (silent=true)" if silent else "posted to ON2IT case"
    return CommandResults(
        outputs_prefix="On2IT.LinkedCase",
        outputs_key_field="on2it_case_id",
        outputs=linkage,
        readable_output=(
            f"Linked XSIAM incident `{xsiam_incident_id}` to ON2IT case `{on2it_case_id}`. Cross-reference note {note_status}."
        ),
    )


def case_add_note_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    client.add_case_note(case_id, args["note"])
    return CommandResults(readable_output=f"Added note to ON2IT case `{case_id}`.")


def case_update_priority_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    priority = _coerce_priority(args["priority"])
    client.update_case_priority(case_id, priority)
    return CommandResults(readable_output=f"Updated priority of ON2IT case `{case_id}` to {priority}.")


def case_update_subject_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    client.update_case_subject(case_id, args["subject"])
    return CommandResults(readable_output=f"Updated subject of ON2IT case `{case_id}`.")


def case_update_primary_contact_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    client.update_case_primary_contact(case_id, args["primary_contact_email"])
    return CommandResults(readable_output=f"Updated primary contact of ON2IT case `{case_id}`.")


def case_escalate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    client.escalate_case(case_id)
    return CommandResults(readable_output=f"Escalated ON2IT case `{case_id}`.")


def case_deescalate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    client.deescalate_case(case_id)
    return CommandResults(readable_output=f"De-escalated ON2IT case `{case_id}`.")


def case_close_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    client.request_close_case(case_id)
    return CommandResults(readable_output=f"Requested close on ON2IT case `{case_id}`.")


def case_attach_file_command(client: Client, args: dict[str, Any]) -> CommandResults:
    case_id = args["id"]
    entry_id = args["entry_id"]
    data_uri = _file_to_data_uri(entry_id)
    client.add_case_attachment(case_id, data_uri)
    return CommandResults(readable_output=f"Attached war room file `{entry_id}` to ON2IT case `{case_id}`.")


# --------------------------------------------------------------------------- #
# Command implementations - Other lookups
# --------------------------------------------------------------------------- #


def asset_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    params: dict[str, Any] = {
        "page_size": arg_to_number(args.get("page_size")) or DEFAULT_FETCH_LIMIT,
        "page_number": arg_to_number(args.get("page_number")) or 1,
    }
    if args.get("id"):
        params["id"] = args["id"]
    if args.get("name"):
        params["name"] = args["name"]
    asset_types = argToList(args.get("asset_type_name"))
    if asset_types:
        # ON2IT API uses the PHP-style "name[]" repeated-key convention for array query params.
        params["asset_type_name[]"] = asset_types
    assets = client.list_assets(params)
    return CommandResults(
        outputs_prefix="On2IT.Asset",
        outputs_key_field="id",
        outputs=assets,
        readable_output=tableToMarkdown(
            f"ON2IT Assets ({len(assets)})",
            [{"id": a.get("id"), "name": a.get("name"), "asset_type_name": a.get("asset_type_name")} for a in assets],
            headers=["id", "name", "asset_type_name"],
        ),
    )


def people_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    email = args["email"]
    people = client.search_people(email)
    return CommandResults(
        outputs_prefix="On2IT.Person",
        outputs_key_field="email",
        outputs=people,
        readable_output=tableToMarkdown(f"ON2IT People matching `{email}`", people),
    )


# --------------------------------------------------------------------------- #
# Fetch + mirroring
# --------------------------------------------------------------------------- #


def _build_incident(case: dict[str, Any], mirror_direction: str | None) -> dict[str, Any]:
    """Translate an ON2IT case summary into an XSIAM incident dict."""
    case_number = case.get("case_number") or case.get("id")
    subject = case.get("subject") or ""
    occurred = _unix_to_iso(case.get("creation_date"))
    incident: dict[str, Any] = {
        "name": f"ON2IT [{case_number}] {subject}".strip(),
        "occurred": occurred,
        "rawJSON": json.dumps(case),
        "severity": _priority_to_severity(case.get("priority")),
        "dbotMirrorId": str(case.get("id") or ""),
    }
    if mirror_direction and mirror_direction != "None":
        incident["dbotMirrorDirection"] = mirror_direction
        incident["dbotMirrorInstance"] = demisto.integrationInstance()
    return incident


def _filter_cases_for_fetch(
    cases: list[dict[str, Any]],
    *,
    case_type_filter: set[str],
    state_filter: set[str],
    last_fetch: int,
) -> list[dict[str, Any]]:
    """Apply user-configured filters and the ``last_update > last_fetch`` watermark."""
    selected: list[dict[str, Any]] = []
    for case in cases:
        last_update = case.get("last_update") or 0
        # Strict > because next_last_fetch = max(selected last_update); equal would re-fetch on every cycle.
        if last_update <= last_fetch:
            continue
        if case_type_filter and case.get("case_type") not in case_type_filter:
            continue
        if state_filter and case.get("state") not in state_filter:
            continue
        selected.append(case)
    selected.sort(key=lambda c: c.get("last_update") or 0)
    return selected


def fetch_incidents(
    client: Client,
    last_run: dict[str, Any],
    params: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch new/updated ON2IT cases as XSIAM incidents.

    Returns ``(next_last_run, incidents)``.
    """
    case_type_filter = _multiselect_to_set(params.get("case_type_filter"))
    state_filter = _multiselect_to_set(params.get("state_filter"))
    mirror_direction = params.get("mirror_direction") or "None"
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_FETCH_LIMIT

    last_fetch = int(last_run.get("last_fetch") or 0)
    if not last_fetch:
        first_fetch_dt = arg_to_datetime(params.get("first_fetch") or "7 days", required=True)
        assert first_fetch_dt is not None  # arg_to_datetime(required=True) guarantees this
        last_fetch = int(first_fetch_dt.timestamp())

    # ON2IT API has no server-side filter or pagination on /cases — must pull the full list and filter client-side.
    cases = client.list_cases()
    selected = _filter_cases_for_fetch(
        cases,
        case_type_filter=case_type_filter,
        state_filter=state_filter,
        last_fetch=last_fetch,
    )[:max_fetch]

    incidents = [_build_incident(case, mirror_direction) for case in selected]
    next_last_fetch = max((case.get("last_update") or 0) for case in selected) if selected else last_fetch
    return {"last_fetch": int(next_last_fetch)}, incidents


def get_modified_remote_data_command(client: Client, args: dict[str, Any]) -> GetModifiedRemoteDataResponse:
    parsed = GetModifiedRemoteDataArgs(args)
    last_update_dt = arg_to_datetime(parsed.last_update, required=True)
    assert last_update_dt is not None
    last_update_ts = int(last_update_dt.timestamp())
    cases = client.list_cases()
    modified_ids = [str(case.get("id")) for case in cases if (case.get("last_update") or 0) > last_update_ts]
    return GetModifiedRemoteDataResponse(modified_ids)


def get_remote_data_command(client: Client, args: dict[str, Any], close_incident: bool) -> GetRemoteDataResponse:
    parsed = GetRemoteDataArgs(args)
    case = client.get_case(parsed.remote_incident_id)
    if not case:
        return GetRemoteDataResponse({}, [])

    last_update_dt = arg_to_datetime(parsed.last_update, required=True)
    assert last_update_dt is not None
    last_update_ts = int(last_update_dt.timestamp())

    entries: list[dict[str, Any]] = []
    for note in case.get("history_of_notes") or []:
        timestamp = note.get("timestamp") or 0
        if timestamp <= last_update_ts:
            continue
        content = note.get("content") or ""
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": content,
                "ContentsFormat": EntryFormat.TEXT,
                "Note": True,
            }
        )

    if close_incident and case.get("state") == "closed":
        # Special XSIAM mirroring entry: ContentsFormat=JSON + dbotIncidentClose=True closes the linked XSIAM incident.
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Closed from Zero Trust SOC.",
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        )

    return GetRemoteDataResponse(case, entries)


def update_remote_system_command(client: Client, args: dict[str, Any], close_on2it_case: bool) -> str:
    """Push XSIAM-side changes (notes, close) back to ON2IT.

    XSIAM passes outgoing entries with mixed-case keys depending on the source:
    manual war-room entries use lower-case (`type`, `contents`), mirrored entries
    sometimes use Pascal-case (`Contents`). We accept either.
    """
    parsed = UpdateRemoteSystemArgs(args)
    case_id = parsed.remote_incident_id

    for entry in parsed.entries or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == EntryType.NOTE or entry.get("category") == "note":
            note_text = entry.get("contents") or entry.get("Contents") or ""
            if isinstance(note_text, dict):
                note_text = json.dumps(note_text)
            if note_text:
                client.add_case_note(case_id, str(note_text))

    if close_on2it_case and parsed.inc_status == IncidentStatus.DONE:
        client.request_close_case(case_id)

    return case_id


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """Expose the ON2IT case fields that XSIAM admins may map outbound."""
    response = GetMappingFieldsResponse()
    scheme = SchemeTypeMapping(type_name="ZeroTrustSOC Case")
    for field in (
        "subject",
        "priority",
        "primary_contact_email",
        "state",
        "resolution_state",
        "case_type",
        "escalated",
    ):
        scheme.add_field(field)
    response.add_scheme_type(scheme)
    return response


# --------------------------------------------------------------------------- #
# Main dispatch
# --------------------------------------------------------------------------- #


COMMAND_HANDLERS = {
    "on2it-protectsurface-list": protectsurface_list_command,
    "on2it-protectsurface-get": protectsurface_get_command,
    "on2it-protectsurface-search": protectsurface_search_command,
    "on2it-protectsurface-states-list": protectsurface_states_list_command,
    "on2it-state-create": state_create_command,
    "on2it-state-delete": state_delete_command,
    "on2it-assessment-questions-get": assessment_questions_get_command,
    "on2it-assessment-create": assessment_create_command,
    "on2it-assessment-get": assessment_get_command,
    "on2it-assessment-list": assessment_list_command,
    "on2it-assessment-summary-get": assessment_summary_get_command,
    "on2it-assessment-delete": assessment_delete_command,
    "on2it-case-list": case_list_command,
    "on2it-case-get": case_get_command,
    "on2it-case-link": case_link_command,
    "on2it-case-add-note": case_add_note_command,
    "on2it-case-update-priority": case_update_priority_command,
    "on2it-case-update-subject": case_update_subject_command,
    "on2it-case-update-primary-contact": case_update_primary_contact_command,
    "on2it-case-escalate": case_escalate_command,
    "on2it-case-deescalate": case_deescalate_command,
    "on2it-case-close": case_close_command,
    "on2it-case-attach-file": case_attach_file_command,
    "on2it-asset-list": asset_list_command,
    "on2it-people-search": people_search_command,
}

_PROTECTSURFACE_COMMANDS = frozenset(
    {
        "on2it-protectsurface-list",
        "on2it-protectsurface-get",
        "on2it-protectsurface-search",
        "on2it-protectsurface-states-list",
        "on2it-state-create",
        "on2it-state-delete",
    }
)


def _build_client(params: dict[str, Any], creds_key: str = "credentials") -> Client:
    base_url = params.get("url") or "https://api.on2it.net/v3"
    creds = params.get(creds_key) or params.get("credentials") or {}
    token = creds.get("password") or ""
    if not token:
        raise DemistoException("API token is required. Configure it in the integration's API Token credentials field.")
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    return Client(base_url=base_url, token=token, verify=verify, proxy=proxy)


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Zero Trust SOC: command={command}")

    try:
        client = _build_client(params)
        ps_client = _build_client(params, creds_key="protectsurfacecredentials")
        eventflow_client = _build_client(params, creds_key="eventflowcredentials")

        if command == "test-module":
            return_results(test_module(ps_client))
            return

        if command == "fetch-incidents":
            next_run, incidents = fetch_incidents(client, demisto.getLastRun(), params)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            return

        if command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args))
            return

        if command == "get-remote-data":
            close_incident = argToBoolean(params.get("close_incident", False))
            return_results(get_remote_data_command(client, args, close_incident))
            return

        if command == "update-remote-system":
            close_on2it_case = argToBoolean(params.get("close_on2it_case", False))
            return_results(update_remote_system_command(client, args, close_on2it_case))
            return

        if command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
            return

        if command == "on2it-case-create":
            return_results(case_create_command(client, eventflow_client, args))
            return

        handler = COMMAND_HANDLERS.get(command)
        if handler is None:
            raise NotImplementedError(f"Command `{command}` is not implemented.")
        active_client = ps_client if command in _PROTECTSURFACE_COMMANDS else client
        return_results(handler(active_client, args))

    except Exception as exc:  # noqa: BLE001 - top-level boundary, surface to XSIAM
        return_error(f"Failed to execute {command} command. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
