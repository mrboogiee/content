"""Unit tests for the ZeroTrustSOC integration.

These tests do not hit the network: they stub HTTP via ``requests_mock`` and
exercise the command functions directly with a real ``Client`` instance.
"""

import json
from pathlib import Path

import pytest
from CommonServerPython import EntryFormat, EntryType, IncidentStatus

from ZeroTrustSOC import (
    Client,
    _build_incident,
    _filter_cases_for_fetch,
    _priority_to_severity,
    case_create_command,
    case_get_command,
    case_link_command,
    case_list_command,
    fetch_incidents,
    get_remote_data_command,
    protectsurface_list_command,
    protectsurface_search_command,
    update_remote_system_command,
)

TEST_DATA = Path(__file__).parent / "test_data"
BASE_URL = "https://api.on2it.test/v3"


def _load(name: str) -> dict:
    return json.loads((TEST_DATA / name).read_text())


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, token="dummy-token", verify=False, proxy=False)


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("priority", "expected"),
    [(1, 4), (2, 3), (3, 2), (4, 1), ("2", 3), (None, 0), ("nope", 0), (99, 0)],
)
def test_priority_to_severity(priority, expected):
    assert _priority_to_severity(priority) == expected


@pytest.mark.parametrize(
    ("content_type", "expected_method"),
    [
        ("ipv4", "ip"),
        ("ipv6", "ip"),
        ("hostname", "exact"),
        ("user_identity", "exact"),
        ("aws_cloud", "exact"),
        ("azure_cloud", "exact"),
        ("gcp_cloud", "exact"),
        ("container", "exact"),
    ],
)
def test_protectsurface_search_picks_match_method(client, requests_mock, content_type, expected_method):
    """search must auto-derive match_method='ip' for ipv4/ipv6, 'exact' otherwise."""
    matcher = requests_mock.get(
        f"{BASE_URL}/zerotrust/get-protectsurface-by-state-type-and-value-match",
        json=_load("protectsurface_search.json"),
    )
    result = protectsurface_search_command(client, {"content_type": content_type, "value": "anything"})

    assert matcher.last_request.qs["match_type"] == [content_type]
    assert matcher.last_request.qs["match_method"] == [expected_method]
    assert matcher.last_request.qs["match_value"] == ["anything"]
    assert result.outputs_prefix == "On2IT.ProtectSurface"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1


# --------------------------------------------------------------------------- #
# ZeroTrust commands
# --------------------------------------------------------------------------- #


def test_protectsurface_list_returns_outputs(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/zerotrust/get-protectsurfaces", json=_load("protectsurfaces_list.json"))
    result = protectsurface_list_command(client, {"limit": "10"})
    assert result.outputs_prefix == "On2IT.ProtectSurface"
    assert result.outputs_key_field == "id"
    assert [ps["id"] for ps in result.outputs] == ["ps-001", "ps-002"]
    assert "Crown Jewels DB" in result.readable_output


def test_protectsurface_list_respects_limit(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/zerotrust/get-protectsurfaces", json=_load("protectsurfaces_list.json"))
    result = protectsurface_list_command(client, {"limit": "1"})
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == "ps-001"


# --------------------------------------------------------------------------- #
# Case commands
# --------------------------------------------------------------------------- #


def test_case_list_parses_fixture(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/case/integration/cases", json=_load("case_list.json"))
    result = case_list_command(client, {})
    assert result.outputs_prefix == "On2IT.Case"
    assert {c["id"] for c in result.outputs} == {"case-aaa", "case-bbb", "case-ccc"}
    assert "C-1001" in result.readable_output


def test_case_get_parses_fixture(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/case/integration/case-aaa", json=_load("case_detail.json"))
    result = case_get_command(client, {"id": "case-aaa"})
    assert result.outputs["id"] == "case-aaa"
    assert result.outputs["priority"] == 2
    assert len(result.outputs["history_of_notes"]) == 2


def test_case_create_sends_envelope(client, requests_mock):
    matcher = requests_mock.post(f"{BASE_URL}/case/integration", json={"data": None}, status_code=201)
    result = case_create_command(
        client,
        {
            "id": "case-xyz",
            "subject": "Test subject",
            "note": "Hello world",
            "case_type": "incident",
            "priority": "2",
            "primary_contact_email": "ops@example.com",
        },
    )
    body = matcher.last_request.json()
    assert "items" in body
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item == {
        "id": "case-xyz",
        "subject": "Test subject",
        "note": "Hello world",
        "case_type": "incident",
        "priority": 2,
        "primary_contact_email": "ops@example.com",
    }
    assert result.outputs["id"] == "case-xyz"


def test_case_create_rejects_invalid_priority(client, requests_mock):
    requests_mock.post(f"{BASE_URL}/case/integration", json={"data": None}, status_code=201)
    with pytest.raises(Exception, match="priority must be"):
        case_create_command(
            client,
            {
                "subject": "x",
                "note": "y",
                "primary_contact_email": "ops@example.com",
                "priority": "9",
            },
        )


def test_case_link_posts_note_when_not_silent(client, requests_mock, mocker):
    mocker.patch("ZeroTrustSOC.demisto.incident", return_value={"id": "INC-42"})
    matcher = requests_mock.post(f"{BASE_URL}/case/integration/case-aaa/notes", json={"data": None})

    result = case_link_command(client, {"on2it_case_id": "case-aaa", "silent": "false"})

    assert matcher.called
    body = matcher.last_request.json()
    assert body == {"items": [{"note": "Linked to Cortex XSIAM incident INC-42."}]}
    assert result.outputs == {
        "on2it_case_id": "case-aaa",
        "xsiam_incident_id": "INC-42",
        "linked_at": result.outputs["linked_at"],
    }


def test_case_link_silent_skips_note(client, requests_mock, mocker):
    mocker.patch("ZeroTrustSOC.demisto.incident", return_value={"id": "INC-42"})
    matcher = requests_mock.post(f"{BASE_URL}/case/integration/case-aaa/notes", json={"data": None})

    result = case_link_command(client, {"on2it_case_id": "case-aaa", "silent": "true"})

    assert not matcher.called
    assert result.outputs["xsiam_incident_id"] == "INC-42"


# --------------------------------------------------------------------------- #
# Fetch + mirroring
# --------------------------------------------------------------------------- #


def test_filter_cases_respects_state_and_type():
    cases = _load("case_list.json")["items"]
    result = _filter_cases_for_fetch(
        cases,
        case_type_filter={"securityincident"},
        state_filter={"new", "in_progress"},
        last_fetch=0,
    )
    # case-ccc is closed (state filter), case-bbb is type=change (type filter)
    assert [c["id"] for c in result] == ["case-aaa"]


def test_filter_cases_uses_last_fetch_watermark():
    cases = _load("case_list.json")["items"]
    result = _filter_cases_for_fetch(cases, case_type_filter=set(), state_filter=set(), last_fetch=1714600000)
    assert [c["id"] for c in result] == ["case-bbb"]  # only case-bbb has last_update > 1714600000


def test_fetch_incidents_advances_last_run(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/case/integration/cases", json=_load("case_list.json"))

    next_run, incidents = fetch_incidents(
        client,
        last_run={"last_fetch": 1714000000},
        params={
            "case_type_filter": ["securityincident"],
            "state_filter": ["new", "in_progress", "closed"],
            "max_fetch": "10",
            "mirror_direction": "Incoming",
        },
    )

    # securityincident + matching states => case-aaa and case-ccc
    incident_ids = [i["dbotMirrorId"] for i in incidents]
    assert set(incident_ids) == {"case-aaa", "case-ccc"}
    assert next_run["last_fetch"] == 1714500000  # max(last_update) of selected cases
    assert all("ON2IT [" in i["name"] for i in incidents)


def test_build_incident_includes_mirror_metadata(mocker):
    mocker.patch("ZeroTrustSOC.demisto.integrationInstance", return_value="instance-1")
    case = {
        "id": "case-aaa",
        "case_number": "C-1001",
        "subject": "x",
        "creation_date": 1714400000,
        "priority": 1,
    }
    incident = _build_incident(case, "Incoming And Outgoing")
    assert incident["dbotMirrorDirection"] == "Incoming And Outgoing"
    assert incident["dbotMirrorInstance"] == "instance-1"
    assert incident["severity"] == 4  # priority 1 => critical
    assert incident["dbotMirrorId"] == "case-aaa"


def test_get_remote_data_emits_note_and_close_entries(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/case/integration/case-aaa", json=_load("case_detail.json"))
    closed_payload = {
        "items": [
            {
                **_load("case_detail.json")["items"][0],
                "state": "closed",
                "history_of_notes": [{"content": "All done.", "timestamp": 1714500001}],
            }
        ]
    }
    requests_mock.get(f"{BASE_URL}/case/integration/case-bbb", json=closed_payload)

    # Notes after lastUpdate=1714400000 => both notes from case-aaa surface, no close entry
    result_open = get_remote_data_command(
        client,
        {"id": "case-aaa", "lastUpdate": "2024-04-29T14:00:00Z"},
        close_incident=True,
    )
    note_entries = [e for e in result_open.entries if e["Type"] == EntryType.NOTE and e["ContentsFormat"] == EntryFormat.TEXT]
    assert len(note_entries) == 2
    assert all(e["Note"] is True for e in note_entries)

    # Closed case + close_incident=True => one extra close entry (JSON format)
    result_closed = get_remote_data_command(
        client,
        {"id": "case-bbb", "lastUpdate": "2024-04-29T14:00:00Z"},
        close_incident=True,
    )
    close_entries = [e for e in result_closed.entries if e["ContentsFormat"] == EntryFormat.JSON]
    assert len(close_entries) == 1
    assert close_entries[0]["Contents"]["dbotIncidentClose"] is True


def test_update_remote_system_posts_notes_and_closes(client, requests_mock):
    note_matcher = requests_mock.post(f"{BASE_URL}/case/integration/case-aaa/notes", json={"data": None})
    close_matcher = requests_mock.post(f"{BASE_URL}/case/integration/case-aaa/request-close", json={"data": None})

    args = {
        "remoteId": "case-aaa",
        "status": IncidentStatus.DONE,
        "entries": [
            {"type": EntryType.NOTE, "contents": "Analyst comment from XSIAM"},
            {"type": EntryType.NOTE, "contents": ""},  # empty note must be skipped
        ],
        "data": {},
        "delta": {},
        "incidentChanged": True,
    }
    remote_id = update_remote_system_command(client, args, close_on2it_case=True)

    assert remote_id == "case-aaa"
    assert note_matcher.call_count == 1
    assert note_matcher.last_request.json() == {"items": [{"note": "Analyst comment from XSIAM"}]}
    assert close_matcher.call_count == 1


def test_update_remote_system_skips_close_when_disabled(client, requests_mock):
    requests_mock.post(f"{BASE_URL}/case/integration/case-aaa/notes", json={"data": None})
    close_matcher = requests_mock.post(f"{BASE_URL}/case/integration/case-aaa/request-close", json={"data": None})

    update_remote_system_command(
        client,
        {
            "remoteId": "case-aaa",
            "status": IncidentStatus.DONE,
            "entries": [],
            "data": {},
            "delta": {},
            "incidentChanged": False,
        },
        close_on2it_case=False,
    )
    assert close_matcher.call_count == 0


# --------------------------------------------------------------------------- #
# Tests for State Management Commands
# --------------------------------------------------------------------------- #


def test_state_create_command(client, requests_mock):
    """Test creating/replacing a state."""
    state_data = {
        "id": "test_state",
        "protectsurface_id": "ps_123",
        "content_type": "ipv4",
        "content": ["10.0.0.1", "10.0.0.2"],
        "description": "Test state",
    }
    requests_mock.post(
        f"{BASE_URL}/zerotrust/create-or-replace-state",
        json={"items": [state_data]},
    )

    from ZeroTrustSOC import state_create_command

    result = state_create_command(
        client,
        {
            "id": "test_state",
            "protectsurface_id": "ps_123",
            "content_type": "ipv4",
            "content": "10.0.0.1,10.0.0.2",
            "description": "Test state",
        },
    )

    assert result.outputs["id"] == "test_state"
    assert result.outputs["content_type"] == "ipv4"


def test_state_delete_command(client, requests_mock):
    """Test deleting a state."""
    requests_mock.post(
        f"{BASE_URL}/zerotrust/remove-state",
        json={"data": None},
    )

    from ZeroTrustSOC import state_delete_command

    result = state_delete_command(client, {"id": "test_state"})

    assert "successfully removed" in result.readable_output


# --------------------------------------------------------------------------- #
# Tests for Assessment Commands
# --------------------------------------------------------------------------- #


def test_assessment_questions_get_command(client, requests_mock):
    """Test retrieving assessment base questions."""
    questions = {"items": [{"question": "Q1", "options": ["A", "B", "C"]}]}
    requests_mock.get(
        f"{BASE_URL}/zerotrust/get-base-questions",
        json=questions,
    )

    from ZeroTrustSOC import assessment_questions_get_command

    result = assessment_questions_get_command(client, {})

    assert result.outputs == questions
    assert "Assessment Base Questions" in result.readable_output


def test_assessment_create_command(client, requests_mock):
    """Test creating an assessment."""
    assessment_data = {
        "id": "assessment_123",
        "assessment_timestamp": 1234567890,
        "answers": {"q1": "a1"},
    }
    requests_mock.post(
        f"{BASE_URL}/zerotrust/create-assessment",
        json={"items": [assessment_data]},
    )

    from ZeroTrustSOC import assessment_create_command

    result = assessment_create_command(
        client,
        {
            "timestamp": 1234567890,
            "answers": '{"q1": "a1"}',
        },
    )

    assert result.outputs["id"] == "assessment_123"
    assert "Assessment Created" in result.readable_output


def test_assessment_get_command(client, requests_mock):
    """Test getting a specific assessment."""
    assessment_data = {
        "id": "assessment_123",
        "assessment_timestamp": 1234567890,
    }
    requests_mock.get(
        f"{BASE_URL}/zerotrust/get-assessment-by-id",
        json={"items": [assessment_data]},
    )

    from ZeroTrustSOC import assessment_get_command

    result = assessment_get_command(client, {"id": "assessment_123"})

    assert result.outputs["id"] == "assessment_123"


def test_assessment_list_command(client, requests_mock):
    """Test listing assessments with pagination."""
    assessments = [
        {"id": "assessment_1", "assessment_timestamp": 1234567890},
        {"id": "assessment_2", "assessment_timestamp": 1234567891},
    ]
    requests_mock.get(
        f"{BASE_URL}/zerotrust/get-assessments",
        json={"items": assessments},
    )

    from ZeroTrustSOC import assessment_list_command

    result = assessment_list_command(client, {"page_size": "2"})

    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "assessment_1"


def test_assessment_summary_get_command(client, requests_mock):
    """Test getting assessment summaries."""
    summaries = [
        {"summary_field": "value1"},
        {"summary_field": "value2"},
    ]
    requests_mock.get(
        f"{BASE_URL}/zerotrust/get-assessments-summary",
        json={"items": summaries},
    )

    from ZeroTrustSOC import assessment_summary_get_command

    result = assessment_summary_get_command(client, {})

    assert len(result.outputs) == 2
    assert "Assessment Summaries" in result.readable_output


def test_assessment_delete_command(client, requests_mock):
    """Test deleting an assessment."""
    requests_mock.post(
        f"{BASE_URL}/zerotrust/remove-assessment-by-id",
        json={"data": None},
    )

    from ZeroTrustSOC import assessment_delete_command

    result = assessment_delete_command(client, {"id": "assessment_123"})

    assert "successfully removed" in result.readable_output
