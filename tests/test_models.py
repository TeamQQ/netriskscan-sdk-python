from __future__ import annotations

from netriskscan.models.risk import IpRiskResult
from netriskscan.models.usage import UsageResult

from .conftest import SAMPLE_IP_RISK_BODY, SAMPLE_USAGE_BODY


def test_tri_state_flags_preserve_none_vs_false():
    body = dict(SAMPLE_IP_RISK_BODY)
    body["flags"] = dict(body["flags"], proxy=False, vpn=None, tor=True)
    result = IpRiskResult._from_json(body)

    assert result.flags.proxy is False
    assert result.flags.vpn is None
    assert result.flags.tor is True
    # A tri-state False must never compare equal to None, and vice versa.
    assert result.flags.proxy is not None
    assert result.flags.vpn is not False


def test_proxy_type_populated_only_when_proxy_detected():
    body = dict(SAMPLE_IP_RISK_BODY)
    body["flags"] = dict(body["flags"], proxy=True, proxyType="residential_proxy")
    result = IpRiskResult._from_json(body)

    assert result.flags.proxy is True
    assert result.flags.proxy_type == "residential_proxy"


def test_reasons_list_parses_open_vocabulary_codes():
    body = dict(SAMPLE_IP_RISK_BODY)
    body["risk"] = dict(
        body["risk"],
        reasons=[{"code": "VPN_DETECTED", "category": "anonymity", "severity": "medium"}],
    )
    result = IpRiskResult._from_json(body)

    assert len(result.risk.reasons) == 1
    assert result.risk.reasons[0].code == "VPN_DETECTED"
    assert result.risk.reasons[0].category == "anonymity"


def test_empty_reasons_list_is_not_none():
    result = IpRiskResult._from_json(SAMPLE_IP_RISK_BODY)
    assert result.risk.reasons == []


def test_network_profile_and_service_default_to_none_when_omitted():
    body = dict(SAMPLE_IP_RISK_BODY)
    network = {k: v for k, v in body["network"].items() if k not in ("profile", "service")}
    body["network"] = network
    result = IpRiskResult._from_json(body)

    assert result.network.profile is None
    assert result.network.service is None


def test_tor_block_present_only_for_relays():
    body = dict(SAMPLE_IP_RISK_BODY)
    body["tor"] = {"isRelay": True, "isExit": False, "isBadExit": False, "role": "guard"}
    result = IpRiskResult._from_json(body)

    assert result.tor is not None
    assert result.tor.role == "guard"
    assert result.tor.is_exit is False


def test_tor_block_absent_by_default():
    result = IpRiskResult._from_json(SAMPLE_IP_RISK_BODY)
    assert result.tor is None


def test_unknown_future_fields_are_ignored_forward_compatibly():
    body = dict(SAMPLE_IP_RISK_BODY)
    body["futureTopLevelField"] = {"anything": True}
    body["risk"] = dict(body["risk"], futureRiskField="unexpected")
    body["flags"] = dict(body["flags"], futureFlag=True)

    result = IpRiskResult._from_json(body)  # must not raise

    assert result.risk.index == 95
    assert result.flags.datacenter is True


def test_usage_result_parses_full_shape():
    result = UsageResult._from_json(SAMPLE_USAGE_BODY)

    assert result.plan == "growth"
    assert result.period.start == "2026-09-01T00:00:00Z"
    assert result.units.used == 1200
    assert result.rate_limit.requests_per_minute == 120
