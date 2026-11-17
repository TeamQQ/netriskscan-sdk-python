from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from netriskscan import IpLocation, IpNetwork
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


def test_schema_160_all_fields(schema_160_body):
    result = IpRiskResult._from_json(schema_160_body)
    assert result.network.domain == "operator.example"
    assert result.network.range == "192.0.2.0/24"
    assert result.location is not None
    assert result.location.continent_code == "NA"
    assert result.location.continent == "North America"
    assert result.location.postal_code == "00501"
    assert isinstance(result.location.postal_code, str)
    assert result.location.latitude == 40.81
    assert result.location.longitude == -73.04
    assert type(result.location.latitude) is float
    assert type(result.location.longitude) is float


@pytest.mark.parametrize("explicit_null", [False, True], ids=["missing", "null"])
def test_schema_160_unknown_fields_default_to_none(explicit_null):
    body = dict(SAMPLE_IP_RISK_BODY)
    if explicit_null:
        body["network"] = dict(body["network"], domain=None, range=None)
        body["location"] = dict(
            body["location"],
            continentCode=None,
            continent=None,
            postalCode=None,
            latitude=None,
            longitude=None,
        )
    result = IpRiskResult._from_json(body)
    assert result.network.domain is None
    assert result.network.range is None
    assert result.network.profile == "public_dns_resolver"
    assert result.network.service == "Google Public DNS"
    assert result.network.asn == "AS15169"
    assert result.location is not None
    assert result.location.country_code == "US"
    assert result.location.time_zone == "America/Chicago"
    assert result.location.continent_code is None
    assert result.location.continent is None
    assert result.location.postal_code is None
    assert result.location.latitude is None
    assert result.location.longitude is None


@pytest.mark.parametrize("latitude,longitude", [(0.0, 0.0), (-90.0, -180.0), (90.0, 180.0)])
def test_coordinates_preserve_zero_and_boundaries(schema_160_body, latitude, longitude):
    schema_160_body["location"].update(latitude=latitude, longitude=longitude)
    location = IpRiskResult._from_json(schema_160_body).location
    assert location is not None
    assert location.latitude == latitude
    assert location.longitude == longitude
    assert type(location.latitude) is float
    assert type(location.longitude) is float


def test_anycast_coordinates_are_not_inferred(schema_160_body):
    schema_160_body["network"].update(profile="public_dns_resolver")
    schema_160_body["location"].update(latitude=None, longitude=None, postalCode=None)
    location = IpRiskResult._from_json(schema_160_body).location
    assert location is not None
    assert location.country_code == "US"
    assert location.continent == "North America"
    assert location.latitude is None
    assert location.longitude is None
    assert location.postal_code is None


def test_ipv6_range_is_preserved(schema_160_body):
    schema_160_body["ip"] = "2001:db8::10"
    schema_160_body["network"]["range"] = "2001:db8::/48"
    result = IpRiskResult._from_json(schema_160_body)
    assert result.ip == "2001:db8::10"
    assert result.network.range == "2001:db8::/48"


@pytest.mark.parametrize(
    "location_data,expected",
    [
        ({"countryCode": "US", "country": "United States"}, ("US", None, None, None)),
        (
            {"continentCode": "NA", "continent": "North America"},
            (None, "NA", "North America", None),
        ),
        ({"latitude": None, "longitude": None}, (None, None, None, None)),
        (None, None),
    ],
    ids=["country-only", "continent-without-city", "null-coordinates", "no-location"],
)
def test_partial_locations(schema_160_body, location_data, expected):
    schema_160_body["location"] = location_data
    location = IpRiskResult._from_json(schema_160_body).location
    if expected is None:
        assert location is None
    else:
        assert location is not None
        assert (
            location.country_code,
            location.continent_code,
            location.continent,
            location.city,
        ) == expected
        assert location.latitude is None
        assert location.longitude is None
        assert location.postal_code is None


@pytest.mark.parametrize(
    "domain,network_range", [(None, "192.0.2.0/24"), ("operator.example", None)]
)
def test_partial_network_fields(schema_160_body, domain, network_range):
    schema_160_body["network"].update(domain=domain, range=network_range)
    network = IpRiskResult._from_json(schema_160_body).network
    assert network.domain == domain
    assert network.range == network_range


@pytest.mark.parametrize(
    "section,attribute",
    [
        ("network", "domain"),
        ("network", "range"),
        ("location", "continent_code"),
        ("location", "continent"),
        ("location", "postal_code"),
        ("location", "latitude"),
        ("location", "longitude"),
    ],
)
def test_new_fields_are_frozen(schema_160_body, section, attribute):
    model = getattr(IpRiskResult._from_json(schema_160_body), section)
    with pytest.raises(FrozenInstanceError):
        setattr(model, attribute, None)


def test_legacy_positional_constructors_and_public_exports():
    from netriskscan import IpRiskResult as PublicResult
    from netriskscan.models import IpLocation as ModelLocation
    from netriskscan.models import IpNetwork as ModelNetwork

    assert PublicResult is IpRiskResult
    assert ModelNetwork is IpNetwork
    assert ModelLocation is IpLocation
    for network in (
        IpNetwork("hosting", "direct", "AS64500", "Example"),
        IpNetwork("hosting", "direct", "AS64500", "Example", "profile", "service"),
    ):
        assert network.organization == "Example"
        assert network.domain is None
        assert network.range is None
    assert network.profile == "profile"
    assert network.service == "service"
    location = IpLocation("US", "United States", "NY", "New York", "Example", "America/New_York")
    assert location.city == "Example"
    assert location.time_zone == "America/New_York"
    assert location.continent_code is None
    assert location.continent is None
    assert location.postal_code is None
    assert location.latitude is None
    assert location.longitude is None


@pytest.mark.parametrize("index", [0, None])
@pytest.mark.parametrize("proxy", [True, False, None])
def test_schema_160_preserves_score_and_flag_semantics(schema_160_body, index, proxy):
    schema_160_body["risk"].update(index=index)
    schema_160_body["flags"].update(proxy=proxy)
    schema_160_body["network"]["futureField"] = {"value": True}
    schema_160_body["location"]["futureField"] = [1, 2, 3]
    result = IpRiskResult._from_json(schema_160_body)
    assert result.risk.index is index
    assert result.flags.proxy is proxy
    assert result.risk.reasons == []
    assert result.network.domain == "operator.example"
    assert result.location is not None
    assert result.location.postal_code == "00501"
