"""
Tests for Phase D server-side enrichment modules.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.unit
class TestBuildLanguageProfile:
    """Test build_language_profile() parsing of Accept-Language header."""

    def test_standard_header(self):
        from main import build_language_profile
        di = {"accept_language": "en-US,en;q=0.9,de;q=0.8"}
        result = build_language_profile(di)
        assert result["primary"] == "en-US"
        assert result["primaryLanguage"] == "en"
        assert result["region"] == "US"
        assert result["count"] == 3
        assert result["entropyBits"] > 0

    def test_single_language(self):
        from main import build_language_profile
        di = {"accept_language": "ja"}
        result = build_language_profile(di)
        assert result["primary"] == "ja"
        assert result["primaryLanguage"] == "ja"
        assert result["region"] is None

    def test_script_subtag(self):
        from main import build_language_profile
        di = {"accept_language": "zh-Hant-TW"}
        result = build_language_profile(di)
        assert result["primaryLanguage"] == "zh"
        assert result["script"] == "Hant"
        assert result["region"] == "TW"

    def test_geo_mismatch_detected(self):
        from main import build_language_profile
        di = {"accept_language": "ru-RU,ru;q=0.9"}
        result = build_language_profile(di, country_code="US")
        assert result["geoMismatch"] is True

    def test_geo_match(self):
        from main import build_language_profile
        di = {"accept_language": "en-US,en;q=0.9"}
        result = build_language_profile(di, country_code="US")
        assert result["geoMismatch"] is False

    def test_unknown_header_returns_empty(self):
        from main import build_language_profile
        assert build_language_profile({"accept_language": "Unknown"}) == {}
        assert build_language_profile({}) == {}


@pytest.mark.unit
class TestBuildProtocolPosture:
    """Test build_protocol_posture() header derivation."""

    def test_basic_https(self):
        from main import build_protocol_posture
        di = {
            "scheme": "https", "x_forwarded_proto": "https",
            "cf_ray": "89abc", "cf_connecting_ip": "1.2.3.4",
            "x_forwarded_for": "1.2.3.4",
        }
        result = build_protocol_posture(di)
        assert result["schemeObserved"] == "https"
        assert result["cloudflareEdge"] is True
        assert result["proxyChainDepth"] == 1
        assert result["ipSource"] == "CF-Connecting-IP"

    def test_deep_proxy_chain(self):
        from main import build_protocol_posture
        di = {
            "scheme": "http", "x_forwarded_for": "1.2.3.4, 5.6.7.8, 9.10.11.12",
        }
        result = build_protocol_posture(di)
        assert result["proxyChainDepth"] == 3

    def test_protocol_mismatch(self):
        from main import build_protocol_posture
        di = {
            "scheme": "http", "x_forwarded_proto": "https",
        }
        result = build_protocol_posture(di)
        assert result["protoConsistency"] is False

    def test_empty_returns_empty(self):
        from main import build_protocol_posture
        assert build_protocol_posture({}) == {}
        assert build_protocol_posture(None) == {}


@pytest.mark.unit
class TestAsnLookup:
    """Test asn_lookup module structure and classification."""

    def test_classify_datacenter(self):
        from asn_lookup import _classify
        assert "Datacenter" in _classify("AS13335", "Cloudflare, Inc.")

    def test_classify_hosting(self):
        from asn_lookup import _classify
        assert "VPN/Hosting" in _classify("AS99999", "Some Hosting Provider")

    def test_classify_residential(self):
        from asn_lookup import _classify
        assert "Residential" in _classify("AS7922", "Comcast Cable Communications")

    def test_lookup_returns_none_for_invalid_ip(self):
        from asn_lookup import lookup_asn
        # Without DB loaded, returns None gracefully
        assert lookup_asn("not-an-ip") is None

    def test_module_has_set_logger(self):
        from asn_lookup import set_logger
        assert callable(set_logger)
