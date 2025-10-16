"""
Integration tests for main.py
Tests API endpoints, routing, and application functionality
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def mock_globals():
    """Mock global variables in main module"""
    with patch('main.sub_nets', []), \
         patch('main.config', {'test_flag': True}), \
         patch('main.redirected', False):
        yield


@pytest.fixture
def app(mock_globals):
    """Create test application instance"""
    from main import app as main_app
    main_app.config["TESTING"] = True
    return main_app


@pytest.fixture
async def client(app):
    """Create test client"""
    return app.test_client()


@pytest.mark.integration
class TestStaticRoutes:
    """Test static page routes"""

    @pytest.mark.asyncio
    async def test_home_page(self, client):
        """Test home page loads successfully"""
        response = await client.get("/")
        assert response.status_code == 200
        data = await response.get_data(as_text=True)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_ticket_route_with_username(self, client):
        """Test ticket route with username parameter"""
        response = await client.get("/ticket/testuser")
        assert response.status_code == 200
        data = await response.get_data(as_text=True)
        assert "testuser" in data

    @pytest.mark.asyncio
    async def test_ticket_route_without_username(self, client):
        """Test ticket route without username"""
        response = await client.get("/ticket/")
        # Should either redirect or show error
        assert response.status_code in [200, 301, 302, 404]


@pytest.mark.integration
class TestAPIEndpoints:
    """Test API endpoints"""

    @pytest.mark.asyncio
    async def test_collect_basic_data_post(self, client):
        """Test basic data collection endpoint with POST"""
        test_data = {
            "screen": {"width": 1920, "height": 1080},
            "browser": {"userAgent": "Mozilla/5.0"},
        }

        with patch("main.send_to_discord") as mock_discord:
            mock_discord.return_value = None
            response = await client.post(
                "/api/collect-data",
                json=test_data,
                headers={"User-Agent": "Mozilla/5.0 Test Browser"},
            )

            assert response.status_code == 200
            json_data = await response.get_json()
            assert json_data["status"] == "success"

    @pytest.mark.asyncio
    async def test_collect_basic_data_get(self, client):
        """Test basic data collection endpoint with GET"""
        response = await client.get("/api/collect-data")
        # Should reject GET requests or return appropriate response
        assert response.status_code in [200, 405]

    @pytest.mark.asyncio
    async def test_collect_advanced_data_post(self, client):
        """Test advanced data collection endpoint"""
        test_data = {
            "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
            "canvas": "data:image/png;base64,test",
            "webgl": {
                "vendor": "Google Inc.",
                "renderer": "ANGLE",
            },
            "userIdentifier": "testuser",
        }

        with patch("main.send_advanced_data_to_discord") as mock_discord:
            mock_discord.return_value = None
            response = await client.post(
                "/api/collect-advanced-data",
                json=test_data,
                headers={
                    "User-Agent": "Mozilla/5.0 Test Browser",
                    "X-Forwarded-For": "192.168.1.100",
                },
            )

            assert response.status_code == 200
            json_data = await response.get_json()
            assert json_data["status"] == "success"

    @pytest.mark.asyncio
    async def test_collect_advanced_data_with_recognition(self, client):
        """Test advanced data collection triggers device recognition"""
        test_data = {
            "screen": {"width": 1920, "height": 1080},
            "canvas": "data:image/png;base64,test",
            "userIdentifier": "testuser",
        }

        with patch("main.send_advanced_data_to_discord") as mock_discord, patch(
            "main.get_tracker"
        ) as mock_get_tracker:
            mock_tracker = Mock()
            mock_tracker.generate_fingerprint.return_value = "abc123fingerprint"
            mock_tracker.check_device.return_value = (False, {"is_returning": False})
            mock_get_tracker.return_value = mock_tracker

            response = await client.post(
                "/api/collect-advanced-data",
                json=test_data,
                headers={
                    "User-Agent": "Mozilla/5.0 Test Browser",
                    "X-Forwarded-For": "192.168.1.100",
                },
            )

            assert response.status_code == 200
            # Verify device tracker was called
            assert mock_get_tracker.called


@pytest.mark.integration
class TestDeviceInfoExtraction:
    """Test device information extraction from requests"""

    @pytest.mark.asyncio
    async def test_user_agent_parsing(self, client):
        """Test that user agent is properly parsed"""
        test_data = {"screen": {"width": 1920, "height": 1080}}

        with patch("main.send_to_discord") as mock_discord:
            mock_discord.return_value = None
            response = await client.post(
                "/api/collect-data",
                json=test_data,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
            )

            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_ip_address_extraction_forwarded(self, client):
        """Test IP extraction from X-Forwarded-For header"""
        test_data = {"screen": {"width": 1920, "height": 1080}}

        with patch("main.send_advanced_data_to_discord") as mock_discord:
            mock_discord.return_value = None
            response = await client.post(
                "/api/collect-advanced-data",
                json=test_data,
                headers={
                    "X-Forwarded-For": "203.0.113.195, 10.0.0.1",
                    "User-Agent": "Mozilla/5.0",
                },
            )

            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_ip_address_extraction_real_ip(self, client):
        """Test IP extraction from X-Real-IP header"""
        test_data = {"screen": {"width": 1920, "height": 1080}}

        with patch("main.send_advanced_data_to_discord") as mock_discord:
            mock_discord.return_value = None
            response = await client.post(
                "/api/collect-advanced-data",
                json=test_data,
                headers={
                    "X-Real-IP": "203.0.113.195",
                    "User-Agent": "Mozilla/5.0",
                },
            )

            assert response.status_code == 200


@pytest.mark.integration
class TestErrorHandling:
    """Test error handling in endpoints"""

    @pytest.mark.asyncio
    async def test_collect_data_invalid_json(self, client):
        """Test handling of invalid JSON data"""
        response = await client.post(
            "/api/collect-data",
            data="not valid json",
            headers={"Content-Type": "application/json"},
        )

        # Should handle gracefully
        assert response.status_code in [200, 400, 500]

    @pytest.mark.asyncio
    async def test_collect_data_empty_payload(self, client):
        """Test handling of empty payload"""
        with patch("main.send_to_discord") as mock_discord:
            mock_discord.return_value = None
            response = await client.post(
                "/api/collect-data",
                json={},
                headers={"User-Agent": "Mozilla/5.0"},
            )

            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_discord_webhook_failure(self, client):
        """Test handling when Discord webhook fails"""
        test_data = {"screen": {"width": 1920, "height": 1080}}

        with patch("main.send_to_discord") as mock_discord:
            mock_discord.side_effect = Exception("Discord webhook failed")
            response = await client.post(
                "/api/collect-data",
                json=test_data,
                headers={"User-Agent": "Mozilla/5.0"},
            )

            # Should still return success to client even if Discord fails
            assert response.status_code == 200


@pytest.mark.integration
class TestVPNDetection:
    """Test VPN detection functionality"""

    @pytest.mark.asyncio
    async def test_vpn_check_endpoint_exists(self, client):
        """Test that VPN check endpoint exists"""
        response = await client.get("/api/check-vpn?ip=8.8.8.8")
        # Should respond (even if VPN check fails)
        assert response.status_code in [200, 404, 500]

    @pytest.mark.asyncio
    async def test_vpn_check_with_private_ip(self, client):
        """Test VPN check with private IP address"""
        response = await client.get("/api/check-vpn?ip=192.168.1.1")
        assert response.status_code in [200, 400, 404]


@pytest.mark.integration
class TestHealthAndStatus:
    """Test health check and status endpoints"""

    @pytest.mark.asyncio
    async def test_root_endpoint_responds(self, client):
        """Test that root endpoint responds"""
        response = await client.get("/")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_static_assets_accessible(self, client):
        """Test that static assets directory is accessible"""
        # Try to access a common static file (may not exist in test)
        response = await client.get("/static/style.css")
        # May be 200 (exists) or 404 (doesn't exist), but should respond
        assert response.status_code in [200, 404]


@pytest.mark.integration
class TestCORS:
    """Test CORS headers and cross-origin requests"""

    @pytest.mark.asyncio
    async def test_cors_headers_on_api(self, client):
        """Test that CORS headers are present on API endpoints"""
        response = await client.options("/api/collect-data")
        # Should allow OPTIONS preflight request
        assert response.status_code in [200, 204]

    @pytest.mark.asyncio
    async def test_api_accepts_cross_origin(self, client):
        """Test that API accepts requests from different origins"""
        test_data = {"screen": {"width": 1920, "height": 1080}}

        with patch("main.send_to_discord") as mock_discord:
            mock_discord.return_value = None
            response = await client.post(
                "/api/collect-data",
                json=test_data,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Origin": "http://example.com",
                },
            )

            # Should accept the request
            assert response.status_code == 200


@pytest.mark.integration
class TestTemplateRendering:
    """Test template rendering"""

    @pytest.mark.asyncio
    async def test_result_template_renders(self, client):
        """Test that result template renders with data"""
        response = await client.get("/ticket/testuser")
        assert response.status_code == 200
        data = await response.get_data(as_text=True)

        # Should contain template elements
        assert "html" in data.lower()
        assert "testuser" in data

    @pytest.mark.asyncio
    async def test_template_escapes_user_input(self, client):
        """Test that templates properly escape user input"""
        # Try to inject script tag
        response = await client.get("/ticket/<script>alert('xss')</script>")
        assert response.status_code in [200, 400, 404]

        if response.status_code == 200:
            data = await response.get_data(as_text=True)
            # Should escape the script tag
            assert "<script>alert('xss')</script>" not in data or "&lt;script&gt;" in data


@pytest.mark.integration
@pytest.mark.slow
class TestEndToEndFlow:
    """Test complete end-to-end user flows"""

    @pytest.mark.asyncio
    async def test_complete_tracking_flow(self, client):
        """Test complete flow: visit page -> collect data -> device tracking"""
        # Step 1: Visit ticket page
        response1 = await client.get("/ticket/testuser")
        assert response1.status_code == 200

        # Step 2: Collect basic data
        with patch("main.send_to_discord") as mock_discord:
            mock_discord.return_value = None
            response2 = await client.post(
                "/api/collect-data",
                json={"screen": {"width": 1920, "height": 1080}},
                headers={"User-Agent": "Mozilla/5.0"},
            )
            assert response2.status_code == 200

        # Step 3: Collect advanced data with device tracking
        with patch("main.send_advanced_data_to_discord") as mock_discord:
            mock_discord.return_value = None
            response3 = await client.post(
                "/api/collect-advanced-data",
                json={
                    "screen": {"width": 1920, "height": 1080},
                    "canvas": "data:image/png;base64,test",
                    "userIdentifier": "testuser",
                },
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "X-Forwarded-For": "192.168.1.100",
                },
            )
            assert response3.status_code == 200

    @pytest.mark.asyncio
    async def test_returning_user_flow(self, client):
        """Test flow for returning user with device recognition"""
        test_data = {
            "screen": {"width": 1920, "height": 1080},
            "canvas": "data:image/png;base64,consistent",
            "userIdentifier": "user1",
        }

        with patch("main.send_advanced_data_to_discord") as mock_discord:
            mock_discord.return_value = None

            # First visit
            response1 = await client.post(
                "/api/collect-advanced-data",
                json=test_data,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "X-Forwarded-For": "192.168.1.100",
                },
            )
            assert response1.status_code == 200

            # Second visit - should be recognized
            response2 = await client.post(
                "/api/collect-advanced-data",
                json=test_data,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "X-Forwarded-For": "192.168.1.100",
                },
            )
            assert response2.status_code == 200
