"""
Tests for crawler/static-path blocking and the robots.txt route.
"""
import pytest
from unittest.mock import patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.unit
class TestIsBlockedCrawlerPath:
    def test_blocks_robots_and_sitemap(self):
        from main import is_blocked_crawler_path
        assert is_blocked_crawler_path("robots.txt")
        assert is_blocked_crawler_path("sitemap.xml")

    def test_blocks_well_known(self):
        from main import is_blocked_crawler_path
        assert is_blocked_crawler_path(".well-known/security.txt")

    def test_blocks_static_assets(self):
        from main import is_blocked_crawler_path
        for p in ("style.css", "main.js", "logo.png", "favicon.ico", "font.woff2"):
            assert is_blocked_crawler_path(p), p

    def test_case_insensitive(self):
        from main import is_blocked_crawler_path
        assert is_blocked_crawler_path("Robots.TXT")
        assert is_blocked_crawler_path("/STYLE.CSS")

    def test_does_not_block_real_invites(self):
        from main import is_blocked_crawler_path
        for p in ("abc123", "realinvite", "user#1234", "abcdefg"):
            assert not is_blocked_crawler_path(p), p

    def test_empty_path_not_blocked(self):
        from main import is_blocked_crawler_path
        assert not is_blocked_crawler_path("")
        assert not is_blocked_crawler_path(None)


@pytest.mark.integration
class TestRobotsAndCrawlerRoutes:
    @pytest.fixture
    def client(self):
        with patch("main.sub_nets", []), patch("main.config", {"test_flag": True}), \
             patch("main.redirected", False):
            from main import app
            app.config["TESTING"] = True
            return app.test_client()

    @pytest.mark.asyncio
    async def test_robots_txt_served(self, client):
        resp = await client.get("/robots.txt")
        assert resp.status_code == 200
        body = (await resp.get_data(as_text=True)).lower()
        assert "user-agent" in body
        assert "disallow" in body

    @pytest.mark.asyncio
    async def test_crawler_path_returns_404_no_shield(self, client):
        with patch("main.redirect_handler") as mock_redir, \
             patch("main.send_to_channel") as mock_send:
            resp = await client.get("/robots.txt.ignore")
            assert resp.status_code in (404, 200)
            mock_redir.assert_not_called()
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_static_suffix_does_not_trigger_shield(self, client):
        with patch("main.redirect_handler") as mock_redir, \
             patch("main.send_to_channel") as mock_send:
            resp = await client.get("/style.css")
            assert resp.status_code in (404, 200)
            mock_redir.assert_not_called()
            mock_send.assert_not_called()
