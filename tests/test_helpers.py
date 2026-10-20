import unittest
from unittest.mock import Mock, patch

import main

class ValidationTests(unittest.TestCase):
    def test_username_allows_50_character_handle(self):
        self.assertTrue(main.USERNAME_RE.fullmatch("a" * 50))

    def test_normalize_domain(self):
        self.assertEqual(main.normalize_domain("Example.COM."), "example.com")

    def test_reject_domain_url(self):
        with self.assertRaises(ValueError):
            main.normalize_domain("https://example.com/path")

    def test_reject_single_label_domain(self):
        with self.assertRaises(ValueError):
            main.normalize_domain("localhost")

    def test_username_rejects_spaces(self):
        with self.assertRaises(ValueError):
            main.scan_username("two words")

    @patch.object(main, "GITHUB_TOKEN", "test-token")
    @patch.object(main, "YOUTUBE_API_KEY", "test-youtube-key")
    @patch.object(main.requests, "get")
    def test_username_uses_official_apis_and_treats_candidates_cautiously(self, get):
        def api_response(url, **kwargs):
            response = Mock()
            response.status_code = 200
            if "api.github.com" in url:
                response.json.return_value = {
                    "login": "octocat",
                    "name": "Octo Cat",
                    "public_repos": 8,
                    "followers": 12,
                    "html_url": "https://github.com/octocat",
                }
            elif "gitlab.com/api/v4/users" in url:
                response.json.return_value = [{
                    "username": "octocat",
                    "name": "Octo Cat",
                    "state": "active",
                    "web_url": "https://gitlab.com/octocat",
                }]
            elif "googleapis.com" in url:
                response.json.return_value = {
                    "items": [{
                        "id": {"channelId": "channel-123"},
                        "snippet": {"title": "Octocat Channel"},
                    }]
                }
            else:
                response.status_code = 200
                response.json.return_value = {}
            return response

        get.side_effect = api_response
        result = main.scan_username("octocat")
        checks = {check["source"]: check for check in result["checks"]}

        self.assertEqual(set(checks), {
            "GitHub", "GitLab", "YouTube", "Instagram", "Reddit",
            "LinkedIn", "TikTok", "Keybase",
        })
        self.assertEqual(checks["GitHub"]["status"], "found")
        self.assertEqual(checks["GitLab"]["status"], "found")
        self.assertEqual(checks["YouTube"]["status"], "inconclusive")
        self.assertEqual(len(checks["YouTube"]["matches"]), 1)
        self.assertTrue(all(
            checks[name]["status"] == "inconclusive"
            for name in ("Instagram", "Reddit", "LinkedIn", "TikTok", "Keybase")
        ))
        github_request = next(
            call for call in get.call_args_list if "api.github.com" in call.args[0]
        )
        self.assertEqual(
            github_request.kwargs["headers"]["Authorization"],
            "Bearer test-token",
        )
        self.assertNotIn("test-token", github_request.args[0])

    @patch.object(main, "YOUTUBE_API_KEY", "")
    @patch.object(main.requests, "get")
    def test_youtube_is_inconclusive_without_api_key(self, get):
        result = main.check_youtube("octocat")

        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("not configured", result["evidence"])
        get.assert_not_called()

    @patch.object(main, "YOUTUBE_API_KEY", "test-youtube-key")
    @patch.object(main.requests, "get")
    def test_youtube_request_error_does_not_expose_api_key(self, get):
        get.side_effect = main.requests.ConnectionError(
            "request failed with key=test-youtube-key"
        )

        result = main.check_youtube("octocat")

        self.assertEqual(result["status"], "inconclusive")
        self.assertNotIn("test-youtube-key", result["evidence"])

    def test_email_invalid_syntax(self):
        with self.assertRaises(ValueError):
            main.scan_email("not-an-email")

    @patch.object(main.requests, "get")
    def test_email_xposedornot_breaches(self, get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "status": "success",
            "breaches": [["ExampleBreach"], "OtherBreach", ["ExampleBreach"]],
            "breach_details": [{
                "name": "ExampleBreach",
                "breach_date": "2024-01-01",
                "company": {"name": "Example"},
                "exposed_data": ["Email addresses"],
            }],
        }
        get.return_value = response

        result = main.scan_email("person+tag@example.com")

        self.assertEqual(result["breach_source"], "XposedOrNot")
        self.assertIn("sent to XposedOrNot", result["privacy_notice"])
        self.assertEqual(result["breach_lookup"]["status"], "breaches_reported")
        self.assertEqual(result["breach_lookup"]["count"], 2)
        self.assertEqual(
            [breach["name"] for breach in result["breach_lookup"]["breaches"]],
            ["ExampleBreach", "OtherBreach"],
        )
        self.assertIn("person+tag@example.com", get.call_args.args[0])
        self.assertEqual(get.call_args.kwargs["params"], {"details": "true"})
        self.assertEqual(
            get.call_args.kwargs["headers"]["Accept"],
            "application/json",
        )

    @patch.object(main.requests, "get")
    def test_email_xposedornot_no_matches(self, get):
        get.return_value.status_code = 200
        get.return_value.json.return_value = {"breaches": []}

        result = main.scan_email("person@example.com")

        self.assertEqual(result["breach_lookup"]["status"], "no_breaches_returned")

    @patch.object(main.requests, "get")
    def test_email_xposedornot_rate_limit(self, get):
        get.return_value.status_code = 429
        get.return_value.headers = {"Retry-After": "60"}

        result = main.scan_email("person@example.com")

        self.assertEqual(result["breach_lookup"]["status"], "rate_limited")
        self.assertNotIn("retry_after", result["breach_lookup"])

    @patch.object(main.requests, "get")
    def test_email_xposedornot_non_200_is_error(self, get):
        get.return_value.status_code = 404

        result = main.scan_email("person@example.com")

        self.assertEqual(result["breach_lookup"]["status"], "error")
        self.assertIn("HTTP 404", result["breach_lookup"]["message"])

    @patch.object(main.requests, "get")
    def test_email_xposedornot_invalid_response_is_error(self, get):
        get.return_value.status_code = 200
        get.return_value.json.return_value = {"breaches": "unexpected"}

        result = main.scan_email("person@example.com")

        self.assertEqual(result["breach_lookup"]["status"], "error")

if __name__ == "__main__":
    unittest.main()
