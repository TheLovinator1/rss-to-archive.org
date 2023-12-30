import requests_mock

from rss_to_archive_org.main import get_status


def test_get_status() -> None:
    """Test the get_status function."""
    with requests_mock.Mocker() as m:
        # Mock the "success" status
        m.get("http://web.archive.org/save/status/123", json={"status": "success"})
        assert get_status(job_id="123") == "success"

        # Mock the "error" status
        m.get("http://web.archive.org/save/status/456", json={"status": "error"})
        assert get_status(job_id="456") == "error"
