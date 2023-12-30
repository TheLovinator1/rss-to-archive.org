from __future__ import annotations

import os
import time

import requests
from dotenv import find_dotenv, load_dotenv
from reader import (
    Feed,
    FeedExistsError,
    FeedNotFoundError,
    InvalidFeedURLError,
    Reader,
    make_reader,
)

from rss_to_archive_org.feeds import rss_feeds

load_dotenv(dotenv_path=find_dotenv(), verbose=True)
access_key: str | None = os.environ.get("ARCHIVE_ORG_ACCESS_KEY")
secret_key: str | None = os.environ.get("ARCHIVE_ORG_SECRET_KEY")

if access_key is None or secret_key is None:
    msg = "You need to set ARCHIVE_ORG_ACCESS_KEY and ARCHIVE_ORG_SECRET_KEY in your environment."
    raise ValueError(msg)


def add_entry_to_archive(url: str) -> str:
    """Add an entry to archive.org.

    Args:
        url: The url to add to archive.org.

    Returns:
        The job id for the request.
    """
    headers: dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Authorization": f"LOW {access_key}:{secret_key}",
    }

    data: dict[str, str] = {
        "url": url,
        "capture_outlinks": "0",
        "capture_screenshot": "1",
        "skip_first_archive": "1",
    }

    response: requests.Response = requests.post(
        url="https://web.archive.org/save",
        data=data,
        headers=headers,
        timeout=10,
    )
    data = response.json()
    job_id: str = data["job_id"]
    return job_id


def get_status(job_id: str) -> None:
    """Get the status of the job.

    Args:
        job_id: The job id returned from add_entry_to_archive.
    """
    while True:
        status_url: str = f"http://web.archive.org/save/status/{job_id}"
        try:
            response: requests.Response = requests.get(url=status_url, timeout=10)
        except requests.exceptions.Timeout:
            time.sleep(5)
            continue
        except requests.exceptions.ConnectionError:
            time.sleep(5)
            continue

        data = response.json()
        if data["status"] == "success":
            break
        if data["status"] == "error":
            break

        time.sleep(5)


def disable_removed_feeds(feeds_in_db: list[Feed], reader: Reader) -> None:
    """Disable feeds that are in the database but not in the list of feeds to add.

    Args:
        feeds_in_db: The feeds that are in the database.
        reader: The reader object.
    """
    # Check if a feed are in the database but not in the list of feeds to add
    for feed in feeds_in_db:
        if feed.url not in rss_feeds:
            try:
                # Disable feed updates
                reader.disable_feed_updates(feed)

                # Mark all the existing entries as read
                for entry in reader.get_entries(feed=feed):
                    reader.mark_entry_as_read(entry)
            except FeedNotFoundError:
                continue


def add_new_feeds(feeds_in_db: list[Feed], reader: Reader) -> None:
    """Add new feeds to the database.

    Args:
        feeds_in_db: The feeds that are in the database.
        reader: The reader object.
    """
    feeds_to_add: list[str] = [feed for feed in rss_feeds if feed not in feeds_in_db]
    if feeds_to_add:
        for feed in feeds_to_add:
            try:
                reader.add_feed(feed)
            except FeedExistsError:
                continue
            except InvalidFeedURLError:
                continue

            # Mark all entries as read so we only send new entries to archive.org
            for entry in reader.get_entries(feed=feed):
                reader.mark_entry_as_read(entry)


def main() -> None:
    """Make reader, add feeds, check for new entries and add them to archive.org."""
    # https://reader.readthedocs.io/en/latest/index.html
    reader: Reader = make_reader(url="db.sqlite3")

    # Get the feeds that are in the database
    feeds_in_db = list(reader.get_feeds())

    # Disable feeds that are in the database but not in the list of feeds to add
    disable_removed_feeds(feeds_in_db=feeds_in_db, reader=reader)

    # Get the feeds that are not in feeds_in_db but in rss_feeds and add them to the database
    add_new_feeds(feeds_in_db=feeds_in_db, reader=reader)

    # Check the feeds for new entries
    reader.update_feeds()

    # Get the new entries
    new_entries = list(reader.get_entries(read=False))
    for entry in new_entries:
        if entry.link:
            job_id: str = add_entry_to_archive(url=entry.link)
            reader.mark_entry_as_read(entry)

            get_status(job_id=job_id)

            # Sleep for 30 seconds to avoid rate limiting
            time.sleep(30)


if __name__ == "__main__":
    main()
