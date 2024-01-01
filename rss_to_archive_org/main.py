from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import requests
import tenacity
from dotenv import find_dotenv, load_dotenv
from loguru import logger
from reader import (
    Feed,
    FeedExistsError,
    FeedNotFoundError,
    InvalidFeedURLError,
    Reader,
    make_reader,
)
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

from rss_to_archive_org.feeds import rss_feeds

load_dotenv(dotenv_path=find_dotenv(), verbose=True)
access_key: str | None = os.environ.get("ARCHIVE_ORG_ACCESS_KEY")
secret_key: str | None = os.environ.get("ARCHIVE_ORG_SECRET_KEY")

if access_key is None or secret_key is None:
    msg = "You need to set ARCHIVE_ORG_ACCESS_KEY and ARCHIVE_ORG_SECRET_KEY in your environment."
    raise ValueError(msg)


@retry(
    wait=wait_fixed(wait=5),
    stop=stop_after_attempt(max_attempt_number=10),
    retry=retry_if_exception_type(exception_types=requests.RequestException),
)
def add_entry_to_archive(url: str) -> str | None:
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

    job_id: str | None = None
    try:
        job_id = data["job_id"]
    except KeyError:
        logger.exception(f"Failed to add {url} to archive.org.")
        # Save URL to file so we can try to add it again later
        with Path.open(Path("no_job_id.txt"), mode="a") as f:
            f.write(f"{url}\n")

    return job_id


@retry(
    wait=wait_fixed(wait=5),
    stop=stop_after_attempt(max_attempt_number=10),
    retry=retry_if_exception_type(exception_types=requests.RequestException),
)
def get_status(job_id: str) -> str:
    """Get the status of the job.

    Args:
        job_id: The job id returned from add_entry_to_archive.

    Returns:
        The status of the job. Either "success" or "error". Only used for testing.
    """
    while True:
        status_url: str = f"http://web.archive.org/save/status/{job_id}"
        response: requests.Response = requests.get(url=status_url, timeout=10)

        data = response.json()
        if data["status"] == "success":
            msg: str = f"Successfully added https://web.archive.org/web/{data['timestamp']}/{data['original_url']} to archive.org."  # noqa: E501
            logger.info(msg)
            return "success"
        if data["status"] == "error":
            logger.error(f"{data['message']}")

            # Save URL to file so we can try to add it again later
            with Path.open(Path("error_urls.txt"), mode="a") as f:
                f.write(f"{data['message']}\n")

            return "error"

        time.sleep(5)
        logger.info("Waiting for archive.org to finish saving the page...")


def disable_removed_feeds(reader: Reader) -> None:
    """Disable feeds that are in the database but not in the list of feeds to add.

    Args:
        feeds_in_db: The feeds that are in the database.
        reader: The reader object.
    """
    feeds_in_db = list(reader.get_feeds(updates_enabled=True))

    # Check if a feed are in the database but not in the list of feeds to add
    for feed in feeds_in_db:
        if feed.url not in rss_feeds:
            try:
                # Disable feed updates
                reader.disable_feed_updates(feed)

                # Mark all the existing entries as read
                for entry in reader.get_entries(feed=feed):
                    reader.mark_entry_as_read(entry)

                logger.info(f"Disabled feed {feed.url}.")
            except FeedNotFoundError:
                logger.exception(f"Feed {feed.url} not found in database.")
                continue


def add_new_feeds(feeds_in_db: list[Feed], reader: Reader) -> None:
    """Add new feeds to the database.

    Args:
        feeds_in_db: The feeds that are in the database.
        reader: The reader object.
    """
    feeds_to_add: list[str] = [feed for feed in rss_feeds if feed not in feeds_in_db]
    if feeds_to_add:
        for feed_url in feeds_to_add:
            try:
                reader.add_feed(feed_url)
            except FeedExistsError:
                continue
            except InvalidFeedURLError:
                logger.exception(f"Feed '{feed_url}' is not a valid url.")
                continue

            # Mark all entries as read so we only send new entries to archive.org
            for entry in reader.get_entries(feed=feed_url):
                reader.mark_entry_as_read(entry)


def main() -> None:
    """Make reader, add feeds, check for new entries and add them to archive.org."""
    # https://reader.readthedocs.io/en/latest/index.html
    reader: Reader = make_reader(url="db.sqlite3")

    # Get the feeds that are in the database
    feeds_in_db = list(reader.get_feeds())

    # Disable feeds that are in the database but not in the list of feeds to add
    disable_removed_feeds(reader=reader)

    # Get the feeds that are not in feeds_in_db but in rss_feeds and add them to the database
    add_new_feeds(feeds_in_db=feeds_in_db, reader=reader)

    # Check the feeds for new entries
    reader.update_feeds()

    # Get the new entries
    new_entries = list(reader.get_entries(read=False))
    if not new_entries:
        logger.info("No new entries found.")
        return

    logger.info(f"Found {len(new_entries)} new entries.")
    for entry in new_entries:
        if entry.link:
            try:
                logger.info(f"Adding {entry.link} to archive.org...")

                job_id: str | None = None
                try:
                    job_id = add_entry_to_archive(url=entry.link)
                except tenacity.RetryError:
                    logger.exception("Failed to add entry to archive.org.")

                reader.mark_entry_as_read(entry)

                # Get the status of the job, either "success" or "error"
                try:
                    if job_id:
                        get_status(job_id=job_id)
                except tenacity.RetryError:
                    logger.exception("Failed to get status from archive.org.")

                logger.info("Sleeping for 11 seconds to avoid rate limiting...")
                time.sleep(11)
            except KeyboardInterrupt:
                logger.info("Exiting...")
                sys.exit(0)


if __name__ == "__main__":
    logger.info("Hello. Starting archiving RSS feeds...")
    logger.info("Press Ctrl+C to exit.")
    main()
    logger.info("Bye.")
