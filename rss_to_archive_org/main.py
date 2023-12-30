import os
import time

import requests
from dotenv import find_dotenv, load_dotenv
from reader import (
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
    print(f"Capture started, job id: {job_id}")
    return job_id


def get_status(job_id: str) -> None:
    while True:
        status_url: str = f"http://web.archive.org/save/status/{job_id}"
        try:
            response: requests.Response = requests.get(url=status_url, timeout=10)
        except requests.exceptions.Timeout as e:
            print(f"Timeout, trying again in 5 seconds.\n{e}")
            time.sleep(5)
            continue
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error, aborting.\n{e}")
            time.sleep(5)
            continue

        data = response.json()
        if data["status"] == "success":
            print(
                f"Capture complete: https://web.archive.org/web/{data['timestamp']}/{data['original_url']}"
            )
            break
        elif data["status"] == "error":
            print(f"Error: {data['message']}")
            break

        time.sleep(5)
        print("Checking status...")


def main() -> None:
    # https://reader.readthedocs.io/en/latest/index.html
    reader: Reader = make_reader(url="db.sqlite3")

    # Get the feeds that are in the database
    feeds_in_db = list(reader.get_feeds())
    print(f"We have {len(feeds_in_db)} feeds in the database.")

    # Check if a feed are in the database but not in the list of feeds to add
    for feed in feeds_in_db:
        if feed.url not in rss_feeds:
            print(f"'{feed.url}' not in feeds.py, disabling feed updates for it.")
            try:
                # Disable feed updates
                reader.disable_feed_updates(feed)

                # Mark all the existing entries as read
                for entry in reader.get_entries(feed=feed):
                    reader.mark_entry_as_read(entry)

            except FeedNotFoundError as e:
                print(f"Feed '{feed.url}' not found in database.\n{e}")
                continue

    # Get the feeds that are not in feeds_in_db but in rss_feeds and add them to the database
    feeds_to_add: list[str] = [feed for feed in rss_feeds if feed not in feeds_in_db]
    if feeds_to_add:
        print(f"We have {len(feeds_to_add)} feeds to add to the database.")
        for feed in feeds_to_add:
            try:
                reader.add_feed(feed)
            except FeedExistsError:
                print(f"Feed {feed} already exists.")
                continue
            except InvalidFeedURLError as e:
                print(f"Feed '{feed}' is not a valid URL.\n{e}")
                continue

            # Mark all entries as read so we only send new entries to archive.org
            for entry in reader.get_entries(feed=feed):
                reader.mark_entry_as_read(entry)

    # Check the feeds for new entries
    reader.update_feeds()

    # Get the new entries
    new_entries = list(reader.get_entries(read=False))
    print(f"We have {len(new_entries)} entries that have not been archived.")
    for entry in new_entries:
        print(f"New entry: {entry.title} - {entry.link}")

        if entry.link:
            job_id: str = add_entry_to_archive(url=entry.link)
            reader.mark_entry_as_read(entry)

            get_status(job_id=job_id)

            # Sleep for 30 seconds to avoid rate limiting
            time.sleep(30)


if __name__ == "__main__":
    main()
