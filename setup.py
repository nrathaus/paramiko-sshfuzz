# This fork is consumed with `pip install git+https://...`, where a static
# version means pip sees "Requirement already satisfied" and never picks up new
# commits. So the version is derived from the date of the last commit instead:
# Y.M.D, with Y counted from EPOCH_YEAR (2026 -> 6, August -> 8).
#
# Granularity is one version per day by choice: a second commit on the same day
# reuses that day's version, so pip will not consider it an upgrade. Use
# `pip install --force-reinstall` to pull a same-day change.
#
# The date comes from the commit rather than the build clock, so building the
# same commit twice yields the same version. Ordering is monotonic - 6.8.5 <
# 6.8.6 < 6.9.1 < 7.1.1 - and Y is an offset from EPOCH_YEAR rather than the
# year's last digit so it keeps climbing past 2029.

import datetime
import os
import subprocess

from setuptools import setup

EPOCH_YEAR = 2020

HERE = os.path.dirname(os.path.abspath(__file__))


def _version():
    try:
        # %cs is the committer date as YYYY-MM-DD.
        day = subprocess.run(
            ("git", "log", "-1", "--format=%cs"),
            cwd=HERE,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        year, month, date = (int(part) for part in day.split("-"))
    except Exception:
        # No git, no repo, or an sdist build: fall back to the build date.
        # Still monotonic, just not reproducible for a given commit.
        today = datetime.date.today()
        year, month, date = today.year, today.month, today.day

    return "{}.{}.{}".format(year - EPOCH_YEAR, month, date)


setup(version=_version())
