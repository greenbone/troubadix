# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG


import asyncio
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Iterator

import httpx

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.patterns import get_xref_pattern
from troubadix.plugin import FilesPlugin, LinterError, LinterResult


class CheckScriptXrefUrlDead(FilesPlugin):
    name = "check_script_xref_url_dead"

    def run(self) -> Iterator[LinterResult]:
        files_urls = defaultdict(list)

        for nasl_file in self.context.nasl_files:
            if not nasl_file.suffix == ".nasl":
                continue

            content = nasl_file.read_text(encoding=CURRENT_ENCODING)
            matches = get_xref_pattern(name="URL", value=r".+?").finditer(
                content
            )
            files_urls[nasl_file] = [match.group("value") for match in matches]

        results = asyncio.run(urls_alive(files_urls))
        for failure in results:
            if not failure:
                continue

            reason = f"{failure.__class__.__name__}"
            if isinstance(failure, httpx.HTTPStatusError):
                reason = f"{reason}, {failure.response.status_code} {failure.response.reason_phrase}"

            if failure:
                yield LinterError(
                    message=f"Dead URL ({reason}): {failure.request.url}",
                    file=nasl_file,
                    plugin=self.name,
                )

    # def check_content(
    #     self,
    #     nasl_file: Path,
    #     file_content: str,
    # ) -> Iterator[LinterResult]:
    #     """
    #     Checks if a URL type script_xref call contains a dead URL
    #     """
    #     if nasl_file.suffix == ".inc":
    #         return

    #     matches = get_xref_pattern(name="URL", value=r".+?").finditer(
    #         file_content
    #     )
    #     urls = [match.group("value") for match in matches]

    #     results = asyncio.run(urls_alive(urls))
    #     for failure in results:
    #         if not failure:
    #             continue

    #         reason = f"{failure.__class__.__name__}"
    #         if isinstance(failure, httpx.HTTPStatusError):
    #             reason = f"{reason}, {failure.response.status_code} {failure.response.reason_phrase}"

    #         if failure:
    #             yield LinterError(
    #                 message=f"Dead URL ({reason}): {failure.request.url}",
    #                 file=nasl_file,
    #                 plugin=self.name,
    #             )


async def urls_alive(files_urls: dict[Path, list[str]]):
    tasks = []
    async with httpx.AsyncClient(http2=True, timeout=10) as client:
        for file, urls in files_urls:
            for url in urls:
                tasks.append(url_alive(client, file, url))

        return await asyncio.gather(*tasks, return_exceptions=True)


async def url_alive(
    client: httpx.AsyncClient, file: Path, url: str
) -> None | httpx.HTTPError:
    # Multiple websites block non-browser-like user agents
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
    }
    response = await client.get(url, headers=headers)
    if response.is_error:
        response.raise_for_status()
