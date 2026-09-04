"""Evidence-based username discovery across public profile pages.

HTTP status codes are only one signal: many services return a branded 200 page
for missing profiles, redirect to login, or challenge automated clients. Each
provider has positive and negative fingerprints, and results include evidence.
Use only for authorized OSINT research.
"""
from __future__ import annotations

import html
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable
from urllib.parse import quote

import requests

DEFAULT_TIMEOUT = 12.0
DEFAULT_WORKERS = 8
MAX_USERNAME_LENGTH = 64
MAX_RESPONSE_BYTES = 2_000_000
HEADERS = {
    "User-Agent": "TraceX/0.4 username-research (authorized OSINT)",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
}


class ResultStatus(str, Enum):
    FOUND = "FOUND"
    LIKELY = "LIKELY"
    NOT_FOUND = "NOT_FOUND"
    BLOCKED = "BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID = "INVALID"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Provider:
    name: str
    url: str
    category: str = "social"
    positive: tuple[str, ...] = ()
    negative: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ("captcha", "cloudflare", "verify you are human")
    not_found_statuses: tuple[int, ...] = (404,)
    headers: tuple[tuple[str, str], ...] = ()
    notes: str = ""

    def target(self, username: str) -> str:
        return self.url.format(username=quote(username, safe=""))


@dataclass
class UsernameResult:
    provider: str
    category: str
    username: str
    url: str
    status: ResultStatus
    confidence: int
    http_status: int | None = None
    final_url: str | None = None
    title: str | None = None
    evidence: list[str] = field(default_factory=list)
    error: str | None = None
    elapsed_ms: float = 0.0
    redirected: bool = False
    content_length: int = 0

    @property
    def found(self) -> bool:
        return self.status in {ResultStatus.FOUND, ResultStatus.LIKELY}

    def as_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider, "category": self.category,
            "username": self.username, "url": self.url,
            "status": self.status.value, "confidence": self.confidence,
            "http_status": self.http_status, "final_url": self.final_url,
            "title": self.title, "evidence": list(self.evidence),
            "error": self.error, "elapsed_ms": self.elapsed_ms,
            "redirected": self.redirected, "content_length": self.content_length,
        }


@dataclass
class UsernameReport:
    username: str
    normalized: str
    started_at: float
    finished_at: float
    results: list[UsernameResult]
    invalid_reason: str | None = None

    @property
    def found(self) -> list[UsernameResult]:
        return [result for result in self.results if result.found]

    @property
    def counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in ResultStatus}
        for result in self.results:
            counts[result.status.value] += 1
        return counts

    @property
    def elapsed_ms(self) -> float:
        return round((self.finished_at - self.started_at) * 1000, 1)

    def as_dict(self) -> dict[str, object]:
        return {
            "username": self.username, "normalized": self.normalized,
            "elapsed_ms": self.elapsed_ms, "counts": self.counts,
            "invalid_reason": self.invalid_reason,
            "results": [result.as_dict() for result in self.results],
        }


def _provider(name: str, url: str, category: str, positive: tuple[str, ...] = (), negative: tuple[str, ...] = ()) -> Provider:
    return Provider(name, url, category, positive, negative)


# Provider rules are data, not scanner branches. This makes adding a site safer.
PROVIDERS: tuple[Provider, ...] = (
    _provider("GitHub", "https://github.com/{username}", "development", ("github", "contributions"), ("not found", "does not exist")),
    _provider("GitLab", "https://gitlab.com/{username}", "development", ("gitlab", "projects"), ("404", "page not found")),
    _provider("Bitbucket", "https://bitbucket.org/{username}/", "development", ("bitbucket", "repositories"), ("does not exist", "not found")),
    _provider("Codeberg", "https://codeberg.org/{username}", "development", ("codeberg", "repositories"), ("page not found", "not found")),
    _provider("SourceForge", "https://sourceforge.net/u/{username}/profile/", "development", ("sourceforge", "profile"), ("not found", "no user")),
    _provider("Hugging Face", "https://huggingface.co/{username}", "development", ("hugging face", "models"), ("not found", "page not found")),
    _provider("Stack Overflow", "https://stackoverflow.com/users/-1/{username}", "development", ("stackoverflow", "reputation"), ("page not found", "does not exist")),
    _provider("Dev.to", "https://dev.to/{username}", "development", ("dev community", "articles"), ("page not found", "not found")),
    _provider("CodePen", "https://codepen.io/{username}", "development", ("codepen", "pens"), ("page not found", "not found")),
    _provider("Replit", "https://replit.com/@{username}", "development", ("replit", "repl"), ("not found", "doesn't exist")),
    _provider("npm", "https://www.npmjs.com/~{username}", "development", ("npm", "packages"), ("not found", "page not found")),
    _provider("PyPI", "https://pypi.org/user/{username}/", "development", ("pypi", "projects"), ("not found", "page not found")),
    _provider("Docker Hub", "https://hub.docker.com/u/{username}", "development", ("docker", "repositories"), ("not found", "page not found")),
    _provider("Kaggle", "https://www.kaggle.com/{username}", "data", ("kaggle", "notebooks"), ("not found", "page not found")),
    _provider("LeetCode", "https://leetcode.com/u/{username}/", "development", ("leetcode", "problems solved"), ("not found", "page not found")),
    _provider("Codewars", "https://www.codewars.com/users/{username}", "development", ("codewars", "honor"), ("not found", "page not found")),
    _provider("Exercism", "https://exercism.org/profiles/{username}", "development", ("exercism", "solutions"), ("not found", "page not found")),
    _provider("HackerRank", "https://www.hackerrank.com/{username}", "development", ("hackerrank", "badges"), ("not found", "page not found")),
    _provider("LinkedIn", "https://www.linkedin.com/in/{username}/", "professional", ("linkedin", "experience"), ("page not found", "not found")),
    _provider("Behance", "https://www.behance.net/{username}", "creative", ("behance", "projects"), ("not found", "page not found")),
    _provider("Dribbble", "https://dribbble.com/{username}", "creative", ("dribbble", "shots"), ("not found", "page not found")),
    _provider("ArtStation", "https://www.artstation.com/{username}", "creative", ("artstation", "portfolio"), ("not found", "page not found")),
    _provider("DeviantArt", "https://www.deviantart.com/{username}", "creative", ("deviantart", "gallery"), ("not found", "page not found")),
    _provider("Flickr", "https://www.flickr.com/people/{username}/", "creative", ("flickr", "photos"), ("not found", "does not exist")),
    _provider("Unsplash", "https://unsplash.com/@{username}", "creative", ("unsplash", "photos"), ("not found", "page not found")),
    _provider("Etsy", "https://www.etsy.com/shop/{username}", "marketplace", ("etsy", "reviews"), ("not found", "page not found")),
    _provider("Redbubble", "https://www.redbubble.com/people/{username}/shop", "marketplace", ("redbubble", "designs"), ("not found", "page not found")),
    _provider("Patreon", "https://www.patreon.com/{username}", "creator", ("patreon", "posts"), ("not found", "page not found")),
    _provider("Ko-fi", "https://ko-fi.com/{username}", "creator", ("ko-fi", "support"), ("not found", "page not found")),
    _provider("Substack", "https://{username}.substack.com", "creator", ("substack", "subscribe"), ("page not found", "doesn't exist")),
    _provider("Medium", "https://medium.com/@{username}", "writing", ("medium", "followers"), ("page not found", "not found")),
    _provider("WordPress", "https://profiles.wordpress.org/{username}/", "writing", ("wordpress", "profile"), ("not found", "page not found")),
    _provider("Tumblr", "https://{username}.tumblr.com", "social", ("tumblr", "posts"), ("not found", "there's nothing here")),
    _provider("Reddit", "https://www.reddit.com/user/{username}/about.json", "social", ("name", "created"), ("page not found", "does not exist")),
    _provider("Mastodon", "https://mastodon.social/@{username}", "social", ("mastodon", "followers"), ("not found", "page not found")),
    _provider("Bluesky", "https://bsky.app/profile/{username}.bsky.social", "social", ("bluesky", "followers"), ("not found", "not found")),
    _provider("Threads", "https://www.threads.net/@{username}", "social", ("threads", "followers"), ("not found", "page isn't available")),
    _provider("Pinterest", "https://www.pinterest.com/{username}/", "social", ("pinterest", "followers"), ("not found", "page not found")),
    _provider("Quora", "https://www.quora.com/profile/{username}", "social", ("quora", "answers"), ("not found", "page not found")),
    _provider("VK", "https://vk.com/{username}", "social", ("vk", "friends"), ("page not found", "profile deleted")),
    _provider("Telegram", "https://t.me/{username}", "messaging", ("telegram", "send message"), ("not found", "if you have telegram")),
    _provider("Keybase", "https://keybase.io/{username}", "security", ("keybase", "proofs"), ("not found", "page not found")),
    _provider("Gravatar", "https://gravatar.com/{username}", "identity", ("gravatar", "profile"), ("not found", "page not found")),
    _provider("Last.fm", "https://www.last.fm/user/{username}", "music", ("last.fm", "scrobbles"), ("not found", "page not found")),
    _provider("SoundCloud", "https://soundcloud.com/{username}", "music", ("soundcloud", "tracks"), ("not found", "page not found")),
    _provider("Bandcamp", "https://bandcamp.com/{username}", "music", ("bandcamp", "music"), ("not found", "page not found")),
    _provider("Spotify", "https://open.spotify.com/user/{username}", "music", ("spotify", "playlist"), ("not found", "page not found")),
    _provider("Twitch", "https://www.twitch.tv/{username}", "streaming", ("twitch", "follow"), ("not found", "page not found")),
    _provider("Vimeo", "https://vimeo.com/{username}", "video", ("vimeo", "videos"), ("not found", "page not found")),
    _provider("Dailymotion", "https://www.dailymotion.com/{username}", "video", ("dailymotion", "videos"), ("not found", "page not found")),
    _provider("Letterboxd", "https://letterboxd.com/{username}/", "media", ("letterboxd", "films"), ("not found", "page not found")),
    _provider("Goodreads", "https://www.goodreads.com/{username}", "media", ("goodreads", "books"), ("not found", "page not found")),
    _provider("MyAnimeList", "https://myanimelist.net/profile/{username}", "media", ("myanimelist", "anime"), ("not found", "page not found")),
    _provider("AniList", "https://anilist.co/user/{username}/", "media", ("anilist", "anime"), ("not found", "page not found")),
    _provider("Steam", "https://steamcommunity.com/id/{username}", "gaming", ("steam community", "games"), ("not found", "page not found")),
    _provider("Chess.com", "https://www.chess.com/member/{username}", "gaming", ("chess.com", "rating"), ("not found", "page not found")),
    _provider("Lichess", "https://lichess.org/@/{username}", "gaming", ("lichess", "games"), ("not found", "page not found")),
    _provider("Roblox", "https://www.roblox.com/user.aspx?username={username}", "gaming", ("roblox", "profile"), ("not found", "page not found")),
    _provider("Minecraft", "https://namemc.com/profile/{username}", "gaming", ("namemc", "minecraft"), ("not found", "page not found")),
    _provider("Speedrun.com", "https://www.speedrun.com/users/{username}", "gaming", ("speedrun.com", "runs"), ("not found", "page not found")),
    _provider("Itch.io", "https://{username}.itch.io", "gaming", ("itch.io", "games"), ("not found", "page not found")),
    _provider("Modrinth", "https://modrinth.com/user/{username}", "gaming", ("modrinth", "projects"), ("not found", "page not found")),
    _provider("Wikimedia", "https://meta.wikimedia.org/wiki/User:{username}", "community", ("user", "wikimedia"), ("does not exist", "not found")),
    _provider("Wikipedia", "https://en.wikipedia.org/wiki/User:{username}", "community", ("user", "wikipedia"), ("does not exist", "redlink")),
    _provider("Archive.org", "https://archive.org/details/@{username}", "community", ("archive.org", "collections"), ("not found",)),
    _provider("Hacker News", "https://news.ycombinator.com/user?id={username}", "community", ("hacker news", "karma"), ("no such user", "not found")),
    _provider("Lobsters", "https://lobste.rs/u/{username}", "community", ("lobsters", "stories"), ("not found", "page not found")),
    _provider("OpenStreetMap", "https://www.openstreetmap.org/user/{username}", "community", ("openstreetmap", "changesets"), ("not found", "page not found")),
    _provider("Strava", "https://www.strava.com/athletes/{username}", "fitness", ("strava", "activities"), ("not found", "page not found")),
    _provider("Rumble", "https://rumble.com/c/{username}", "video", ("rumble", "videos"), ("not found", "page not found")),
    _provider("Odysee", "https://odysee.com/@{username}", "video", ("odysee", "videos"), ("not found", "page not found")),
    _provider("Gitea", "https://gitea.com/{username}", "development", ("gitea", "repositories"), ("not found", "page not found")),
    _provider("Observable", "https://observablehq.com/@{username}", "data", ("observable", "notebooks"), ("not found", "page not found")),
    _provider("ResearchGate", "https://www.researchgate.net/profile/{username}", "professional", ("researchgate", "research"), ("not found", "page not found")),
    _provider("ORCID", "https://orcid.org/{username}", "professional", ("orcid", "researcher"), ("not found", "page not found")),
    _provider("Linktree", "https://linktr.ee/{username}", "identity", ("linktree", "links"), ("not found", "page not found")),
    _provider("Carrd", "https://{username}.carrd.co", "identity", ("carrd", "profile"), ("not found", "page not found")),
)

_cache: dict[tuple[str, str], tuple[float, UsernameResult]] = {}
_cache_lock = threading.Lock()
_CACHE_SECONDS = 300.0


def normalize_username(value: str) -> str:
    """Validate a username without silently changing internal characters."""
    username = value.strip().lstrip("@").strip()
    if not username:
        raise ValueError("A username is required.")
    if len(username) > MAX_USERNAME_LENGTH:
        raise ValueError(f"Username must be {MAX_USERNAME_LENGTH} characters or fewer.")
    if any(character.isspace() for character in username):
        raise ValueError("Username cannot contain spaces.")
    if not re.fullmatch(r"[\w.\-]+", username, flags=re.ASCII):
        raise ValueError("Use letters, numbers, underscores, dots, and hyphens only.")
    return username.lower()


def _clean_text(body: str) -> str:
    body = re.sub(r"<script\b[^>]*>.*?</script>", " ", body, flags=re.I | re.S)
    body = re.sub(r"<style\b[^>]*>.*?</style>", " ", body, flags=re.I | re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    return html.unescape(re.sub(r"\s+", " ", body)).strip().lower()


def _page_title(body: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    if not match:
        return None
    title = html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()
    return title[:180] or None


def _evidence_matches(text: str, markers: Iterable[str], limit: int = 3) -> list[str]:
    evidence: list[str] = []
    for marker in markers:
        position = text.find(marker.lower())
        if position >= 0:
            start = max(0, position - 55)
            end = min(len(text), position + len(marker) + 75)
            evidence.append(re.sub(r"\s+", " ", text[start:end]).strip()[:180])
        if len(evidence) >= limit:
            break
    return evidence


def _classify(provider: Provider, response: requests.Response, text: str) -> tuple[ResultStatus, int, list[str], str | None]:
    """Classify status, redirects, page markers, and positive evidence."""
    if response.status_code == 429:
        return ResultStatus.RATE_LIMITED, 0, [], "service requested rate limiting"
    if response.status_code in {401, 403, 406, 409, 451}:
        return ResultStatus.BLOCKED, 0, [], f"service returned HTTP {response.status_code}"
    if response.status_code in provider.not_found_statuses:
        return ResultStatus.NOT_FOUND, 0, _evidence_matches(text, provider.negative), None
    if response.status_code >= 500:
        return ResultStatus.ERROR, 0, [], f"service returned HTTP {response.status_code}"
    blocked = _evidence_matches(text, provider.blocked)
    if blocked:
        return ResultStatus.BLOCKED, 0, blocked, "challenge or bot protection detected"
    negative = _evidence_matches(text, provider.negative)
    positive = _evidence_matches(text, provider.positive)
    if negative and not positive:
        return ResultStatus.NOT_FOUND, 0, negative, None
    score = 25 if response.status_code == 200 else 0
    if response.url.rstrip("/") != response.request.url.rstrip("/"):
        score -= 10
    if positive:
        score += min(55, len(positive) * 28)
    evidence = positive
    if score >= 70:
        return ResultStatus.FOUND, min(score, 99), evidence, None
    if score >= 35:
        return ResultStatus.LIKELY, score, evidence or ["limited profile evidence"], None
    return ResultStatus.UNKNOWN, max(score, 0), evidence, "not enough profile evidence"


def check_provider(username: str, provider: Provider, session: requests.Session | None = None, timeout: float = DEFAULT_TIMEOUT, retries: int = 1, use_cache: bool = True) -> UsernameResult:
    """Check one provider and return a detailed evidence-backed result."""
    normalized = normalize_username(username)
    url = provider.target(normalized)
    key = (provider.name, normalized)
    if use_cache:
        with _cache_lock:
            cached = _cache.get(key)
            if cached and time.monotonic() - cached[0] < _CACHE_SECONDS:
                return cached[1]
    client = session or requests.Session()
    request_headers = dict(HEADERS)
    request_headers.update(dict(provider.headers))
    started = time.perf_counter()
    last_error = "request failed"
    for attempt in range(max(0, retries) + 1):
        try:
            response = client.get(url, headers=request_headers, timeout=(min(5.0, timeout), timeout), allow_redirects=True, stream=True)
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_content(chunk_size=32768):
                if not chunk:
                    continue
                remaining = MAX_RESPONSE_BYTES - size
                chunks.append(chunk[:remaining])
                size += min(len(chunk), remaining)
                if size >= MAX_RESPONSE_BYTES:
                    break
            body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
            status, confidence, evidence, error = _classify(provider, response, _clean_text(body))
            result = UsernameResult(provider.name, provider.category, normalized, url, status, confidence, response.status_code, response.url, _page_title(body), evidence, error, round((time.perf_counter() - started) * 1000, 1), bool(response.history), size)
            if use_cache and status not in {ResultStatus.RATE_LIMITED, ResultStatus.ERROR}:
                with _cache_lock:
                    _cache[key] = (time.monotonic(), result)
            return result
        except requests.Timeout:
            last_error = "request timed out"
        except requests.ConnectionError:
            last_error = "connection failed"
        except requests.RequestException as error:
            last_error = type(error).__name__
        if attempt < retries:
            time.sleep(0.25 * (attempt + 1))
    return UsernameResult(provider.name, provider.category, normalized, url, ResultStatus.ERROR, 0, error=last_error, elapsed_ms=round((time.perf_counter() - started) * 1000, 1))


def scan_username(username: str, providers: Iterable[Provider] = PROVIDERS, timeout: float = DEFAULT_TIMEOUT, workers: int = DEFAULT_WORKERS, retries: int = 1, use_cache: bool = True) -> UsernameReport:
    """Scan providers concurrently and preserve catalog order in the report."""
    started = time.perf_counter()
    try:
        normalized = normalize_username(username)
    except ValueError as error:
        return UsernameReport(username, "", started, time.perf_counter(), [], str(error))
    selected = tuple(providers)
    results: list[UsernameResult | None] = [None] * len(selected)
    worker_count = max(1, min(int(workers), len(selected) or 1))
    with requests.Session() as session, ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(check_provider, normalized, provider, session, timeout, retries, use_cache): index for index, provider in enumerate(selected)}
        for future in as_completed(future_map):
            index = future_map[future]
            provider = selected[index]
            try:
                results[index] = future.result()
            except Exception as error:
                results[index] = UsernameResult(provider.name, provider.category, normalized, provider.target(normalized), ResultStatus.ERROR, 0, error=f"provider implementation error: {type(error).__name__}")
    return UsernameReport(username, normalized, started, time.perf_counter(), [result for result in results if result])


def github_username_lookup(username: str) -> str:
    """Backward-compatible GitHub helper for existing callers."""
    return check_provider(username, PROVIDERS[0]).status.value


def providers_by_category(category: str) -> tuple[Provider, ...]:
    """Return providers in one category for focused scans."""
    wanted = category.strip().lower()
    return tuple(provider for provider in PROVIDERS if provider.category == wanted)


def clear_cache() -> None:
    """Clear cached provider observations."""
    with _cache_lock:
        _cache.clear()


def report_json(report: UsernameReport, indent: int = 2) -> str:
    """Serialize a report for automation or later review."""
    return json.dumps(report.as_dict(), indent=indent, ensure_ascii=False)


def report_csv_rows(report: UsernameReport) -> list[dict[str, object]]:
    """Return flat rows suitable for CSV, spreadsheets, or a data pipeline."""
    return [
        {
            "username": report.normalized,
            "provider": result.provider,
            "category": result.category,
            "status": result.status.value,
            "confidence": result.confidence,
            "http_status": result.http_status,
            "url": result.url,
            "final_url": result.final_url or "",
            "title": result.title or "",
            "evidence": " | ".join(result.evidence),
            "error": result.error or "",
            "elapsed_ms": result.elapsed_ms,
        }
        for result in report.results
    ]
