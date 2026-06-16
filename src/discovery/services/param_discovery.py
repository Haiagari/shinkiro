"""Descubrimiento de parámetros HTTP para OzyRecon."""

import json
import time
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

import requests

from src.utils import log

NOISE_PARAMS = frozenset({
    "_", "_t", "nonce", "_dc", "callback", "rand", "rnd", "timestamp", "ts",
    "_rnd", "_rand", "_timestamp", "t", "nocache", "_cache", "cachebreaker",
})

COMMON_PARAMS = [
    "page", "pages", "page_number", "p", "page_no", "pageindex", "page_index",
    "limit", "limits", "per_page", "perpage", "items_per_page", "max_results",
    "max", "count", "size", "page_size", "pagesize", "offset", "start",
    "start_index", "from", "to", "skip", "take", "rows", "rowcount", "num",
    "num_results", "page_num",
    "sort", "sort_by", "sortby", "sort_order", "sortorder", "order", "order_by",
    "orderby", "ordering", "dir", "direction", "sort_dir", "sortdir",
    "sort_field", "sortfield", "order_dir", "orderdir", "sort_direction",
    "sortdirection", "oder", "sorting", "sorted", "sort_column", "sortcolumn",
    "sortkey", "sort_key", "order_column", "ordercolumn", "orderkey", "order_key",
    "filter", "filters", "filter_by", "filterby", "q", "query", "search",
    "search_query", "searchquery", "keyword", "keywords", "term", "terms",
    "phrase", "match", "text", "where", "condition", "conditions", "having",
    "id", "ids", "uid", "uuid", "guid", "sid", "pid", "cid", "lid", "i_d",
    "user_id", "userid", "user", "username", "login", "account_id", "accountid",
    "customer_id", "customerid", "client_id", "clientid", "profile_id",
    "profileid", "member_id", "memberid", "group_id", "groupid", "role_id",
    "roleid", "obj_id", "object_id", "objectid", "entity_id", "entityid",
    "token", "access_token", "accesstoken", "refresh_token", "refreshtoken",
    "auth_token", "authtoken", "bearer", "jwt", "api_key", "apikey", "api-key",
    "apiKey", "key", "secret", "client_secret", "clientsecret", "app_secret",
    "appsecret", "app_key", "appkey", "signature", "sig", "hash", "checksum",
    "hmac", "scope", "grant_type", "granttype", "response_type", "responsetype",
    "format", "fmt", "output", "out", "response_format", "responseformat",
    "content_type", "contenttype", "accept", "jsonp", "ext", "extension",
    "filetype", "file_type", "mime_type", "mimetype",
    "type", "types", "category", "categories", "cat", "tag", "tags", "label",
    "labels", "class", "classification", "kind", "group", "section", "subsection",
    "view", "mode", "display", "layout", "template", "theme", "style", "skin",
    "color", "lang", "language", "locale", "tz", "timezone", "date_format",
    "dateformat",
    "tab", "module", "controller", "action", "method", "route", "r", "redirect",
    "return", "return_url", "returnurl", "next", "previous", "prev", "back",
    "referer", "referrer", "source", "origin",
    "title", "name", "slug", "description", "body", "content", "summary",
    "excerpt", "note", "notes", "comment", "comments", "message", "msg",
    "subject", "headline", "caption", "alt", "alt_text",
    "meta", "metadata", "data", "info", "extra", "options", "settings",
    "config", "configuration", "params", "parameters", "args", "arguments",
    "op", "operation", "cmd", "command", "do", "exec", "execute", "run",
    "process", "create", "update", "delete", "remove", "add", "edit", "save",
    "submit", "cancel", "publish", "archive", "restore",
    "status", "state", "active", "enabled", "disabled", "visible", "hidden",
    "archived", "published", "draft", "pending", "approved", "rejected",
    "flag", "flags", "enable", "disable", "show", "hide", "expand", "collapse",
    "include", "exclude", "with", "without", "has", "is", "not", "only",
    "debug", "verbose", "trace", "log", "logging", "profile", "benchmark",
    "test", "dry_run", "dryrun", "preview", "validate", "sandbox",
    "date", "dates", "start_date", "startdate", "end_date", "enddate", "since",
    "before", "after", "from_date", "fromdate", "to_date", "todate", "range",
    "interval", "period", "schedule", "frequency",
    "parent", "parent_id", "parentid", "child", "children", "related", "rel",
    "relation", "link", "linked", "associated",
    "file", "files", "upload", "uploaded", "image", "img", "picture", "photo",
    "avatar", "icon", "logo", "attachment", "attachments", "media", "video",
    "audio", "document", "doc", "pdf", "csv", "export", "import", "download",
    "url", "uri", "href", "src", "source_url", "sourceurl", "target", "domain",
    "host", "hostname", "port", "path", "endpoint", "service", "base_url",
    "password", "pass", "pwd", "passwd", "email", "mail", "phone",
    "phone_number", "phonenumber", "mobile", "zip", "zipcode", "postal",
    "country", "region",
    "provider", "platform", "channel", "medium", "campaign", "source_id",
    "sourceid", "integration", "connector", "webhook", "hook",
    "fields", "select", "expand", "embed", "depth", "level", "version",
    "api_version", "apiversion", "rev", "revision", "branch",
    "error", "errors", "warning", "warnings", "code", "codes", "reason",
    "cause", "help", "hint", "tip",
    "city", "state_province", "state", "zipcode", "postal_code", "postalcode",
    "address", "location", "lat", "lon", "lng", "geo", "coordinates", "coords",
    "longitude", "latitude",
    "price", "prices", "cost", "amount", "total", "subtotal", "tax", "shipping",
    "discount", "coupon", "promo", "promocode", "currency", "payment",
    "checkout", "cart", "order_id", "orderid", "transaction", "txn", "invoice",
    "share", "like", "vote", "rating", "stars", "score", "review", "feedback",
    "subscribe", "unsubscribe", "follow", "friend", "invite",
    "ip", "user_agent", "useragent", "ua", "browser", "device", "screen",
    "resolution", "viewport", "platform", "os",
    "item", "element", "entry", "record", "row", "idx", "ix", "val", "value",
    "values", "prop", "props", "attribute", "attr", "attrs", "properties",
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
    "o", "r", "s", "u", "v", "w", "x", "y", "z",
    "_method", "_token", "_csrf", "csrf_token", "csrftoken",
    "csrfmiddlewaretoken", "__viewstate", "__eventtarget", "__eventargument",
    "form_id", "formid", "authenticity_token",
    "dir", "directory", "folder", "root", "base", "relative", "absolute",
    "upload_dir", "uploaddir", "download_path",
    "encoding", "charset", "compress", "compression", "gzip", "deflate",
    "encode", "decode", "escape", "unescape",
    "cursor", "after", "before", "first", "last", "since_id", "sinceid",
    "max_id", "maxid", "min_id", "minid", "high", "low", "ceil", "floor",
    "aggregate", "aggr", "group_by", "groupby", "sum", "avg", "average",
    "min", "max", "distinct", "unique", "count_distinct", "countdistinct",
    "event", "events", "topic", "topics", "subscription", "delivery", "retry",
    "attempt", "max_retries", "maxretries",
    "throttle", "burst", "concurrency", "rate_limit", "ratelimit",
    "fuzzy", "wildcard", "regex", "pattern", "glob", "similar", "suggest",
    "autocomplete", "spell",
    "feature", "experiment", "ab_test", "abtest", "variant", "bucket",
    "rollout", "percentage", "sample", "sampling",
    "any", "all", "in", "not_in", "notin", "gt", "gte", "lt", "lte", "eq",
    "ne", "like", "ilike", "contains", "startswith", "endswith",
    "accept_language", "acceptlanguage", "x_requested_with", "xrequestedwith",
    "purpose", "intent", "context", "environment", "env", "stage", "slot",
    "instance", "tenant", "schema", "namespace", "ns", "realm", "zone",
    "cluster", "shard", "partition", "segment", "slice",
    "session", "session_id", "sessionid", "phpsessid", "jsessionid",
    "aspsessionid", "cfid", "cftoken", "sess",
    "request_id", "requestid", "trace_id", "traceid", "span_id", "spanid",
    "correlation_id", "correlationid", "transaction_id", "transactionid",
    "currency_code", "currencycode", "language_code", "languagecode",
    "country_code", "countrycode", "timezone_offset", "timezoneoffset",
    "hl", "ui_locales", "ui_locale",
    "parameter", "option", "setting", "preference", "prefs", "custom",
    "additional", "supplement", "aux", "auxiliary",
    "line", "lines", "buffer", "chunk", "batch", "page_token", "next_token",
    "continuation_token", "resume", "resume_token",
    "exclusive_start_key", "max_keys", "delimiter", "prefix",
    "fields[]", "include[]", "sort[]", "filter[]",
    "$top", "$skip", "$filter", "$orderby", "$select", "$expand", "$count",
    "$search", "$format", "$inlinecount", "$skiptoken",
    "query", "variables", "operationName", "persistedQuery",
    "f_id", "f_user_id", "f_page", "f_limit", "f_offset", "f_search", "f_q",
    "f_sort", "f_order", "f_filter", "f_category", "f_type", "f_status",
    "id_filter", "name_filter", "title_filter", "type_filter",
    "category_filter", "status_filter", "date_filter", "search_filter",
    "sort_param", "order_param", "page_param", "limit_param", "offset_param",
    "items_count", "itemscount", "total_count", "totalcount", "total_items",
    "totalitems", "records_per_page", "recordsperpage",
    "results_per_page", "resultsperpage",
]

if len(COMMON_PARAMS) < 500:
    COMMON_PARAMS += [f"p{i}" for i in range(500 - len(COMMON_PARAMS))]


class ParamDiscoverer:
    """Descubre parámetros HTTP válidos para una URL probando una wordlist."""

    def __init__(
        self,
        delay: float = 0.0,
        timeout: int = 10,
        headers: Optional[dict[str, str]] = None,
        diff_threshold: int = 0,
        noise_params: Optional[set[str]] = None,
    ):
        self.delay = delay
        self.timeout = timeout
        self.diff_threshold = diff_threshold
        self.noise = set(noise_params) if noise_params else set(NOISE_PARAMS)
        self.headers = headers or {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/124.0.0.0"
            ),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
        }
        self._baseline: Optional[dict] = None

    def baseline_request(self, url: str, method: str = "GET") -> dict:
        """Establece la línea base de comparación."""
        resp = requests.request(method, url, headers=self.headers, timeout=self.timeout)
        self._baseline = {
            "status": resp.status_code,
            "length": len(resp.content),
            "body": resp.text,
            "is_json": _is_json_response(resp),
            "json_body": _safe_parse_json(resp),
        }
        return dict(self._baseline)

    def discover(self, base_url: str, params: Optional[list[str]] = None) -> list[dict]:
        """Descubre parámetros válidos probando contra base_url."""
        clean_url = _strip_query(base_url)
        if self._baseline is None:
            self.baseline_request(clean_url)

        wordlist = params or COMMON_PARAMS
        findings: list[dict] = []

        for param in wordlist:
            if param in self.noise:
                continue

            result = self._test_param(clean_url, param)
            if result:
                findings.extend(result)

        return findings

    def _test_param(self, base_url: str, param: str) -> Optional[list[dict]]:
        """Prueba un parámetro individual vía GET y POST."""
        entries: list[dict] = []

        for method in ("GET", "POST"):
            try:
                resp = self._do_request(method, base_url, param)
                effect = self._classify_effect(method, param, resp)
                if effect:
                    entry: dict[str, Any] = {
                        "param": param,
                        "type": method,
                        "effect": effect,
                    }
                    if resp["is_json"]:
                        entry["json_seen"] = True
                    entries.append(entry)
            except requests.RequestException:
                continue

        if self.delay > 0:
            time.sleep(self.delay)

        return entries or None

    def _do_request(self, method: str, base_url: str, param: str) -> dict:
        """Ejecuta request con el parámetro y devuelve métricas."""
        if method == "GET":
            sep = "&" if "?" in base_url else "?"
            url = f"{base_url}{sep}{param}=test"
            resp = requests.get(url, headers=self.headers, timeout=self.timeout)
        else:
            resp = requests.post(
                base_url,
                headers={**self.headers, "Content-Type": "application/x-www-form-urlencoded"},
                data={param: "test"},
                timeout=self.timeout,
            )

        return {
            "status": resp.status_code,
            "length": len(resp.content),
            "body": resp.text,
            "is_json": _is_json_response(resp),
            "json_body": _safe_parse_json(resp),
        }

    def _classify_effect(self, method: str, param: str, response: dict) -> Optional[str]:
        """Clasifica el efecto del parámetro contra la baseline."""
        b = self._baseline
        if b is None:
            return None

        is_reflective = _param_reflected(param, response, method)
        if is_reflective:
            return "reflective"

        if abs(response["length"] - b["length"]) > self.diff_threshold:
            return "functional"

        if response["status"] != b["status"]:
            return "stateless"

        return None


def _is_json_response(resp: requests.Response) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return "json" in ct or ct.startswith("application/")


def _safe_parse_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except (json.JSONDecodeError, ValueError):
        return None


def _param_reflected(param: str, response: dict, method: str) -> bool:
    """Determina si el parámetro aparece reflejado en la respuesta."""
    if response["is_json"] and response["json_body"]:
        return _key_in_nested_json(response["json_body"], param)

    body = response["body"].lower()
    return param.lower() in body and "test" in body


def _key_in_nested_json(data: Any, target: str) -> bool:
    """Busca target como key en JSON anidado."""
    if isinstance(data, dict):
        for key, val in data.items():
            if key == target:
                return True
            if isinstance(val, (dict, list)):
                if _key_in_nested_json(val, target):
                    return True
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                if _key_in_nested_json(item, target):
                    return True
    return False


def _strip_query(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=""))
