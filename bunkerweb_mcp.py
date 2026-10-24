#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=1.12"]
# ///
"""
Serveur MCP (stdio) pour piloter une instance BunkerWeb via son API (>= 1.6).

Dépendance unique : le SDK `mcp` (v1 ou v2). Le HTTP passe par la stdlib,
donc rien d'autre à installer.

Configuration par variables d'environnement :

  BUNKERWEB_API_URL            URL de l'API (défaut : http://127.0.0.1:8888)
  BUNKERWEB_API_TOKEN          Jeton « override » (API_TOKEN côté BunkerWeb) — accès admin complet
  BUNKERWEB_API_TOKEN_FILE     ... ou chemin d'un fichier contenant ce jeton
  BUNKERWEB_API_USERNAME       Utilisateur API (API_USERNAME ou utilisateur ACL)
  BUNKERWEB_API_PASSWORD       Mot de passe associé
  BUNKERWEB_API_PASSWORD_FILE  ... ou chemin d'un fichier contenant le mot de passe
  BUNKERWEB_ACCESS_LEVEL       read (défaut) | operate | admin — quels outils sont exposés
  BUNKERWEB_SHOW_SECRETS       true pour ne PAS masquer mots de passe/clés dans les réponses (défaut : false)
  BUNKERWEB_MAX_CHARS          Taille max d'une réponse renvoyée au modèle (défaut : 25000)
  BUNKERWEB_TIMEOUT            Timeout HTTP en secondes (défaut : 30)
  BUNKERWEB_VERIFY_TLS         false pour accepter un certificat auto-signé si l'URL est en https (défaut : true)
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Literal, Optional

try:  # SDK mcp 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # SDK mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]
from mcp.types import ToolAnnotations

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_secret(name: str) -> str:
    """Lit VAR, sinon le contenu du fichier VAR_FILE."""
    value = _env(name)
    if value:
        return value
    path = _env(f"{name}_FILE")
    if path:
        with open(os.path.expanduser(path), encoding="utf-8") as fh:
            return fh.read().strip()
    return ""


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


API_URL = _env("BUNKERWEB_API_URL", "http://127.0.0.1:8888").rstrip("/")
API_TOKEN = _env_secret("BUNKERWEB_API_TOKEN")
API_USERNAME = _env("BUNKERWEB_API_USERNAME")
API_PASSWORD = _env_secret("BUNKERWEB_API_PASSWORD")
SHOW_SECRETS = _env_bool("BUNKERWEB_SHOW_SECRETS", False)
VERIFY_TLS = _env_bool("BUNKERWEB_VERIFY_TLS", True)
MAX_CHARS = int(_env("BUNKERWEB_MAX_CHARS", "25000") or 25000)
TIMEOUT = float(_env("BUNKERWEB_TIMEOUT", "30") or 30)

_LEVELS = {"read": 0, "operate": 1, "admin": 2}
ACCESS_LEVEL = _env("BUNKERWEB_ACCESS_LEVEL", "read").lower()
if ACCESS_LEVEL not in _LEVELS:
    print(f"[bunkerweb-mcp] BUNKERWEB_ACCESS_LEVEL invalide ({ACCESS_LEVEL!r}), repli sur 'read'", file=sys.stderr)
    ACCESS_LEVEL = "read"

# --------------------------------------------------------------------------- #
# Client HTTP
# --------------------------------------------------------------------------- #


class BunkerWebError(Exception):
    pass


class BunkerWebClient:
    """Client minimal de l'API BunkerWeb, avec gestion du jeton Biscuit."""

    def __init__(self) -> None:
        self._biscuit: Optional[str] = None
        self._lock = threading.Lock()
        self._ssl = None
        if API_URL.startswith("https://") and not VERIFY_TLS:
            self._ssl = ssl.create_default_context()
            self._ssl.check_hostname = False
            self._ssl.verify_mode = ssl.CERT_NONE

    # -- bas niveau -------------------------------------------------------- #
    def _raw(self, method: str, path: str, *, query: Optional[dict] = None, body: Any = None,
             headers: Optional[dict] = None) -> tuple[int, Any]:
        url = API_URL + path
        if query:
            clean = {k: v for k, v in query.items() if v is not None}
            for k, v in clean.items():
                if isinstance(v, bool):
                    clean[k] = "true" if v else "false"
            if clean:
                url += "?" + urllib.parse.urlencode(clean)
        data = None
        hdrs = {"Accept": "application/json", "User-Agent": f"bunkerweb-mcp/{__version__}"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self._ssl) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        except urllib.error.URLError as exc:
            raise BunkerWebError(
                f"API injoignable sur {API_URL} ({exc.reason}). Le tunnel SSH est-il ouvert ?"
            ) from exc
        text = raw.decode("utf-8", errors="replace")
        try:
            payload: Any = json.loads(text) if text else None
        except json.JSONDecodeError:
            payload = text
        return status, payload

    # -- authentification -------------------------------------------------- #
    def _basic(self) -> str:
        return "Basic " + base64.b64encode(f"{API_USERNAME}:{API_PASSWORD}".encode()).decode()

    def _login(self) -> None:
        """Obtient un jeton Biscuit via POST /auth (identifiants en Basic)."""
        status, payload = self._raw("POST", "/auth", headers={"Authorization": self._basic()})
        if status == 200 and isinstance(payload, dict) and payload.get("token"):
            self._biscuit = payload["token"]
            return
        # Repli : un admin peut appeler les routes directement en Basic.
        self._biscuit = None
        if status in (401, 403):
            raise BunkerWebError(f"Authentification refusée par /auth (HTTP {status}) : {payload}")

    def _auth_header(self, force_login: bool = False) -> dict:
        if API_TOKEN:
            return {"Authorization": f"Bearer {API_TOKEN}"}
        if API_USERNAME and API_PASSWORD:
            with self._lock:
                if force_login or self._biscuit is None:
                    self._login()
                if self._biscuit:
                    return {"Authorization": f"Bearer {self._biscuit}"}
                return {"Authorization": self._basic()}
        raise BunkerWebError(
            "Aucun identifiant configuré : définir BUNKERWEB_API_TOKEN ou BUNKERWEB_API_USERNAME/BUNKERWEB_API_PASSWORD."
        )

    # -- appel authentifié ------------------------------------------------- #
    def request(self, method: str, path: str, *, query: Optional[dict] = None, body: Any = None,
                auth: bool = True) -> Any:
        headers = self._auth_header() if auth else {}
        status, payload = self._raw(method, path, query=query, body=body, headers=headers)
        if status == 401 and auth and not API_TOKEN and API_USERNAME:
            # Biscuit expiré (TTL par défaut 3600 s) : on se reconnecte une fois.
            headers = self._auth_header(force_login=True)
            status, payload = self._raw(method, path, query=query, body=body, headers=headers)
        if status >= 400:
            msg = payload.get("message") if isinstance(payload, dict) else payload
            hint = ""
            if status == 403:
                hint = " (IP hors API_WHITELIST_IPS ou permission ACL manquante)"
            elif status == 429:
                hint = " (rate limit de l'API atteint, réessayer dans une minute)"
            raise BunkerWebError(f"HTTP {status} sur {method.upper()} {path}{hint} : {msg}")
        return payload


client = BunkerWebClient()

# --------------------------------------------------------------------------- #
# Mise en forme des réponses
# --------------------------------------------------------------------------- #

_SECRET_RX = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE|_KEY$|^KEY$|API_KEY|APIKEY|CREDENTIAL|DATABASE_URI)", re.I)
_MASK = "***masqué***"


def _mask(obj: Any) -> Any:
    if SHOW_SECRETS:
        return obj
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if isinstance(key, str) and _SECRET_RX.search(key):
                if isinstance(value, dict) and "value" in value:
                    out[key] = {**value, "value": _MASK if value.get("value") else value.get("value")}
                elif isinstance(value, (str, int, float)) and value not in ("", None):
                    out[key] = _MASK
                else:
                    out[key] = _mask(value)
            else:
                out[key] = _mask(value)
        # format {"setting": "X_PASSWORD", "value": "..."}
        name = obj.get("setting") or obj.get("name") or obj.get("key")
        if isinstance(name, str) and _SECRET_RX.search(name) and isinstance(obj.get("value"), str) and obj.get("value"):
            out["value"] = _MASK
        return out
    if isinstance(obj, list):
        return [_mask(v) for v in obj]
    return obj


def _render(payload: Any, mask: bool = True) -> str:
    if mask:
        payload = _mask(payload)
    # JSON compact : ~2x moins de caractères que indent=2, et aussi lisible pour un modèle
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + (
            f"\n\n[... réponse tronquée à {MAX_CHARS} caractères sur {len(text)} — "
            "affiner la requête (filtres, full=false) ou augmenter BUNKERWEB_MAX_CHARS]"
        )
    return text


def _call(method: str, path: str, *, query: Optional[dict] = None, body: Any = None,
          auth: bool = True, mask: bool = True) -> str:
    try:
        return _render(client.request(method, path, query=query, body=body, auth=auth), mask=mask)
    except BunkerWebError as exc:
        return f"ERREUR : {exc}"


def _seg(value: str) -> str:
    """Encode un segment de chemin (nom de service, hostname…)."""
    value = (value or "").strip()
    if not value or value in (".", "..") or "/" in value:
        raise BunkerWebError(f"Identifiant invalide : {value!r}")
    return urllib.parse.quote(value, safe="")


def _safe(fn):
    """Transforme les BunkerWebError levées avant l'appel HTTP en message d'erreur."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except BunkerWebError as exc:
            return f"ERREUR : {exc}"

    return wrapper


# --------------------------------------------------------------------------- #
# Serveur MCP
# --------------------------------------------------------------------------- #

INSTRUCTIONS = f"""Outils pour piloter un WAF BunkerWeb via son API (niveau d'accès : {ACCESS_LEVEL}).
- Commencer par bw_health pour vérifier la connexion.
- Les écritures (services, configs, réglages globaux) sont stockées en base puis appliquées
  par le scheduler ; appeler bw_reload_instances (test=true par défaut) si un rechargement est nécessaire.
- Les configs personnalisées, variables de service et réglages globaux sont injectés tels quels
  dans NGINX/Lua : relire attentivement tout contenu avant de l'écrire et demander confirmation
  à l'utilisateur avant toute écriture ou suppression.
- Les valeurs sensibles (mots de passe, clés, jetons) sont masquées dans les réponses."""

mcp = _Server("bunkerweb", instructions=INSTRUCTIONS)

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)


def tool(level: str, annotations: ToolAnnotations):
    """Enregistre l'outil seulement si BUNKERWEB_ACCESS_LEVEL le permet."""

    def decorator(fn):
        if _LEVELS[ACCESS_LEVEL] >= _LEVELS[level]:
            mcp.tool(annotations=annotations)(_safe(fn))
        return fn

    return decorator


# ============================== LECTURE ===================================== #


@tool("read", RO)
def bw_health() -> str:
    """Vérifie que l'API BunkerWeb répond (GET /ping et /health) et que l'authentification fonctionne."""
    lines = [f"API : {API_URL} — niveau d'accès MCP : {ACCESS_LEVEL}"]
    for path in ("/ping", "/health"):
        try:
            lines.append(f"{path} → {json.dumps(client.request('GET', path, auth=False), ensure_ascii=False)}")
        except BunkerWebError as exc:
            lines.append(f"{path} → ERREUR : {exc}")
    try:
        instances = client.request("GET", "/instances")
        count = len(instances.get("instances", instances)) if isinstance(instances, (dict, list)) else "?"
        lines.append(f"Authentification OK — {count} instance(s) visible(s)")
    except BunkerWebError as exc:
        lines.append(f"Authentification : ERREUR : {exc}")
    return "\n".join(lines)


@tool("read", RO)
def bw_list_instances() -> str:
    """Liste les instances BunkerWeb enregistrées (hostname, port, méthode, dernière activité)."""
    return _call("GET", "/instances")


@tool("read", RO)
def bw_ping_instances(hostname: Optional[str] = None) -> str:
    """Teste la joignabilité des instances depuis l'API. Sans hostname : toutes les instances."""
    path = f"/instances/{_seg(hostname)}/ping" if hostname else "/instances/ping"
    return _call("GET", path)


@tool("read", RO)
def bw_get_global_settings(full: bool = False, methods: bool = False) -> str:
    """Réglages globaux. Par défaut seulement les valeurs non par défaut ;
    full=true pour tous les réglages (volumineux), methods=true pour savoir d'où vient chaque valeur."""
    return _call("GET", "/global_settings", query={"full": full or None, "methods": methods or None})


@tool("read", RO)
def bw_list_services(with_drafts: bool = True) -> str:
    """Liste les services (sites) configurés, brouillons inclus par défaut."""
    return _call("GET", "/services", query={"with_drafts": with_drafts})


@tool("read", RO)
def bw_get_service(service: str, full: bool = False, methods: bool = False) -> str:
    """Configuration d'un service (identifiant = premier SERVER_NAME, ex. www.example.com).
    full=true pour tous les réglages, methods=true pour la provenance de chaque valeur."""
    return _call("GET", f"/services/{_seg(service)}", query={"full": full or None, "methods": methods or None})


@tool("read", RO)
def bw_list_configs(service: Optional[str] = None, type: Optional[str] = None, with_data: bool = False) -> str:
    """Liste les configurations personnalisées (snippets NGINX/ModSecurity).
    service : 'global' ou un service ; type : http, server_http, default_server_http, modsec,
    modsec_crs, stream, server_stream, crs_plugins_before, crs_plugins_after ; with_data=true inclut le contenu."""
    return _call("GET", "/configs", query={"service": service, "type": type, "with_data": with_data or None})


@tool("read", RO)
def bw_get_config(service: str, type: str, name: str) -> str:
    """Contenu d'une configuration personnalisée. service='global' pour une config globale."""
    return _call("GET", f"/configs/{_seg(service)}/{_seg(type)}/{_seg(name)}", query={"with_data": True}, mask=False)


def _flatten_bans(payload: Any) -> list[dict]:
    """GET /bans renvoie {instance: {"data": [ban, ...]}} ; on aplatit et on dédoublonne."""
    items: list[dict] = []
    if isinstance(payload, dict):
        if isinstance(payload.get("bans"), list):
            items = payload["bans"]
        else:
            for inst, val in payload.items():
                data = val.get("data") if isinstance(val, dict) else val
                if isinstance(data, list):
                    items.extend({**b, "_instance": inst} for b in data if isinstance(b, dict))
    elif isinstance(payload, list):
        items = [b for b in payload if isinstance(b, dict)]
    seen, out = set(), []
    for b in items:
        key = (b.get("ip"), b.get("service"), b.get("ban_scope"))
        if key not in seen:
            seen.add(key)
            out.append(b)
    return out


def _compact_ban(b: dict) -> dict:
    events = b.get("reason_data") if isinstance(b.get("reason_data"), list) else []
    urls = []
    for e in events:
        u = e.get("url") if isinstance(e, dict) else None
        if u and u not in urls:
            urls.append(u)
    country = next((e.get("country") for e in events if isinstance(e, dict) and e.get("country")), b.get("country"))
    return {k: v for k, v in {
        "ip": b.get("ip"),
        "service": b.get("service"),
        "scope": b.get("ban_scope"),
        "reason": b.get("reason"),
        "country": country,
        "permanent": b.get("permanent"),
        "expires_in_s": b.get("exp"),
        "banned_at": b.get("date"),
        "events": len(events) or None,
        "sample_urls": urls[:5] or None,
    }.items() if v is not None}


@tool("read", RO)
def bw_list_bans(service: Optional[str] = None, ip: Optional[str] = None, reason: Optional[str] = None,
                 limit: int = 50, details: bool = False) -> str:
    """Bannissements actifs, avec un résumé (nombre par service, motif, pays) puis la liste.
    Filtres optionnels : service, ip, reason. limit = nombre max de bans listés (défaut 50).
    details=true renvoie les événements bruts qui ont déclenché chaque ban (volumineux : à combiner avec ip=)."""
    from collections import Counter

    try:
        bans = _flatten_bans(client.request("GET", "/bans"))
    except BunkerWebError as exc:
        return f"ERREUR : {exc}"
    total = len(bans)
    if ip:
        bans = [b for b in bans if b.get("ip") == ip]
    if service:
        bans = [b for b in bans if b.get("service") == service]
    if reason:
        bans = [b for b in bans if reason.lower() in str(b.get("reason", "")).lower()]
    rows = [_compact_ban(b) for b in bans]
    summary = {
        "total_actifs": total,
        "apres_filtres": len(rows),
        "par_service": dict(Counter(r.get("service") or "(global)" for r in rows).most_common()),
        "par_motif": dict(Counter(r.get("reason") for r in rows).most_common()),
        "par_pays": dict(Counter(r.get("country") or "?" for r in rows).most_common(10)),
    }
    limit = max(1, min(limit, 500))
    listed = bans[:limit] if details else rows[:limit]
    result = {"resume": summary, "bans": listed}
    if len(rows) > limit:
        result["note"] = f"{len(rows) - limit} ban(s) non listé(s) : utiliser les filtres ou augmenter limit"
    return _render(result)


@tool("read", RO)
def bw_list_plugins(type: Optional[str] = None, plugin_id: Optional[str] = None) -> str:
    """Liste les plugins installés (id, nom, version, type, nombre de réglages).
    type optionnel : all, external, ui, pro, core. plugin_id='xxx' pour le détail complet d'un plugin
    (description et définition de tous ses réglages)."""
    try:
        payload = client.request("GET", "/plugins", query={"type": type})
    except BunkerWebError as exc:
        return f"ERREUR : {exc}"
    plugins = payload.get("plugins", payload) if isinstance(payload, dict) else payload
    if not isinstance(plugins, list):
        return _render(payload)
    if plugin_id:
        match = [p for p in plugins if isinstance(p, dict) and p.get("id") == plugin_id]
        return _render(match[0] if match else f"ERREUR : plugin {plugin_id!r} introuvable")
    rows = [{
        "id": p.get("id"), "name": p.get("name"), "version": p.get("version"),
        "type": p.get("type"), "method": p.get("method"),
        "settings": len(p.get("settings") or {}),
    } for p in plugins if isinstance(p, dict)]
    return _render({"count": len(rows), "plugins": rows})


@tool("read", RO)
def bw_list_jobs(job_name: Optional[str] = None, failed_only: bool = False) -> str:
    """Jobs du scheduler : planning, dernière exécution et nombre d'échecs récents.
    job_name='xxx' pour l'historique complet d'un job ; failed_only=true pour ne voir que les jobs en échec."""
    try:
        payload = client.request("GET", "/jobs")
    except BunkerWebError as exc:
        return f"ERREUR : {exc}"
    jobs = payload.get("jobs", payload) if isinstance(payload, dict) else payload
    if not isinstance(jobs, dict):
        return _render(payload)
    if job_name:
        return _render(jobs.get(job_name, f"ERREUR : job {job_name!r} introuvable"))
    rows = []
    for name, j in jobs.items():
        if not isinstance(j, dict):
            continue
        history = j.get("history") or []
        last = history[0] if history else {}
        fails = sum(1 for h in history if isinstance(h, dict) and h.get("success") is False)
        row = {k: v for k, v in {
            "job": name, "plugin": j.get("plugin_id"), "every": j.get("every"), "reload": j.get("reload"),
            "last_run": last.get("start_date"), "last_success": last.get("success"),
            "failures_in_history": fails or None, "history_size": len(history),
            "cache_files": len(j["cache"]) if isinstance(j.get("cache"), list) else None,
        }.items() if v is not None}
        if not failed_only or last.get("success") is False or fails:
            rows.append(row)
    return _render({"count": len(rows), "jobs": rows})


@tool("read", RO)
def bw_list_cache(service: Optional[str] = None, plugin: Optional[str] = None, job_name: Optional[str] = None) -> str:
    """Liste les fichiers de cache produits par les jobs (certificats, listes de blacklist, etc.), sans leur contenu."""
    return _call("GET", "/cache", query={"service": service, "plugin": plugin, "job_name": job_name})


_PATH_RX = re.compile(r"^/[A-Za-z0-9_\-./~%]*$")


@tool("read", RO)
def bw_api_get(path: str, query: Optional[dict[str, str]] = None) -> str:
    """Requête GET libre sur l'API, pour les routes non couvertes par les autres outils
    (ex. /openapi.json pour découvrir les routes de la version installée)."""
    if not _PATH_RX.match(path) or ".." in path or path.startswith("/auth"):
        return "ERREUR : chemin refusé (doit commencer par /, sans '..', hors /auth)"
    return _call("GET", path, query=query)


# ============================== OPÉRATIONS ================================== #


@tool("operate", WRITE)
def bw_ban_ip(ip: str, duration_seconds: int = 86400, reason: str = "mcp", service: Optional[str] = None) -> str:
    """Bannit une IP (IPv4/IPv6). duration_seconds=0 pour un bannissement permanent.
    service optionnel pour limiter le ban à un seul service."""
    body = [{"ip": ip, "exp": duration_seconds, "reason": reason, "service": service}]
    return _call("POST", "/bans", body=body)


@tool("operate", WRITE)
def bw_unban_ip(ip: str, service: Optional[str] = None) -> str:
    """Lève le bannissement d'une IP, globalement ou pour un service donné.
    (Les bans d'origine CrowdSec exigent une procédure dédiée : utiliser bw_api_request en admin.)"""
    return _call("POST", "/bans/unban", body=[{"ip": ip, "service": service}])


@tool("operate", WRITE)
def bw_reload_instances(hostname: Optional[str] = None, test: bool = True) -> str:
    """Recharge la configuration NGINX. Sans hostname : toutes les instances.
    test=true (défaut) valide la configuration avant rechargement."""
    if hostname:
        return _call("POST", f"/instances/{_seg(hostname)}/reload", query={"test": "yes" if test else "no"})
    return _call("POST", "/instances/reload", query={"test": "yes" if test else "no"})


@tool("operate", WRITE)
def bw_run_jobs(plugin: str, job_name: Optional[str] = None) -> str:
    """Déclenche les jobs d'un plugin (ex. plugin='blacklist' pour rafraîchir les listes,
    'letsencrypt' pour les certificats). job_name optionnel."""
    return _call("POST", "/jobs/run", body={"jobs": [{"plugin": plugin, "name": job_name}]})


# ============================== ADMINISTRATION ============================== #


@tool("admin", WRITE)
def bw_update_global_settings(settings: dict[str, Any]) -> str:
    """Modifie des réglages globaux (dict SETTING → valeur scalaire, ex. {"USE_ANTIBOT": "captcha"}).
    Les clés en lecture seule sont rejetées par l'API. Effet appliqué par le scheduler."""
    if not isinstance(settings, dict) or not settings:
        return "ERREUR : settings doit être un objet non vide"
    return _call("PATCH", "/global_settings", body=settings)


@tool("admin", WRITE)
def bw_create_service(server_name: str, variables: Optional[dict[str, str]] = None, is_draft: bool = True) -> str:
    """Crée un service. server_name : un ou plusieurs noms séparés par des espaces (le premier sert d'ID).
    variables : réglages SANS préfixe (ex. {"USE_REVERSE_PROXY": "yes", "REVERSE_PROXY_HOST": "http://app:8080"}).
    Créé en brouillon par défaut : passer is_draft=false ou utiliser bw_convert_service pour le mettre en ligne."""
    body = {"server_name": server_name, "is_draft": is_draft, "variables": variables or None}
    return _call("POST", "/services", body=body)


@tool("admin", WRITE)
def bw_update_service(service: str, variables: Optional[dict[str, str]] = None,
                      server_name: Optional[str] = None, is_draft: Optional[bool] = None) -> str:
    """Met à jour un service : variables à ajouter/modifier (sans préfixe), renommage via server_name, statut brouillon."""
    body = {k: v for k, v in {"variables": variables, "server_name": server_name, "is_draft": is_draft}.items()
            if v is not None}
    if not body:
        return "ERREUR : rien à modifier"
    return _call("PATCH", f"/services/{_seg(service)}", body=body)


@tool("admin", WRITE)
def bw_convert_service(service: str, convert_to: Literal["online", "draft"]) -> str:
    """Passe un service en ligne ('online') ou en brouillon ('draft')."""
    return _call("POST", f"/services/{_seg(service)}/convert", query={"convert_to": convert_to})


@tool("admin", DESTRUCTIVE)
def bw_delete_service(service: str) -> str:
    """SUPPRIME un service et ses réglages dérivés. Irréversible : confirmer avec l'utilisateur avant."""
    return _call("DELETE", f"/services/{_seg(service)}")


@tool("admin", WRITE)
def bw_create_config(type: str, name: str, data: str, service: str = "global", is_draft: bool = False) -> str:
    """Crée une configuration personnalisée (snippet injecté tel quel dans NGINX/ModSecurity).
    type : http, server_http, default_server_http, modsec, modsec_crs, stream, server_stream,
    crs_plugins_before, crs_plugins_after. name : lettres, chiffres, _ et - uniquement."""
    body = {"service": service, "type": type, "name": name, "data": data, "is_draft": is_draft}
    return _call("POST", "/configs", body=body, mask=False)


@tool("admin", WRITE)
def bw_update_config(service: str, type: str, name: str, data: Optional[str] = None,
                     new_name: Optional[str] = None, new_service: Optional[str] = None,
                     is_draft: Optional[bool] = None) -> str:
    """Modifie le contenu d'une configuration personnalisée gérée par l'API, ou la renomme/déplace."""
    body = {k: v for k, v in {"data": data, "name": new_name, "service": new_service, "is_draft": is_draft}.items()
            if v is not None}
    if not body:
        return "ERREUR : rien à modifier"
    return _call("PATCH", f"/configs/{_seg(service)}/{_seg(type)}/{_seg(name)}", body=body, mask=False)


@tool("admin", DESTRUCTIVE)
def bw_delete_config(service: str, type: str, name: str) -> str:
    """SUPPRIME une configuration personnalisée gérée par l'API. Confirmer avec l'utilisateur avant."""
    return _call("DELETE", f"/configs/{_seg(service)}/{_seg(type)}/{_seg(name)}")


@tool("admin", DESTRUCTIVE)
def bw_stop_instances(hostname: Optional[str] = None) -> str:
    """ARRÊTE NGINX sur une instance (ou toutes sans hostname) : coupe le trafic web. Confirmer avant."""
    path = f"/instances/{_seg(hostname)}/stop" if hostname else "/instances/stop"
    return _call("POST", path)


@tool("admin", DESTRUCTIVE)
def bw_api_request(method: Literal["GET", "POST", "PATCH", "PUT", "DELETE"], path: str,
                   query: Optional[dict[str, str]] = None, body: Optional[Any] = None) -> str:
    """Requête libre sur l'API (toute méthode), pour les cas non couverts.
    Consulter /openapi.json via bw_api_get pour connaître les routes. Confirmer avec l'utilisateur avant toute écriture."""
    if not _PATH_RX.match(path) or ".." in path or path.startswith("/auth"):
        return "ERREUR : chemin refusé (doit commencer par /, sans '..', hors /auth)"
    return _call(method, path, query=query, body=body)


# --------------------------------------------------------------------------- #


def main() -> None:
    if not (API_TOKEN or (API_USERNAME and API_PASSWORD)):
        print("[bunkerweb-mcp] Attention : aucun identifiant configuré, seuls /ping et /health fonctionneront.",
              file=sys.stderr)
    print(f"[bunkerweb-mcp] {API_URL} — niveau {ACCESS_LEVEL}", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
