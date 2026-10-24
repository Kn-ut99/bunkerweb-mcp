# bunkerweb-mcp

Serveur MCP (transport stdio) pour piloter BunkerWeb ≥ 1.6 depuis Claude Desktop ou Hermes Agent, via l'API BunkerWeb joignable en local à travers un tunnel SSH.

Un seul fichier Python, une seule dépendance (`mcp`), compatible SDK MCP v1 et v2.

## 1. Côté serveur BunkerWeb

L'API doit avoir au moins un moyen d'authentification. Dans `/etc/bunkerweb/api.env` (installation Linux) ou l'environnement du conteneur `bw-api` :

```env
API_USERNAME=admin
API_PASSWORD=UnMotDePasse-Fort!42
# ou, en complément (accès admin « break-glass ») :
# API_TOKEN=un-jeton-long-et-aleatoire
```

puis `sudo systemctl reload bunkerweb-api`.

### Utilisateur dédié pour le MCP (recommandé)

Le compte `API_USERNAME` est un **admin** : il passe outre toutes les permissions. Si le serveur MCP l'utilise, la seule protection restante est `BUNKERWEB_ACCESS_LEVEL`, un garde-fou côté client que le modèle ne peut pas contourner, mais qui ne protège plus rien si quelqu'un réutilise le mot de passe ailleurs.

Mieux vaut donc créer un second utilisateur, **non admin**, dont les droits sont limités par l'API elle-même. BunkerWeb crée ces utilisateurs à partir d'un fichier JSON lu au démarrage :

1. Écrire le fichier ci-dessous dans `/var/lib/bunkerweb/api_acl_bootstrap.json` (chemin lu par défaut), ou ailleurs en pointant `API_ACL_BOOTSTRAP_FILE=/chemin/du/fichier.json` dans `api.env`.
2. Le rendre lisible par l'API uniquement : `sudo chown nginx:nginx` (ou l'utilisateur du conteneur `bw-api`) et `chmod 600`. Le mot de passe peut aussi y être stocké en hash bcrypt via `password_hash` au lieu de `password` (voir la doc BunkerWeb).
3. `sudo systemctl reload bunkerweb-api` (ou redémarrer le conteneur `bw-api`).

L'exemple suivant correspond au niveau MCP `operate` : **lecture de tout + gestion des bans + lancement des jobs**, sans aucun droit de modifier la configuration.


```json
{
  "users": {
    "mcp": {
      "admin": false,
      "password": "Autre-Mot-De-Passe-Fort!7",
      "permissions": {
        "instances": { "*": { "instances_read": true } },
        "global_config": { "*": { "global_config_read": true } },
        "services": { "*": { "service_read": true } },
        "configs": { "*": { "configs_read": true, "config_read": true } },
        "bans": { "*": { "ban_read": true, "ban_update": true, "ban_delete": true } },
        "plugins": { "*": { "plugin_read": true } },
        "cache": { "*": { "cache_read": true } },
        "jobs": { "*": { "job_read": true, "job_run": true } }
      }
    }
  }
}
```

Pour un compte **strictement en lecture seule** (niveau MCP `read`), retirez `ban_update`, `ban_delete` et `job_run`. Ensuite, utilisez ce compte dans la config du client (`BUNKERWEB_API_USERNAME=mcp`) et gardez l'admin pour une entrée séparée, activée seulement quand c'est nécessaire.

> Les permissions d'écriture sur `configs`, `services`, `global_config`, `plugins` et `instances_create/update` équivalent à un accès admin (le contenu finit tel quel dans NGINX/Lua). Ne les accordez que si vous voulez vraiment que le modèle puisse modifier la config.

## 2. Tunnel SSH

```bash
ssh -N -L 127.0.0.1:8888:127.0.0.1:8888 user@serveur-bunkerweb
```

Les requêtes arrivent sur l'API depuis `127.0.0.1`, donc compatibles avec `API_WHITELIST_IPS=127.0.0.1` et avec la liaison du jeton Biscuit à l'IP cliente. Pour un tunnel permanent : `autossh -M 0 -N -o ServerAliveInterval=30 -L ...` ou une unité systemd `--user`.

Test rapide : `curl http://127.0.0.1:8888/ping`

## 3. Installation

```bash
mkdir -p ~/.local/share/bunkerweb-mcp
cp bunkerweb_mcp.py ~/.local/share/bunkerweb-mcp/
```

Avec [uv](https://docs.astral.sh/uv/) rien d'autre à faire : `uv run` lit les métadonnées en tête du script et installe `mcp` dans un environnement isolé.
Sans uv : `python -m venv ~/.local/share/bunkerweb-mcp/venv && ~/.local/share/bunkerweb-mcp/venv/bin/pip install mcp`, puis utilisez ce `python` comme commande.

Mettez le mot de passe dans un fichier plutôt qu'en clair dans la config du client :

```bash
install -m 600 /dev/null ~/.config/bunkerweb-mcp.pass
echo 'Autre-Mot-De-Passe-Fort!7' > ~/.config/bunkerweb-mcp.pass
```

## 4. Brancher le client

### Claude Desktop

Paramètres → Développeur → Modifier la configuration (`claude_desktop_config.json`), voir `claude_desktop_config.example.json` :

```json
{
  "mcpServers": {
    "bunkerweb": {
      "command": "uv",
      "args": ["run", "/home/VOUS/.local/share/bunkerweb-mcp/bunkerweb_mcp.py"],
      "env": {
        "BUNKERWEB_API_URL": "http://127.0.0.1:8888",
        "BUNKERWEB_API_USERNAME": "mcp",
        "BUNKERWEB_API_PASSWORD_FILE": "/home/VOUS/.config/bunkerweb-mcp.pass",
        "BUNKERWEB_ACCESS_LEVEL": "read"
      }
    }
  }
}
```

Redémarrez Claude Desktop. Si `uv` n'est pas trouvé, mettez son chemin absolu (`which uv`).

### Hermes Agent

Dans `~/.hermes/config.yaml` (à fusionner, ne pas écraser le fichier), voir `hermes_config.example.yaml` :

```yaml
mcp_servers:
  bunkerweb:
    command: "uv"
    args: ["run", "/home/VOUS/.local/share/bunkerweb-mcp/bunkerweb_mcp.py"]
    env:
      BUNKERWEB_API_URL: "http://127.0.0.1:8888"
      BUNKERWEB_API_USERNAME: "mcp"
      BUNKERWEB_API_PASSWORD_FILE: "/home/VOUS/.config/bunkerweb-mcp.pass"
      BUNKERWEB_ACCESS_LEVEL: "read"
```

Puis `/reload-mcp` dans Hermes (ou redémarrage). Hermes ne transmet que les variables listées dans `env`, c'est voulu.

Premier essai : « vérifie la connexion à BunkerWeb » → le modèle appelle `bw_health`.

## 5. Niveaux d'accès

`BUNKERWEB_ACCESS_LEVEL` décide quels outils sont **exposés** au modèle (un outil non exposé ne peut pas être appelé, même par erreur). Les permissions ACL côté BunkerWeb restent la vraie barrière ; les deux se cumulent.

| Niveau | Outils |
|---|---|
| `read` (défaut) | `bw_health`, `bw_list_instances`, `bw_ping_instances`, `bw_get_global_settings`, `bw_list_services`, `bw_get_service`, `bw_list_configs`, `bw_get_config`, `bw_list_bans`, `bw_list_plugins`, `bw_list_jobs`, `bw_list_cache`, `bw_api_get` |
| `operate` | + `bw_ban_ip`, `bw_unban_ip`, `bw_reload_instances` (avec test de config par défaut), `bw_run_jobs` |
| `admin` | + `bw_update_global_settings`, `bw_create_service` (en brouillon par défaut), `bw_update_service`, `bw_convert_service`, `bw_delete_service`, `bw_create_config`, `bw_update_config`, `bw_delete_config`, `bw_stop_instances`, `bw_api_request` |

Les outils portent les annotations MCP `readOnlyHint` / `destructiveHint`, ce qui permet au client de demander confirmation avant les actions qui écrivent ou suppriment.

Astuce : déclarez deux entrées (`bunkerweb` en `read`, `bunkerweb-admin` en `admin`) et n'activez la seconde que le temps d'une intervention.

## 6. Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `BUNKERWEB_API_URL` | `http://127.0.0.1:8888` | URL de l'API (ajouter le préfixe si `API_ROOT_PATH` est défini) |
| `BUNKERWEB_API_USERNAME` / `BUNKERWEB_API_PASSWORD` | — | Identifiants ; le serveur obtient un jeton Biscuit via `POST /auth`, le réutilise et le renouvelle à l'expiration |
| `BUNKERWEB_API_PASSWORD_FILE` | — | Mot de passe lu depuis un fichier |
| `BUNKERWEB_API_TOKEN` / `BUNKERWEB_API_TOKEN_FILE` | — | Jeton `API_TOKEN` (accès admin total, prioritaire sur les identifiants) |
| `BUNKERWEB_ACCESS_LEVEL` | `read` | `read`, `operate` ou `admin` |
| `BUNKERWEB_SHOW_SECRETS` | `false` | Par défaut, les valeurs des réglages contenant PASSWORD, SECRET, TOKEN, KEY, DATABASE_URI… sont masquées avant d'être envoyées au modèle |
| `BUNKERWEB_MAX_CHARS` | `25000` | Troncature des grosses réponses (ex. `full=true`) |
| `BUNKERWEB_TIMEOUT` | `30` | Timeout HTTP (s) |
| `BUNKERWEB_VERIFY_TLS` | `true` | `false` pour un certificat auto-signé si l'API est en https |

## 7. Dépannage

- **« API injoignable »** : le tunnel SSH n'est pas ouvert, ou le port local diffère.
- **HTTP 403** : IP hors `API_WHITELIST_IPS`, ou permission ACL manquante pour l'utilisateur.
- **HTTP 429** : rate limit de l'API (`/auth` est limité à 10 requêtes/min par défaut) ; le serveur réutilise son jeton, donc ça ne devrait arriver qu'en rafale.
- **HTTP 404 sur une route** : la route n'existe pas dans votre version ; `bw_api_get` avec `path="/openapi.json"` liste celles qui existent.
- Les logs du serveur MCP sortent sur stderr (visibles dans les logs MCP de Claude Desktop ou de Hermes).

## Licence

MIT, voir [LICENSE](LICENSE).
