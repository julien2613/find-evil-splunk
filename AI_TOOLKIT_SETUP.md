# Configuration du Splunk AI Toolkit (commande `| ai`)

L'outil `forensics_ai_triage` s'appuie sur la commande SPL **`| ai`** du Splunk AI
Toolkit. Sur **Splunk Enterprise local** (macOS Apple Silicon), la mise en route
demande quatre étapes — toutes découvertes et validées sur cette machine.

## 1. Installer le AI Toolkit
- Splunkbase **app 2890** → `Splunk_ML_Toolkit` dans `etc/apps/`.

## 2. Installer le moteur Python (PSC) — variante exacte
- Splunkbase **app 2882**, variante **macOS Apple Silicon (arm64)**.
- Déballe sous `Splunk_SA_Scientific_Python_darwin_arm64` (le nom que `| ai` réclame).
- ⚠️ **Linux/Intel ne fonctionnent pas** : binaires Python compilés par plateforme.

### Retirer la quarantaine macOS (sinon SIGKILL)
Le Python embarqué n'est pas signé → Gatekeeper le tue (`error code 9`). Fix :
```bash
xattr -dr com.apple.quarantine \
  /Applications/Splunk/etc/apps/Splunk_SA_Scientific_Python_darwin_arm64
```
Puis redémarrer Splunk.

## 3. Donner la capacité à l'utilisateur
La commande `| ai` exige `apply_ai_commander_command`, absente du rôle `admin`.
Ajouter le rôle **`mltk_admin`** à l'utilisateur (Settings → Users), ou accorder
les capacités `apply_ai_commander_command` / `edit_ai_commander_config` /
`list_ai_commander_config` au rôle voulu.

## 4. Créer la connexion LLM (UI)
Dans **AI Toolkit → Connections** (`/app/Splunk_ML_Toolkit/connections`) :
- Provider **Anthropic**, modèle `claude-sonnet-4-5-20250929`
- Access Token = clé `sk-ant-…`, endpoint `https://api.anthropic.com/v1/messages`
- Nommer la connexion **`claude`** (référencée par l'outil `forensics_ai_triage`).

> La page Connections n'affiche les providers qu'une fois PSC installé **et** le
> rôle accordé. Sans cela, seul « Custom » apparaît.

## 5. Vérifier
```spl
| makeresults | ai connection="claude" prompt="dis bonjour"
```
Doit retourner une réponse du modèle. Ensuite l'outil MCP `forensics_ai_triage`
fonctionne (voir `../forensic_ai_tool.json`).
