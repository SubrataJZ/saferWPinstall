# SaferWP Install

A MainWP/ManageWP-style tool for tracking WordPress plugin & theme vulnerabilities
across your managed sites. It has two parts:

1. **`agent-plugin/`** — a small WordPress plugin you install on each managed site.
   It exposes an authenticated REST endpoint that reports installed plugins/themes
   and their versions, and accepts start/stop scan commands.
2. **`dashboard/`** — a central Node.js web app. You add each site's URL + agent
   API key, it pulls the inventory, cross-references every plugin/theme against
   the [WPScan Vulnerability Database](https://wpscan.com/api), and recommends
   the safest version to upgrade to using each item's published version history.

## How it decides what's "safe"

For every installed plugin/theme:
1. Look up its known vulnerabilities from WPScan (each entry includes the version
   it was `fixed_in`, if patched).
2. A vulnerability **applies** if the installed version is below its `fixed_in`
   (or if it has no `fixed_in` at all — still unpatched).
3. Pull the plugin/theme's full published version history from the official
   WordPress.org API.
4. **Recommend** the latest stable release if it clears every known fix
   threshold; otherwise recommend the earliest available version that does.

## Setup

### 1. Install the agent on each managed site

Copy `agent-plugin/saferwp-agent.php` into a plugin folder (e.g.
`wp-content/plugins/saferwp-agent/saferwp-agent.php`) on each WordPress site you
want to manage, then activate it. Go to **Settings → SaferWP Agent** in wp-admin
to get the site's URL and API key.

### 2. Run the dashboard

```bash
cd dashboard
npm install
export WPSCAN_API_TOKEN=your_free_wpscan_token   # https://wpscan.com/api
npm start
```

Open `http://localhost:3000`, click **+ Add site**, and paste in the name, URL,
and API key from step 1.

### 3. Manage scans

- **Scan now** runs an immediate scan and shows results under **View findings**.
- **Stop** disables both the dashboard's schedule and the agent's willingness to
  respond to scans on that site; **Resume** re-enables both.
- Each site has its own cron schedule (default: every 6 hours) editable when adding it.

## Notes & limits

- The free WPScan API tier has a daily request quota; each plugin/theme lookup
  during a scan costs one request. For larger fleets, get a paid WPScan key or
  add caching (not included in this MVP).
- Vulnerability coverage depends on what WPScan tracks. If a slug isn't in their
  database, it's reported as having no known vulnerabilities on record — that's
  "unknown," not a guarantee of safety.
- Data persists in `dashboard/saferwp.db` (SQLite).
