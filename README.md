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

### Optional environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `WPSCAN_API_TOKEN` | Your free/paid WPScan API token | *(required)* |
| `WPSCAN_API_BASE` | Override the WPScan API base URL (e.g. to point at a mock/staging server) | `https://wpscan.com/api/v3` |
| `WPORG_API_BASE` | Override the WordPress.org API base URL used for version history | `https://api.wordpress.org` |
| `WPSCAN_DAILY_LIMIT` | Live WPScan requests allowed per day before falling back to cache | `25` (WPScan's free-tier limit) |
| `WPSCAN_CACHE_TTL_HOURS` | How long a cached vulnerability lookup is trusted before refetching | `24` |
| `PORT` | Dashboard HTTP port | `3000` |

## Staying inside the WPScan free-tier quota (25 requests/day)

Every plugin/theme lookup costs one WPScan request, and a fleet of managed sites
can easily have far more than 25 distinct plugins/themes between them. The
dashboard is built to spend that budget efficiently rather than run out
partway through a scan and silently call things "safe":

- **Shared, TTL-cached lookups.** A vulnerability lookup is cached by
  `(type, slug)` — not per site, not per version — for `WPSCAN_CACHE_TTL_HOURS`
  (default 24h). Ten sites all running Contact Form 7 cost **one** WPScan
  request between them, not ten, and re-scanning the same site within the TTL
  window costs nothing.
- **Hard budget cap.** The dashboard tracks its own daily request count and
  stops making live calls once `WPSCAN_DAILY_LIMIT` (default 25, matching
  WPScan's free tier) is reached — it never lets a scan blow through the quota
  and start drawing 429s.
- **Never silently "safe."** Once the budget is spent, remaining items fall
  back to a stale cached result if one exists (flagged in the UI), or are
  explicitly marked "vulnerability status unknown this scan" — never reported
  as vulnerability-free just because no live check could run.
- **Live quota visible in the dashboard.** The header shows `used / limit`
  WPScan requests for today, so you can see at a glance whether a fleet's
  scan schedule is going to fit inside the budget.

For a larger fleet: raise the cache TTL (vulnerability disclosures aren't
hourly events), stagger each site's cron schedule so they don't all scan at
once, or get a paid WPScan key with a higher limit.

## Notes & limits

- Vulnerability coverage depends on what WPScan tracks. If a slug isn't in their
  database, it's reported as having no known vulnerabilities on record — that's
  "unknown," not a guarantee of safety.
- Data persists in `dashboard/saferwp.db` (SQLite).
