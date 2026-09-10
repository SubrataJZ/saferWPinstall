const fetch = require('node-fetch');

/**
 * Pulls the full published version history for a plugin or theme from the
 * official WordPress.org API. Used to know what versions actually exist so
 * recommendations point at a real, downloadable release.
 */
async function getVersionHistory(type, slug) {
  const url =
    type === 'theme'
      ? `https://api.wordpress.org/themes/info/1.2/?action=theme_information&slug=${encodeURIComponent(slug)}&request[fields][versions]=1`
      : `https://api.wordpress.org/plugins/info/1.0/${encodeURIComponent(slug)}.json`;

  const res = await fetch(url);
  if (!res.ok) return { versions: [], latest: null };

  const data = await res.json();
  if (!data || !data.versions) {
    return { versions: [], latest: data && data.version ? [data.version] : [] };
  }

  const versions = Object.keys(data.versions).filter((v) => v !== 'trunk');
  return { versions, latest: data.version || null };
}

module.exports = { getVersionHistory };
