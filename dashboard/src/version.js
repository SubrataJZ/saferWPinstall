/**
 * PHP-style version_compare, good enough for the dotted numeric versions
 * WordPress.org and WPScan both use (e.g. "1.2.10" > "1.2.9").
 */
function compareVersions(a, b) {
  const pa = String(a).split(/[.\-+]/).map((s) => (isNaN(s) ? s : parseInt(s, 10)));
  const pb = String(b).split(/[.\-+]/).map((s) => (isNaN(s) ? s : parseInt(s, 10)));
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    return String(x).localeCompare(String(y));
  }
  return 0;
}

const lt = (a, b) => compareVersions(a, b) < 0;
const gte = (a, b) => compareVersions(a, b) >= 0;
const gt = (a, b) => compareVersions(a, b) > 0;

/**
 * Given the installed version and a list of vulnerabilities (each with an optional
 * fixed_in version), decide whether the installed copy is actually affected.
 * WPScan lists vulns discovered against the plugin historically; a vuln only
 * applies to versions strictly below its fixed_in (or all versions if fixed_in
 * is null, meaning still unpatched).
 */
function findApplicableVulnerabilities(installedVersion, vulnerabilities) {
  return vulnerabilities.filter((v) => {
    if (!v.fixed_in) return true; // unpatched - affects every version including latest
    return lt(installedVersion, v.fixed_in);
  });
}

/**
 * Recommends the safest version to upgrade to: the lowest available version that is
 * >= installed, not itself flagged by any known vulnerability's fixed_in threshold,
 * preferring the latest stable release when it clears all known issues.
 */
function recommendSafeVersion(installedVersion, availableVersions, vulnerabilities) {
  const highestFixedIn = vulnerabilities
    .map((v) => v.fixed_in)
    .filter(Boolean)
    .sort(compareVersions)
    .pop();

  const sorted = [...availableVersions].filter((v) => /^[\d.]+$/.test(v)).sort(compareVersions);
  const latest = sorted[sorted.length - 1];

  if (!highestFixedIn) {
    return {
      recommended_version: latest || installedVersion,
      reason: vulnerabilities.length
        ? 'No patched version published yet for the known issue(s); latest available release shown.'
        : 'No known vulnerabilities on record; latest stable release recommended.',
    };
  }

  if (latest && gte(latest, highestFixedIn)) {
    return {
      recommended_version: latest,
      reason: `Latest release (${latest}) already includes the fix from ${highestFixedIn}.`,
    };
  }

  // Fall back to the earliest available version that clears the fix threshold.
  const safest = sorted.find((v) => gte(v, highestFixedIn));
  return {
    recommended_version: safest || highestFixedIn,
    reason: `Earliest version that includes the fix for the known vulnerability (fixed in ${highestFixedIn}).`,
  };
}

module.exports = { compareVersions, lt, gte, gt, findApplicableVulnerabilities, recommendSafeVersion };
