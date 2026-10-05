/**
 * Every finding scripts/judge-headers.sh can emit, in one list.
 *
 * The point of writing this down is test/catalogue.test.mjs, which drives each
 * entry out of a real run of the real script and asserts the two sets match in
 * both directions. A finding that cannot be produced is removed; a finding the
 * script produces that is not listed here fails the suite.
 *
 * Without that, a catalogue is documentation, and documentation of a checker
 * drifts from the checker within about two commits.
 */

/** Findings with a fixed id. */
export const FINDINGS = [
  {
    id: 'missing/x-content-type-options',
    level: 'error',
    what: 'X-Content-Type-Options was not sent on the final response.',
  },
  {
    id: 'weak/x-content-type-options',
    level: 'error',
    what: 'Sent, but the value is not nosniff, which is the only value that does anything.',
  },
  {
    id: 'missing/x-frame-options',
    level: 'error',
    what: 'X-Frame-Options was not sent on the final response.',
  },
  {
    id: 'weak/x-frame-options',
    level: 'error',
    what: 'Sent with a value that permits framing, such as ALLOWALL, or with the obsolete ALLOW-FROM.',
  },
  {
    id: 'missing/referrer-policy',
    level: 'error',
    what: 'Referrer-Policy was not sent on the final response.',
  },
  {
    id: 'weak/referrer-policy',
    level: 'error',
    what: 'Sent as unsafe-url, or empty, so the full URL goes to every destination.',
  },
  {
    id: 'missing/permissions-policy',
    level: 'error',
    what: 'Permissions-Policy was not sent on the final response.',
  },
  {
    id: 'weak/permissions-policy',
    level: 'error',
    what: 'Sent with an empty or letterless value, so no browser feature is restricted.',
  },
  {
    id: 'missing/strict-transport-security',
    level: 'error',
    what: 'The final response is HTTPS and sent no HSTS header.',
  },
  {
    id: 'weak/strict-transport-security',
    level: 'warn',
    what: 'max-age is under 30 days, which is a staging value left in production, or absent from the header.',
  },
  {
    id: 'disabled/strict-transport-security',
    level: 'error',
    what: 'max-age=0, which switches HSTS off. That is the back-out value, not a deployment.',
  },
  {
    id: 'transport/not-https',
    level: 'warn',
    what: 'The final URL is not HTTPS, so HSTS could not be judged at all.',
  },
  {
    id: 'csp/absent',
    level: 'note',
    what: 'No Content-Security-Policy. Deliberately a note: on a page-builder site, not deploying one is often the right call.',
  },
  {
    id: 'csp/unsafe-inline',
    level: 'warn',
    what: 'A CSP is present and permits unsafe-inline, which allows the injection the policy was deployed to stop.',
  },
  {
    id: 'leak/pingback',
    level: 'warn',
    what: 'X-Pingback advertises the XML-RPC endpoint in every response.',
  },
];

/**
 * Open families: one id carrying a value read from the response, so the set of
 * concrete messages is not finite. Listed separately so the catalogue test can
 * require each family to be produced without requiring an exhaustive list.
 */
export const FAMILIES = [
  {
    id: 'redirect-only',
    level: 'error',
    carries: 'the header name',
    what: 'A required header is sent on a redirect hop but not on the final response. Any checker that searches the whole dump calls this a pass.',
  },
  {
    id: 'leak/version',
    level: 'warn',
    carries: 'the header name and its value',
    what: 'A response header gives away a software version, for example Server or X-Powered-By. Presence alone is not the finding.',
  },
];

export const ALL_IDS = [...FINDINGS, ...FAMILIES].map((f) => f.id);
