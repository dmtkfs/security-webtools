/**
 * Parse raw HTTP response headers into a simple map.
 * Header names are normalized to lowercase, last occurrence wins if a header is repeated
 *
 * @param {string} rawText
 * @returns {Record<string, string>}
 */
export function parseRawHeaders(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return {};
  }

  const lines = rawText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const headers = {};

  for (const line of lines) {
    // Skip status line
    if (!line.includes(':')) continue;

    const idx = line.indexOf(':');
    if (idx <= 0) continue;

    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();

    if (!name) continue;

    headers[name] = value;
  }

  return headers;
}

//Extract HTTP status code from the raw header text, if present
function extractStatusCode(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return null;
  }

  const lines = rawText.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    if (trimmed.toUpperCase().startsWith('HTTP/')) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        const code = parseInt(parts[1], 10);
        return Number.isFinite(code) ? code : null;
      }
      break;
    } else {
      break;
    }
  }

  return null;
}

// Internal helper: create a "missing" finding for a header
function missingHeaderFinding(displayName, description, recommendation) {
  return {
    name: displayName,
    status: 'missing',
    message: `${displayName} header is not present. ${description}`,
    recommendation,
    score: 0,
  };
}

// Analyze a Content-Security-Policy value
function checkCsp(value) {
  const raw = value || '';
  const lower = raw.toLowerCase();

  const hasDefaultSrc = lower.includes('default-src');
  const hasUnsafeInline = lower.includes('unsafe-inline');
  const hasUnsafeEval = lower.includes('unsafe-eval');
  const hasStarWildcard =
    /\s\*\s/.test(lower) || /\s\*[.;]/.test(lower) || /:\s*\*/.test(lower);
  const hasStrictDynamic = lower.includes("'strict-dynamic'");
  const hasNonce = lower.includes('nonce-');

  if (hasUnsafeInline || hasUnsafeEval || !hasDefaultSrc || hasStarWildcard) {
    const reason = [];

    if (!hasDefaultSrc) {
      reason.push('missing a default-src directive');
    }
    if (hasUnsafeInline) {
      reason.push("uses 'unsafe-inline'");
    }
    if (hasUnsafeEval) {
      reason.push("uses 'unsafe-eval'");
    }
    if (hasStarWildcard) {
      reason.push('relies on broad * wildcards');
    }

    let message = `Content-Security-Policy is present but ${reason.join(
      ', '
    )}, which reduces its effectiveness.`;

    if (hasStrictDynamic && hasNonce) {
      message +=
        " This policy also uses 'strict-dynamic' with nonced scripts, which can mitigate some inline-script risks, but many scanners still treat unsafe-inline/unsafe-eval as weaknesses.";
    }

    return {
      name: 'Content-Security-Policy',
      status: 'weak',
      message,
      recommendation:
        'Tighten your CSP: define a strict default-src, avoid unsafe-inline and unsafe-eval and minimize wildcard (*) sources.',
      score: 1,
    };
  }

  let okMessage =
    'Content-Security-Policy is present with a default-src and no obvious unsafe-inline/unsafe-eval directives.';

  if (hasStrictDynamic) {
    okMessage +=
      " It also uses 'strict-dynamic', a modern CSP pattern that relies on nonced or hashed scripts.";
  }

  return {
    name: 'Content-Security-Policy',
    status: 'ok',
    message: okMessage,
    recommendation:
      'Review your CSP periodically to ensure it remains aligned with your application behavior and least-privilege principles.',
    score: 2,
  };
}

// Analyze a Strict-Transport-Security value
function checkHsts(value) {
  const raw = value || '';
  const lower = raw.toLowerCase();

  const maxAgeMatch = lower.match(/max-age\s*=\s*(\d+)/);
  const includeSubdomains = lower.includes('includesubdomains');

  if (!maxAgeMatch) {
    return {
      name: 'Strict-Transport-Security',
      status: 'weak',
      message:
        'Strict-Transport-Security is present but max-age is missing or malformed.',
      recommendation:
        'Set a strong max-age (e.g. at least 15552000 seconds ≈ 180 days) and consider includeSubDomains (and preload where appropriate).',
      score: 1,
    };
  }

  const maxAge = parseInt(maxAgeMatch[1], 10);

  if (maxAge === 0) {
    return {
      name: 'Strict-Transport-Security',
      status: 'weak',
      message:
        'Strict-Transport-Security is set with max-age=0, which explicitly disables HSTS in supporting browsers.',
      recommendation:
        'Avoid using max-age=0 in production. Either omit the header or configure a positive max-age with includeSubDomains.',
      score: 1,
    };
  }

  const hasStrongMaxAge = Number.isFinite(maxAge) && maxAge >= 15552000;

  if (!hasStrongMaxAge || !includeSubdomains) {
    const parts = [];
    if (!hasStrongMaxAge) {
      parts.push('max-age is shorter than ~180 days');
    }
    if (!includeSubdomains) {
      parts.push('includeSubDomains is not set');
    }

    return {
      name: 'Strict-Transport-Security',
      status: 'weak',
      message: `Strict-Transport-Security is present but ${parts.join(
        ' and '
      )}.`,
      recommendation:
        'Increase max-age to at least 15552000 seconds and add includeSubDomains. Optionally consider preload once you are confident in HTTPS coverage.',
      score: 1,
    };
  }

  return {
    name: 'Strict-Transport-Security',
    status: 'ok',
    message:
      'Strict-Transport-Security is present with a strong max-age and includeSubDomains.',
    recommendation:
      'Ensure HTTPS is enforced across all subdomains and consider HSTS preload if it fits your deployment model.',
    score: 2,
  };
}

// Analyze an X-Frame-Options value
function checkXfo(value) {
  const raw = (value || '').trim();
  const lower = raw.toLowerCase();

  if (lower === 'deny' || lower === 'sameorigin') {
    const mode =
      lower === 'deny'
        ? 'DENY (strongest setting)'
        : 'SAMEORIGIN (only same-site frames allowed)';

    return {
      name: 'X-Frame-Options',
      status: 'ok',
      message: `X-Frame-Options is set to ${mode}.`,
      recommendation:
        'Verify that only trusted flows require framing; for newer browsers you can also consider using a frame-ancestors directive in your CSP.',
      score: 2,
    };
  }

  return {
    name: 'X-Frame-Options',
    status: 'weak',
    message:
      'X-Frame-Options is present but not using a recommended value (DENY or SAMEORIGIN).',
    recommendation:
      'Set X-Frame-Options to DENY or SAMEORIGIN to reduce clickjacking risk or switch to an appropriate CSP frame-ancestors policy.',
    score: 1,
  };
}

// Analyze an X-Content-Type-Options value
function checkXcto(value) {
  const raw = (value || '').trim();
  const lower = raw.toLowerCase();

  if (lower === 'nosniff') {
    return {
      name: 'X-Content-Type-Options',
      status: 'ok',
      message: 'X-Content-Type-Options is set to nosniff.',
      recommendation:
        'Keep X-Content-Type-Options: nosniff enabled to reduce MIME-sniffing and certain script injection risks.',
      score: 2,
    };
  }

  return {
    name: 'X-Content-Type-Options',
    status: 'weak',
    message:
      'X-Content-Type-Options is present but not set to the recommended nosniff value.',
    recommendation:
      'Set X-Content-Type-Options: nosniff to harden against MIME-sniffing issues.',
    score: 1,
  };
}

// Analyze a Referrer-Policy value
function checkReferrerPolicy(value) {
  const raw = (value || '').trim();
  const lower = raw.toLowerCase();

  if (!lower) {
    return {
      name: 'Referrer-Policy',
      status: 'weak',
      message:
        'Referrer-Policy is present but empty or malformed, so the browser may fall back to less private defaults.',
      recommendation:
        'Set a privacy-friendly referrer policy such as strict-origin-when-cross-origin, same-origin or no-referrer.',
      score: 1,
    };
  }

  // "Stronger" policies
  const strongPolicies = new Set([
    'no-referrer',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'origin-when-cross-origin',
  ]);

  // "Weaker" policies
  const weakPolicies = new Set(['unsafe-url', 'no-referrer-when-downgrade']);

  const tokens = lower.split(',').map((t) => t.trim()).filter(Boolean);

  if (tokens.length > 1) {
    const allKnown = tokens.every(
      (t) => strongPolicies.has(t) || weakPolicies.has(t)
    );

    const policyList = tokens.join(', ');
    const messageBase = allKnown
      ? `Referrer-Policy is set to multiple values (${policyList}), which is not a standard pattern and may lead browsers to ignore some values or fall back to defaults.`
      : `Referrer-Policy is set to multiple or non-standard values ("${raw}"), which may not provide the intended protection.`;

    return {
      name: 'Referrer-Policy',
      status: 'weak',
      message: messageBase,
      recommendation:
        'Use a single, well-defined referrer policy such as strict-origin-when-cross-origin, same-origin or no-referrer.',
      score: 1,
    };
  }

  // Single value
  if (strongPolicies.has(lower)) {
    return {
      name: 'Referrer-Policy',
      status: 'ok',
      message: `Referrer-Policy is set to ${raw}, which is generally considered privacy-friendly.`,
      recommendation:
        'Ensure the chosen policy aligns with your analytics and logging needs while minimizing unnecessary referrer data leakage.',
      score: 2,
    };
  }

  if (weakPolicies.has(lower)) {
    return {
      name: 'Referrer-Policy',
      status: 'weak',
      message: `Referrer-Policy is set to ${raw}, which may leak more referrer information than necessary.`,
      recommendation:
        'Prefer stricter policies like strict-origin-when-cross-origin, same-origin or no-referrer where possible.',
      score: 1,
    };
  }

  // Unknown / custom value -> treat as weak
  return {
    name: 'Referrer-Policy',
    status: 'weak',
    message: `Referrer-Policy is set to ${raw}, which is not a commonly-used standard value and may not provide the intended protection.`,
    recommendation:
      'Use a standard, privacy-friendly referrer policy such as strict-origin-when-cross-origin, same-origin or no-referrer.',
    score: 1,
  };
}

// Extended header checks (do NOT affect numeric score)

// Permissions-Policy
function checkPermissionsPolicy(value) {
  const raw = (value || '').trim();
  const lower = raw.toLowerCase();

  if (!raw) {
    return {
      name: 'Permissions-Policy',
      status: 'weak',
      message:
        'Permissions-Policy is present but empty or malformed, so powerful browser features may not be constrained as intended.',
      recommendation:
        'Define a Permissions-Policy that disables or restricts features (camera, microphone, geolocation, etc.) you do not need.',
      score: 1,
    };
  }

  const hasWildcard = lower.includes('*');

  if (hasWildcard) {
    return {
      name: 'Permissions-Policy',
      status: 'weak',
      message:
        'Permissions-Policy is present but uses broad * wildcards, which may allow more access to powerful features than necessary.',
      recommendation:
        'Tighten your Permissions-Policy by scoping each feature to specific origins or disabling unused features entirely.',
      score: 1,
    };
  }

  return {
    name: 'Permissions-Policy',
    status: 'ok',
    message:
      'Permissions-Policy is present with at least some feature-level restrictions configured.',
    recommendation:
      'Review your Permissions-Policy periodically to ensure only required features are enabled for trusted origins.',
    score: 2,
  };
}

// Cross-Origin-Opener-Policy (COOP)
function checkCoop(value) {
  const raw = (value || '').trim();
  const lower = raw.toLowerCase();

  if (!raw) {
    return {
      name: 'Cross-Origin-Opener-Policy',
      status: 'weak',
      message:
        'Cross-Origin-Opener-Policy is present but empty or malformed, so the document may not have strong process isolation from other origins.',
      recommendation:
        'Use Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if needed) to reduce cross-origin interference and enable stronger isolation.',
      score: 1,
    };
  }

  if (lower === 'same-origin' || lower === 'same-origin-allow-popups') {
    return {
      name: 'Cross-Origin-Opener-Policy',
      status: 'ok',
      message: `Cross-Origin-Opener-Policy is set to ${raw}, enabling stronger browsing-context isolation.`,
      recommendation:
        'Ensure COOP is aligned with your use of window.open/popups; keep it at same-origin or same-origin-allow-popups where possible.',
      score: 2,
    };
  }

  // e.g. unsafe-none or other custom values
  return {
    name: 'Cross-Origin-Opener-Policy',
    status: 'weak',
    message: `Cross-Origin-Opener-Policy is set to ${raw}, which may not provide strong isolation from cross-origin windows.`,
    recommendation:
      'Prefer same-origin (or same-origin-allow-popups) for COOP on security-sensitive origins.',
    score: 1,
  };
}

// Cross-Origin-Embedder-Policy (COEP)
function checkCoep(value) {
  const raw = (value || '').trim();
  const lower = raw.toLowerCase();

  if (!raw) {
    return {
      name: 'Cross-Origin-Embedder-Policy',
      status: 'weak',
      message:
        'Cross-Origin-Embedder-Policy is present but empty or malformed, so cross-origin resources may not require explicit protection.',
      recommendation:
        'Use Cross-Origin-Embedder-Policy: require-corp on origins where you want strong isolation and safe use of powerful APIs.',
      score: 1,
    };
  }

  if (lower === 'require-corp') {
    return {
      name: 'Cross-Origin-Embedder-Policy',
      status: 'ok',
      message:
        'Cross-Origin-Embedder-Policy is set to require-corp, enforcing that cross-origin resources explicitly opt in.',
      recommendation:
        'Verify that required third-party resources send appropriate CORP/COEP headers to avoid breakage.',
      score: 2,
    };
  }

  // e.g. unsafe-none or others
  return {
    name: 'Cross-Origin-Embedder-Policy',
    status: 'weak',
    message: `Cross-Origin-Embedder-Policy is set to ${raw}, which may not provide strong protection for embedded cross-origin resources.`,
    recommendation:
      'Consider using require-corp on sensitive origins to tighten embedding rules.',
    score: 1,
  };
}

// Cross-Origin-Resource-Policy (CORP)
function checkCorp(value) {
  const raw = (value || '').trim();
  const lower = raw.toLowerCase();

  if (!raw) {
    return {
      name: 'Cross-Origin-Resource-Policy',
      status: 'weak',
      message:
        'Cross-Origin-Resource-Policy is present but empty or malformed, so cross-origin fetch restrictions may not apply as intended.',
      recommendation:
        'Set Cross-Origin-Resource-Policy to same-origin or same-site for sensitive resources to reduce data exfiltration via cross-site requests.',
      score: 1,
    };
  }

  if (lower === 'same-origin' || lower === 'same-site') {
    return {
      name: 'Cross-Origin-Resource-Policy',
      status: 'ok',
      message: `Cross-Origin-Resource-Policy is set to ${raw}, restricting which sites may load the resource.`,
      recommendation:
        'Ensure CORP is applied consistently to resources that should not be embeddable from arbitrary origins.',
      score: 2,
    };
  }

  if (lower === 'cross-origin') {
    return {
      name: 'Cross-Origin-Resource-Policy',
      status: 'weak',
      message:
        'Cross-Origin-Resource-Policy is set to cross-origin, which allows any site to load this resource.',
      recommendation:
        'Use same-origin or same-site where feasible for sensitive resources that should not be freely embeddable.',
      score: 1,
    };
  }

  // Unknown/custom value
  return {
    name: 'Cross-Origin-Resource-Policy',
    status: 'weak',
    message: `Cross-Origin-Resource-Policy is set to ${raw}, which is not a common value and may not provide the intended restrictions.`,
    recommendation:
      'Prefer same-origin or same-site for CORP unless you have a deliberate need for wider exposure.',
    score: 1,
  };
}

// Feature-Policy (deprecated)
// Only report if present; missing is fine (Permissions-Policy replaces it)
function checkFeaturePolicy() {
  return {
    name: 'Feature-Policy (deprecated)',
    status: 'weak',
    message:
      'Feature-Policy header is present but this mechanism is deprecated in modern browsers.',
    recommendation:
      'Migrate from Feature-Policy to Permissions-Policy with equivalent or stricter feature restrictions.',
    score: 1,
  };
}

// X-XSS-Protection (legacy)
// Only report if present; missing is fine (CSP is preferred)
function checkXssProtection(value) {
  const raw = (value || '').trim();
  const lower = raw.toLowerCase();

  if (!raw) {
    return {
      name: 'X-XSS-Protection (legacy)',
      status: 'weak',
      message:
        'X-XSS-Protection header is present but empty or malformed. This legacy mechanism is unreliable and largely deprecated.',
      recommendation:
        'Prefer a strong Content-Security-Policy instead of relying on legacy X-XSS-Protection filters.',
      score: 1,
    };
  }

  if (lower.startsWith('1;') && lower.includes('mode=block')) {
    return {
      name: 'X-XSS-Protection (legacy)',
      status: 'ok',
      message:
        'X-XSS-Protection is set to 1; mode=block. This may provide limited protection in older browsers, but is deprecated overall.',
      recommendation:
        'Maintain a strong CSP and consider eventually removing X-XSS-Protection once you no longer rely on legacy browsers.',
      score: 1,
    };
  }

  if (lower === '0') {
    return {
      name: 'X-XSS-Protection (legacy)',
      status: 'weak',
      message:
        'X-XSS-Protection is explicitly disabled (0). In modern browsers this header is ignored, but older engines may not apply any XSS filter.',
      recommendation:
        'Rely on Content-Security-Policy for XSS mitigation; if you keep this header, prefer 1; mode=block or remove it entirely.',
      score: 1,
    };
  }

  // Any other value -> treat as weak / unclear
  return {
    name: 'X-XSS-Protection (legacy)',
    status: 'weak',
    message: `X-XSS-Protection is set to "${raw}", which is non-standard and may not behave as expected.`,
    recommendation:
      'Use a well-formed value like 1; mode=block if you must support legacy browsers and rely primarily on CSP for modern XSS protection.',
    score: 1,
  };
}

// Analyze Set-Cookie headers from the raw header text
// This does not affect the numeric score, only produces an extra finding
function analyzeSetCookieHeaders(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return [];
  }

  const lines = rawText.split(/\r?\n/);
  const cookieStrings = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const match = trimmed.match(/^set-cookie\s*:(.*)$/i);
    if (match && match[1]) {
      cookieStrings.push(match[1].trim());
    }
  }

  if (cookieStrings.length === 0) {
    return [];
  }

  let total = 0;
  let missingSecure = 0;
  let missingHttpOnly = 0;
  let missingSameSite = 0;
  let sameSiteNoneWithoutSecure = 0;
  let strongCookies = 0;
  let domainScopedCookies = 0;
  let rootPathCookies = 0;

  for (const cookie of cookieStrings) {
    total += 1;

    const parts = cookie.split(';').map((p) => p.trim()).filter(Boolean);
    if (parts.length === 0) continue;

    const attrs = parts.slice(1).map((p) => p.toLowerCase());

    const hasSecure = attrs.some((p) => p === 'secure');
    const hasHttpOnly = attrs.some((p) => p === 'httponly');
    const sameSiteAttr = attrs.find((p) => p.startsWith('samesite='));
    const domainAttr = attrs.find((p) => p.startsWith('domain='));
    const pathAttr = attrs.find((p) => p.startsWith('path='));

    let sameSiteValue = null;
    if (sameSiteAttr) {
      const eqIndex = sameSiteAttr.indexOf('=');
      if (eqIndex !== -1) {
        sameSiteValue = sameSiteAttr.slice(eqIndex + 1).trim();
      }
    }

    if (!hasSecure) missingSecure += 1;
    if (!hasHttpOnly) missingHttpOnly += 1;
    if (!sameSiteValue) missingSameSite += 1;
    if (sameSiteValue && sameSiteValue === 'none' && !hasSecure) {
      sameSiteNoneWithoutSecure += 1;
    }

    if (
      hasSecure &&
      hasHttpOnly &&
      sameSiteValue &&
      (sameSiteValue === 'strict' || sameSiteValue === 'lax')
    ) {
      strongCookies += 1;
    }

    if (domainAttr) {
      domainScopedCookies += 1;
    }

    if (pathAttr) {
      const eqIndex = pathAttr.indexOf('=');
      const pathValue =
        eqIndex !== -1 ? pathAttr.slice(eqIndex + 1).trim() : '';
      if (pathValue === '/') {
        rootPathCookies += 1;
      }
    }
  }

  const details = [];
  if (missingSecure > 0) {
    details.push(
      `${missingSecure} cookie(s) missing the Secure flag (transmitted over plain HTTP if used on non-HTTPS origins).`
    );
  }
  if (missingHttpOnly > 0) {
    details.push(
      `${missingHttpOnly} cookie(s) missing the HttpOnly flag, making them accessible to JavaScript and increasing XSS impact.`
    );
  }
  if (missingSameSite > 0) {
    details.push(
      `${missingSameSite} cookie(s) without an explicit SameSite attribute, relying on browser defaults.`
    );
  }
  if (sameSiteNoneWithoutSecure > 0) {
    details.push(
      `${sameSiteNoneWithoutSecure} cookie(s) use SameSite=None without Secure, which is rejected by modern browsers and weakens CSRF protections.`
    );
  }
  if (strongCookies > 0) {
    details.push(
      `${strongCookies} cookie(s) already use a strong combination of Secure + HttpOnly + SameSite=Strict/Lax.`
    );
  }
  if (domainScopedCookies > 0) {
    details.push(
      `${domainScopedCookies} cookie(s) use a Domain attribute, making them valid across subdomains of that domain.`
    );
  }
  if (rootPathCookies > 0) {
    details.push(
      `${rootPathCookies} cookie(s) are scoped to the root path '/', so they will be sent on all paths for that origin.`
    );
  }

  const messageParts = [];
  messageParts.push(`Analyzed ${total} Set-Cookie header(s).`);
  if (details.length > 0) {
    messageParts.push(details.join(' '));
  } else {
    messageParts.push(
      'All analyzed cookies appear to set Secure, HttpOnly and an explicit SameSite attribute.'
    );
  }

  const anyWeak =
    missingSecure > 0 ||
    missingHttpOnly > 0 ||
    missingSameSite > 0 ||
    sameSiteNoneWithoutSecure > 0;

  const status = anyWeak ? 'weak' : 'ok';

  const recommendation =
    'Ensure sensitive cookies are set with Secure, HttpOnly and an explicit SameSite attribute (Strict or Lax for session cookies). Avoid SameSite=None without Secure. For highly sensitive cookies, also review Domain and Path scopes to avoid unnecessary exposure across subdomains or paths.';

  return [
    {
      name: 'Set-Cookie security flags',
      status,
      message: messageParts.join(' '),
      recommendation,
      score: anyWeak ? 1 : 2,
    },
  ];
}

/**
 * Main entrypoint: analyze headers string for security posture.
 *
 * @param {string} rawText
 * @returns {{
 *   overallScore: number,
 *   overallLabel: "Hardened" | "Partially hardened" | "Exposed",
 *   overallMessage: string,
 *   headerFindings: Array<{
 *     name: string,
 *     status: "ok" | "weak" | "missing",
 *     message: string,
 *     recommendation: string,
 *     score: 0 | 1 | 2
 *   }>
 * }}
 */
export function analyzeHeaders(rawText) {
  const headers = parseRawHeaders(rawText);
  const statusCode = extractStatusCode(rawText);

  // Core headers that feed into the numeric score
  const coreRules = [
    {
      key: 'content-security-policy',
      displayName: 'Content-Security-Policy',
      description:
        'It defines which sources are allowed for scripts, styles and other content.',
      recommendation:
        'Add a Content-Security-Policy header to reduce XSS and injection risks.',
      checker: checkCsp,
    },
    {
      key: 'strict-transport-security',
      displayName: 'Strict-Transport-Security',
      description:
        'It enforces HTTPS by telling browsers to never downgrade connections to HTTP.',
      recommendation:
        'Add a Strict-Transport-Security header with a strong max-age and includeSubDomains.',
      checker: checkHsts,
    },
    {
      key: 'x-frame-options',
      displayName: 'X-Frame-Options',
      description:
        'It controls whether your pages can be embedded in iframes, mitigating clickjacking.',
      recommendation:
        'Add an X-Frame-Options header set to DENY or SAMEORIGIN.',
      checker: checkXfo,
    },
    {
      key: 'x-content-type-options',
      displayName: 'X-Content-Type-Options',
      description:
        'It asks browsers not to sniff MIME types, avoiding some script injection issues.',
      recommendation:
        'Add X-Content-Type-Options: nosniff to prevent MIME-sniffing.',
      checker: checkXcto,
    },
    {
      key: 'referrer-policy',
      displayName: 'Referrer-Policy',
      description:
        'It limits how much URL information is sent in Referer headers to other sites.',
      recommendation:
        'Add a Referrer-Policy header that minimizes cross-site referrer leakage.',
      checker: checkReferrerPolicy,
    },
  ];

  // Extended / modern headers
  // These DO NOT affect the numeric score, but show as extra findings
  const extendedRules = [
    {
      key: 'permissions-policy',
      displayName: 'Permissions-Policy',
      description:
        'It restricts access to powerful browser features (camera, microphone, geolocation, etc.) on a per-origin basis.',
      recommendation:
        'Define a Permissions-Policy that disables or restricts features you do not need.',
      checker: checkPermissionsPolicy,
      optionalWhenMissing: false,
    },
    {
      key: 'cross-origin-opener-policy',
      displayName: 'Cross-Origin-Opener-Policy',
      description:
        'It controls whether the top-level document shares a browsing context group with cross-origin pages.',
      recommendation:
        'Use Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups) on security-sensitive origins.',
      checker: checkCoop,
      optionalWhenMissing: false,
    },
    {
      key: 'cross-origin-embedder-policy',
      displayName: 'Cross-Origin-Embedder-Policy',
      description:
        'It controls whether cross-origin resources must explicitly opt in before being embedded, enabling strong isolation.',
      recommendation:
        'Use Cross-Origin-Embedder-Policy: require-corp on origins that need powerful APIs and tight isolation.',
      checker: checkCoep,
      optionalWhenMissing: false,
    },
    {
      key: 'cross-origin-resource-policy',
      displayName: 'Cross-Origin-Resource-Policy',
      description:
        'It restricts which origins can load a given resource, helping to prevent data exfiltration via cross-site requests.',
      recommendation:
        'Use Cross-Origin-Resource-Policy: same-origin or same-site for sensitive resources.',
      checker: checkCorp,
      optionalWhenMissing: false,
    },
    {
      key: 'feature-policy',
      displayName: 'Feature-Policy (deprecated)',
      description:
        'Older mechanism for restricting powerful features; replaced by Permissions-Policy in modern browsers.',
      recommendation:
        'Migrate from Feature-Policy to Permissions-Policy with equivalent or stricter restrictions.',
      checker: checkFeaturePolicy,
      optionalWhenMissing: true,
    },
    {
      key: 'x-xss-protection',
      displayName: 'X-XSS-Protection (legacy)',
      description:
        'Legacy XSS filter control header, deprecated in modern Chromium-based browsers.',
      recommendation:
        'Prefer strong Content-Security-Policy instead of relying on X-XSS-Protection.',
      checker: checkXssProtection,
      optionalWhenMissing: true,
    },
  ];

  const headerFindings = [];

  // Needed for CSP special-case logic
  const hasCspReportOnly =
    typeof headers['content-security-policy-report-only'] !== 'undefined';

  // -------------------------
  // Core rules and scoring
  // -------------------------

  const maxScore = coreRules.length * 2;
  let actualScore = 0;

  for (const rule of coreRules) {
    const value = headers[rule.key];

    // Special handler when CSP-Report-Only present but enforcing CSP missing
    if (
      rule.key === 'content-security-policy' &&
      typeof value === 'undefined' &&
      hasCspReportOnly
    ) {
      const finding = {
        name: rule.displayName,
        status: 'weak',
        message:
          'Only Content-Security-Policy-Report-Only is present. Violations are reported but not blocked, so the browser does not enforce CSP.',
        recommendation:
          'Once you are comfortable with violation reports, promote the policy to an enforcing Content-Security-Policy header (or deploy both enforcing and report-only variants).',
        score: 1,
      };
      headerFindings.push(finding);
      actualScore += finding.score;
      continue;
    }

    if (typeof value === 'undefined') {
      const finding = missingHeaderFinding(
        rule.displayName,
        rule.description,
        rule.recommendation
      );
      headerFindings.push(finding);
    } else {
      const finding = rule.checker(value);
      headerFindings.push(finding);
      if (typeof finding.score === 'number') {
        actualScore += finding.score;
      }
    }
  }

  // -------------------------
  // Extended rules (no score)
  // -------------------------

  for (const rule of extendedRules) {
    const value = headers[rule.key];

    if (typeof value === 'undefined') {
      if (rule.optionalWhenMissing) {
        continue;
      }

      headerFindings.push(
        missingHeaderFinding(
          rule.displayName,
          rule.description,
          rule.recommendation
        )
      );
      continue;
    }

    headerFindings.push(rule.checker(value));
  }

  // -------------------------
  // Cookie security analysis (no score)
  // -------------------------

  const cookieFindings = analyzeSetCookieHeaders(rawText);
  if (cookieFindings.length > 0) {
    headerFindings.push(...cookieFindings);
  }

  // -------------------------
  // Overall score + label
  // -------------------------

  const overallScore =
    maxScore > 0 ? Math.round((actualScore / maxScore) * 100) : 0;

  let overallLabel = 'Exposed';
  let overallMessage =
    'Browser-side hardening headers are largely missing. This increases the risk of XSS, clickjacking and downgrade attacks.';

  if (overallScore >= 85) {
    overallLabel = 'Hardened';
    overallMessage =
      'Most core browser security headers are present and reasonably configured. Continue to review them as the application evolves.';
  } else if (overallScore >= 60) {
    overallLabel = 'Partially hardened';
    overallMessage =
      'Some important security headers are in place, but there are gaps or weak configurations that attackers could chain into an exploit.';
  }

  // Context if this appears to be a redirect response
  if (statusCode && statusCode >= 300 && statusCode < 400) {
    overallMessage +=
      ` Note: this looks like a redirect response (HTTP ${statusCode}), which often omits many security headers. ` +
      'For a fuller picture of browser-side hardening, also analyze the final 200 OK response.';
  }

  return {
    overallScore,
    overallLabel,
    overallMessage,
    headerFindings,
  };
}
