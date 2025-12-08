/**
 * HTML client-side security audit (heuristic).
 * Flags inline JS/CSS, unsafe forms, mixed content, javascript: URLs,
 * iframes, comments with secrets and other browser-side smells
 *
 * @param {string} rawHtml
 * @returns {{
 *   riskLevel: "low" | "moderate" | "elevated",
 *   overview: string,
 *   issues: Array<{
 *     type: string,
 *     severity: "low" | "medium" | "high",
 *     title: string,
 *     detail: string,
 *     recommendation?: string,
 *     snippet?: string
 *   }>,
 *   stats: {
 *     scriptBlockCount: number,
 *     inlineScriptChars: number,
 *     inlineEventHandlers: number,
 *     formCount: number,
 *     httpResourceCount: number
 *   }
 * }}
 */
export function analyzeHtmlSecurity(rawHtml) {
  const html = typeof rawHtml === 'string' ? rawHtml : '';
  const issues = [];

  function addIssue({ type, severity, title, detail, recommendation, snippet }) {
    issues.push({
      type,
      severity,
      title,
      detail,
      recommendation: recommendation || '',
      snippet: snippet
        ? snippet.trim().slice(0, 600)
        : '',
    });
  }

  // -----------------------------
  // Basic stats: scripts, forms, http resources
  // -----------------------------

  let scriptBlockCount = 0;
  let inlineScriptChars = 0;

  const scriptBlockRegex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let blockMatch;
  while ((blockMatch = scriptBlockRegex.exec(html)) !== null) {
    scriptBlockCount++;
    const attrs = blockMatch[1] || '';
    const inner = blockMatch[2] || '';

    // Inline script (no src attribute)
    if (!/\bsrc\s*=\s*["'][^"']+["']/i.test(attrs)) {
      inlineScriptChars += inner.length;
    }

    // Source map hints
    if (/\.map["']/i.test(attrs) || /sourceMappingURL\s*=/i.test(inner)) {
      addIssue({
        type: 'source-map',
        severity: 'low',
        title: 'JavaScript source map reference found',
        detail:
          'This page references a JavaScript source map. If the map is publicly accessible, it may reveal original source code, comments or paths.',
        recommendation:
          'Ensure source maps exposed in production do not contain sensitive comments, credentials or internal-only paths. Consider restricting or stripping them in hardened builds.',
        snippet: `<script${attrs}>...`,
      });
    }
  }

  // Inline <style> blocks and style="" attributes
  let styleBlockCount = 0;
  let inlineStyleCharsTotal = 0;

  const styleBlockRegex = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;
  let styleBlockMatch;
  while ((styleBlockMatch = styleBlockRegex.exec(html)) !== null) {
    styleBlockCount++;
    inlineStyleCharsTotal += (styleBlockMatch[1] || '').length;
  }

  const inlineStyleAttrRegex = /\sstyle\s*=\s*["'][^"']*["']/gi;
  const inlineStyleAttrMatches = html.match(inlineStyleAttrRegex) || [];
  const inlineStyleAttrCount = inlineStyleAttrMatches.length;

  if (styleBlockCount > 0 || inlineStyleAttrCount > 0) {
    const cssKb = Math.round(inlineStyleCharsTotal / 1024);
    const severity =
      inlineStyleCharsTotal > 60000 || inlineStyleAttrCount > 80
        ? 'medium'
        : 'low';

    const isSignificant =
      inlineStyleCharsTotal > 4096 || inlineStyleAttrCount > 10;

    const title = isSignificant
      ? 'Significant amount of inline CSS'
      : 'Inline CSS in markup';

    const detail = isSignificant
      ? `Detected ${styleBlockCount} <style> block(s) and ${inlineStyleAttrCount} style="..." attribute(s) (~${cssKb} KB total CSS). Heavy inline CSS can make it harder to enforce strict style-src CSP and to audit styling changes.`
      : `Detected ${styleBlockCount} <style> block(s) and ${inlineStyleAttrCount} style="..." attribute(s). Inline CSS can make it harder to enforce a strict style-src CSP and to keep presentation logic separate.`;

    addIssue({
      type: 'inline-styles',
      severity,
      title,
      detail,
      recommendation:
        'Where possible, move inline styles into CSS files or modules and avoid requiring unsafe-inline in your style-src CSP.',
    });
  }

  // Count forms (for stats)
  const formMatches = html.match(/<form\b[^>]*>/gi) || [];
  const formCount = formMatches.length;

  // External http:// resources (potential mixed-content / downgrade hint)
  const httpResourceRegex =
    /\b(?:src|href)\s*=\s*["']http:\/\/([^"']+)["']/gi;
  let httpMatch;
  let httpResourceCount = 0;
  const httpResourceSnippets = [];
  while ((httpMatch = httpResourceRegex.exec(html)) !== null) {
    httpResourceCount++;
    if (httpResourceSnippets.length < 5) {
      httpResourceSnippets.push(httpMatch[0]);
    }
  }

  if (httpResourceCount > 0) {
    addIssue({
      type: 'mixed-content',
      severity: 'high',
      title: 'Insecure HTTP resource reference',
      detail:
        `The HTML references ${httpResourceCount} external resource(s) over plain HTTP. If this page is served over HTTPS, that creates a mixed-content or downgrade risk.`,
      recommendation:
        'Serve external assets over HTTPS where possible. Avoid loading active content (scripts, iframes) from plain HTTP origins on HTTPS pages.',
      snippet: httpResourceSnippets.join('\n'),
    });
  }

  // -----------------------------
  // Inline event handlers
  // -----------------------------

  // onClick=, onload=, onmouseover=, etc.
  const inlineHandlerRegex = /\son[a-z]+\s*=\s*["'][^"']*["']/gi;
  const inlineHandlerMatches = html.match(inlineHandlerRegex) || [];
  const inlineEventHandlers = inlineHandlerMatches.length;

  if (inlineEventHandlers > 0) {
    const severity =
      inlineEventHandlers > 25 ? 'high' : inlineEventHandlers > 5 ? 'medium' : 'low';

    addIssue({
      type: 'inline-events',
      severity,
      title: 'Inline JavaScript event handlers in markup',
      detail:
        `Detected ${inlineEventHandlers} inline event handler attribute(s) (onclick=, onload=, etc.). Inline JS makes it harder to enforce strong CSP and can increase XSS risk.`,
      recommendation:
        'Prefer unobtrusive JavaScript: bind event listeners from JS files instead of inline handlers. This also makes it easier to adopt a strict Content-Security-Policy without unsafe-inline.',
      snippet: inlineHandlerMatches.slice(0, 5).join('\n'),
    });
  }

  // -----------------------------
  // Inline script payloads
  // -----------------------------

  if (inlineScriptChars > 0) {
    const inlineKb = Math.round(inlineScriptChars / 1024);
    const severity =
      inlineScriptChars > 120000
        ? 'high'
        : inlineScriptChars > 20000
        ? 'medium'
        : 'low';

    const isSignificant = inlineScriptChars > 4096;

    const title = isSignificant
      ? 'Significant amount of inline JavaScript'
      : 'Inline JavaScript present';

    const detail = isSignificant
      ? `Estimated inline JavaScript size is ~${inlineKb} KB. Large inline JS blobs make it harder to audit and to enforce CSP without unsafe-inline.`
      : `Estimated inline JavaScript size is ~${inlineKb} KB. Inline JS can make it harder to adopt a strict Content-Security-Policy without unsafe-inline, especially as the application grows.`;

    addIssue({
      type: 'inline-scripts',
      severity,
      title,
      detail,
      recommendation:
        'Where possible, move inline scripts into external JS bundles and use nonces or hashes under a strict Content-Security-Policy.',
    });
  }

  // -----------------------------
  // Forms: passwords + GET / http action
  // -----------------------------

  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let formMatch;

  let passwordGetCount = 0;
  let sensitiveGetCount = 0;
  let httpActionPasswordCount = 0;
  let httpActionNonPasswordCount = 0;

  const passwordGetSnippets = [];
  const sensitiveGetSnippets = [];
  const httpActionSnippets = [];

  while ((formMatch = formRegex.exec(html)) !== null) {
    const formAttrs = formMatch[1] || '';
    const formInner = formMatch[2] || '';
    const formAttrsLower = formAttrs.toLowerCase();

    // Extract method + action
    const methodMatch = formAttrsLower.match(/\bmethod\s*=\s*["']([^"']+)["']/);
    const actionMatch = formAttrsLower.match(/\baction\s*=\s*["']([^"']+)["']/);

    const method = methodMatch ? methodMatch[1].trim() : ''; // GET default
    const action = actionMatch ? actionMatch[1].trim() : '';

    const hasPasswordField = /<input\b[^>]*type=["']password["']/i.test(
      formInner
    );

    const hasSensitiveName =
      /\b(name|id)\s*=\s*["'](?:password|passwd|pass|token|api[_-]?key|secret)["']/i.test(
        formInner
      );

    const isGetLike =
      !method || method === '' || method.toLowerCase() === 'get';

    const isHttpAction =
      action.toLowerCase().startsWith('http://');

    // Password + GET
    if (hasPasswordField && isGetLike) {
      passwordGetCount++;
      if (passwordGetSnippets.length < 3) {
        passwordGetSnippets.push(`<form${formAttrs}>...</form>`);
      }
    }

    // Sensitive names + GET
    if (!hasPasswordField && hasSensitiveName && isGetLike) {
      sensitiveGetCount++;
      if (sensitiveGetSnippets.length < 3) {
        sensitiveGetSnippets.push(`<form${formAttrs}>...</form>`);
      }
    }

    // HTTP action for forms
    if (isHttpAction) {
      if (hasPasswordField) {
        httpActionPasswordCount++;
      } else {
        httpActionNonPasswordCount++;
      }

      if (httpActionSnippets.length < 3) {
        httpActionSnippets.push(`<form${formAttrs}>...</form>`);
      }
    }
  }

  if (passwordGetCount > 0) {
    addIssue({
      type: 'form-password-get',
      severity: 'high',
      title: 'Password form submitted with GET or default method',
      detail:
        `Detected ${passwordGetCount} form(s) containing a password field using GET (or no explicit method), which can leak credentials via URL, logs and referrer headers.`,
      recommendation:
        'Use method="POST" for login and password forms. Avoid putting credentials or secrets in URL query strings.',
      snippet: passwordGetSnippets.join('\n'),
    });
  }

  if (sensitiveGetCount > 0) {
    addIssue({
      type: 'form-sensitive-get',
      severity: 'medium',
      title: 'Form with sensitive parameter using GET',
      detail:
        `Detected ${sensitiveGetCount} form(s) with fields named like password/token/api_key/secret using GET (or no explicit method), which may leak secrets in URLs.`,
      recommendation:
        'Prefer POST for forms carrying tokens or secrets. Carefully validate which data is placed in query strings.',
      snippet: sensitiveGetSnippets.join('\n'),
    });
  }

  const httpActionTotal = httpActionPasswordCount + httpActionNonPasswordCount;

  if (httpActionTotal > 0) {
    const severity =
      httpActionPasswordCount > 0 ? 'high' : 'medium';

    addIssue({
      type: 'form-http-action',
      severity,
      title: 'Form submits to an HTTP endpoint',
      detail:
        `Detected ${httpActionTotal} form(s) whose action points to a plain HTTP URL, including ${httpActionPasswordCount} with password fields. If used for authentication or sensitive data, this exposes contents to interception.`,
      recommendation:
        'Prefer HTTPS form actions. Avoid sending credentials or sensitive data to HTTP endpoints.',
      snippet: httpActionSnippets.join('\n'),
    });
  }

  // -----------------------------
  // Embedded frames and widgets
  // -----------------------------

  const iframeRegex = /<iframe\b([^>]*?)>/gi;
  let iframeMatch;
  let iframeCount = 0;
  let iframeSandboxedCount = 0;
  const iframeSnippets = [];

  while ((iframeMatch = iframeRegex.exec(html)) !== null) {
    iframeCount++;
    const attrs = iframeMatch[1] || '';
    const attrsLower = attrs.toLowerCase();

    if (/\bsandbox\b/.test(attrsLower)) {
      iframeSandboxedCount++;
    }

    if (iframeSnippets.length < 5) {
      iframeSnippets.push(`<iframe${attrs}>`);
    }
  }

  const embedRegex = /<(?:embed|object)\b([^>]*?)>/gi;
  let embedMatch;
  let embedObjectCount = 0;

  while ((embedMatch = embedRegex.exec(html)) !== null) {
    embedObjectCount++;
    if (iframeSnippets.length < 5) {
      iframeSnippets.push(embedMatch[0]);
    }
  }

  const totalEmbedded = iframeCount + embedObjectCount;

  if (totalEmbedded > 0) {
    const unsandboxed = iframeCount - iframeSandboxedCount;
    const severity =
      unsandboxed > 5 || totalEmbedded > 10
        ? 'medium'
        : 'low';

    addIssue({
      type: 'iframes-embeds',
      severity,
      title: 'Embedded frames and widgets in markup',
      detail:
        `Detected ${totalEmbedded} embedded frame/widget element(s) (${iframeCount} iframe(s), ${embedObjectCount} embed/object).` +
        (unsandboxed > 0
          ? ` ${unsandboxed} iframe(s) appear without a sandbox attribute.`
          : '') +
        ' Embedded content increases client-side attack surface and may pull in third-party code.',
      recommendation:
        'Audit embedded frames and widgets. Use sandbox and restrictive permissions where possible and avoid embedding untrusted origins.',
      snippet: iframeSnippets.join('\n'),
    });
  }

  // -----------------------------
  // target="_blank" without rel="noopener"/"noreferrer"
  // -----------------------------

  const anchorRegex = /<a\b([^>]*?)>/gi;
  let anchorMatch;
  let targetBlankNoNoopenerCount = 0;
  const targetBlankSnippets = [];

  while ((anchorMatch = anchorRegex.exec(html)) !== null) {
    const attrs = anchorMatch[1] || '';
    const attrsLower = attrs.toLowerCase();

    if (!/\btarget\s*=\s*["']?_blank["']?/i.test(attrsLower)) continue;

    const relMatch = attrsLower.match(/\brel\s*=\s*["']([^"']*)["']/i);
    const relVal = relMatch ? relMatch[1] : '';

    const hasNoopener = relVal.includes('noopener');
    const hasNoreferrer = relVal.includes('noreferrer');

    if (hasNoopener || hasNoreferrer) continue;

    targetBlankNoNoopenerCount++;
    if (targetBlankSnippets.length < 5) {
      targetBlankSnippets.push(`<a${attrs}>`);
    }
  }

  if (targetBlankNoNoopenerCount > 0) {
    const severity =
      targetBlankNoNoopenerCount > 20
        ? 'high'
        : targetBlankNoNoopenerCount > 5
        ? 'medium'
        : 'low';

    addIssue({
      type: 'target-blank-noopener',
      severity,
      title: 'target="_blank" links without rel="noopener"',
      detail:
        `Detected ${targetBlankNoNoopenerCount} link(s) using target="_blank" without rel="noopener" or rel="noreferrer". This can allow the opened page to manipulate the opener tab via window.opener.`,
      recommendation:
        'Add rel="noopener" (and optionally rel="noreferrer") to links that open in a new tab to prevent tabnabbing and limit cross-window access.',
      snippet: targetBlankSnippets.join('\n'),
    });
  }

  // -----------------------------
  // Meta http-equiv="refresh"
  // -----------------------------

  const metaRefreshRegex =
    /<meta\b[^>]*http-equiv\s*=\s*["']refresh["'][^>]*>/gi;
  let metaMatch;
  let metaRefreshCount = 0;
  const metaRefreshSnippets = [];

  while ((metaMatch = metaRefreshRegex.exec(html)) !== null) {
    metaRefreshCount++;
    if (metaRefreshSnippets.length < 5) {
      metaRefreshSnippets.push(metaMatch[0]);
    }
  }

  if (metaRefreshCount > 0) {
    addIssue({
      type: 'meta-refresh',
      severity: 'medium',
      title: 'Meta refresh redirect in HTML',
      detail:
        `Detected ${metaRefreshCount} <meta http-equiv="refresh"> tag(s). Meta refresh redirects can be used for UX tricks or phishing-style flows and may surprise users.`,
      recommendation:
        'Avoid using meta refresh for critical redirects. Prefer server-side redirects or explicit client-side navigation logic under your control.',
      snippet: metaRefreshSnippets.join('\n'),
    });
  }

  // -----------------------------
  // javascript: URLs in href/src
  // -----------------------------

  const jsUrlRegex =
    /\b(?:href|src)\s*=\s*["']\s*javascript:[^"']*["']/gi;
  let jsUrlMatch;
  let jsUrlCount = 0;
  const jsUrlSnippets = [];

  while ((jsUrlMatch = jsUrlRegex.exec(html)) !== null) {
    jsUrlCount++;
    if (jsUrlSnippets.length < 5) {
      jsUrlSnippets.push(jsUrlMatch[0]);
    }
  }

  if (jsUrlCount > 0) {
    const severity =
      jsUrlCount > 10 ? 'high' : jsUrlCount > 3 ? 'medium' : 'low';

    addIssue({
      type: 'javascript-url',
      severity,
      title: 'javascript: URLs in markup',
      detail:
        `Detected ${jsUrlCount} javascript: URL(s) in href/src attributes. These can be an XSS smell and are difficult to lock down with CSP.`,
      recommendation:
        'Avoid using javascript: URLs in anchors or other elements. Prefer normal links and bind behavior via JavaScript event listeners instead.',
      snippet: jsUrlSnippets.join('\n'),
    });
  }

  // -----------------------------
  // Links with very long / parameter-heavy query strings
  // -----------------------------

  const longQueryLinkRegex =
    /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let hrefMatch;
  let longQueryCount = 0;
  const longQuerySnippets = [];

  while ((hrefMatch = longQueryLinkRegex.exec(html)) !== null) {
    const href = hrefMatch[1];
    if (!href) continue;

    try {
      const url = new URL(href, 'https://example.com');
      const query = url.search || '';
      if (!query) continue;

      const queryLength = query.length;
      const paramCount = (query.match(/&/g) || []).length + 1;

      if (queryLength > 200 || paramCount > 8) {
        longQueryCount++;
        if (longQuerySnippets.length < 5) {
          longQuerySnippets.push(hrefMatch[0]);
        }
      }
    } catch {
      // ignore invalid URLs
    }
  }

  if (longQueryCount > 0) {
    const severity =
      longQueryCount > 20 ? 'high' : longQueryCount > 5 ? 'medium' : 'low';

    addIssue({
      type: 'long-query-links',
      severity,
      title: 'Links with long or parameter-heavy query strings',
      detail:
        `Detected ${longQueryCount} link(s) whose href contains a very long or parameter-heavy query string. These can sometimes indicate IDs, tokens or other sensitive data being passed in URLs.`,
      recommendation:
        'Review long query strings for exposure of identifiers, tokens or secrets. Where possible, move sensitive data to POST bodies or opaque server-side state.',
      snippet: longQuerySnippets.join('\n'),
    });
  }

  // -----------------------------
  // Comments with potentially sensitive hints
  // -----------------------------

  const commentRegex = /<!--([\s\S]*?)-->/g;
  let commentMatch;
  let sensitiveCommentCount = 0;
  const commentSnippets = [];

  while ((commentMatch = commentRegex.exec(html)) !== null) {
    const commentBody = commentMatch[1] || '';
    const commentLower = commentBody.toLowerCase();

    if (
      commentLower.includes('todo') ||
      commentLower.includes('fixme') ||
      commentLower.includes('password') ||
      commentLower.includes('secret') ||
      commentLower.includes('api key') ||
      commentLower.includes('apikey') ||
      commentLower.includes('token')
    ) {
      sensitiveCommentCount++;
      if (commentSnippets.length < 3) {
        commentSnippets.push(
          `<!--${commentBody.trim().slice(0, 280)}-->`
        );
      }
    }
  }

  if (sensitiveCommentCount > 0) {
    addIssue({
      type: 'comments',
      severity: 'medium',
      title: 'HTML comments with potentially sensitive or debug info',
      detail:
        `Found ${sensitiveCommentCount} HTML comment(s) containing TODO/FIXME notes or terms like password/secret/token. Comments can leak implementation details or hints to attackers if not scrubbed.`,
      recommendation:
        'Avoid shipping internal debug comments or hints about credentials to production. Review comments for sensitive information.',
      snippet: commentSnippets.join('\n'),
    });
  }

  // -----------------------------
  // Compute risk score -> riskLevel + overview
  // -----------------------------

  let score = 0;

  for (const issue of issues) {
    if (issue.severity === 'high') score += 3;
    else if (issue.severity === 'medium') score += 2;
    else score += 1;
  }

  let riskLevel = 'low';
  if (score >= 7) riskLevel = 'elevated';
  else if (score >= 3) riskLevel = 'moderate';

  // Special-case: pages with no scripts and no http:// resources are likely simpler
  const hasScripts = scriptBlockCount > 0;
  const hasThirdPartyHttp = httpResourceCount > 0;

  if (!hasScripts && !hasThirdPartyHttp && issues.length === 0) {
    riskLevel = 'low';
    issues.push({
      type: 'minimal-page',
      severity: 'low',
      title: 'Minimal client-side surface',
      detail:
        'Minimal scripting and no insecure HTTP resources detected, suggesting a simpler attack surface on the client side.',
      recommendation:
        'Continue to validate inputs server-side and keep the HTML minimal where possible.',
    });
  }

  const stats = {
    scriptBlockCount,
    inlineScriptChars,
    inlineEventHandlers: inlineEventHandlers,
    formCount,
    httpResourceCount,
  };

  const overviewParts = [];

  overviewParts.push(
    `Estimated ${scriptBlockCount} <script> block(s), ${formCount} form(s) and ${httpResourceCount} http:// resource reference(s).`
  );

  if (issues.length === 0) {
    overviewParts.push(
      'No obvious client-side security smells were detected from HTML alone, but this does not guarantee the absence of vulnerabilities.'
    );
  } else {
    overviewParts.push(
      `${issues.length} potential issue(s) or risk factor(s) detected in the markup.`
    );
  }

  const overview = overviewParts.join(' ');

  return {
    riskLevel,
    overview,
    issues,
    stats,
  };
}
