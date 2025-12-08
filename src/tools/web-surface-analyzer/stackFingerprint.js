/**
 * HTML tech stack fingerprinting.
 * Detects CMS, JS frameworks, hosting/CDNs, analytics, backend hints
 * and computes a simple exposure profile
 *
 * @param {string} rawHtml
 * @returns {{
 *   summary: string,
 *   techFindings: Array,
 *   exposureLevel: "low" | "moderate" | "elevated",
 *   exposureFactors: string[]
 * }}
 */
export function analyzeHtmlForStack(rawHtml) {
  const html = typeof rawHtml === 'string' ? rawHtml : '';
  const lower = html.toLowerCase();

  const techFindings = [];

  function hasFinding(category, label) {
    return techFindings.some(
      (f) => f.category === category && f.label === label
    );
  }

  function addFinding(category, label, confidence, evidence) {
    if (!evidence) return;
    if (hasFinding(category, label)) return;
    techFindings.push({ category, label, evidence, confidence });
  }

  function applyHintPatterns(patterns) {
    for (const hint of patterns) {
      try {
        if (hint.test(html, lower)) {
          addFinding(
            hint.category,
            hint.label,
            hint.confidence,
            hint.evidence
          );
        }
      } catch {
        // Defensive
      }
    }
  }

  // -----------------------------
  // Basic script/app-shell stats
  // -----------------------------

  let scriptBlockCount = 0;
  let inlineScriptChars = 0;

  const scriptBlockRegex = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  let blockMatch;
  while ((blockMatch = scriptBlockRegex.exec(html)) !== null) {
    scriptBlockCount++;

    const openingTag = blockMatch[0].slice(
      0,
      blockMatch[0].indexOf('>') + 1
    );
    if (!/src=["']?[^"']+["']?/i.test(openingTag)) {
      const inner = blockMatch[1] || '';
      inlineScriptChars += inner.length;
    }
  }

  const hasAppRoot =
    /<div[^>]+id=["'](root|app|__next)["'][^>]*>/i.test(html);

  // -----------------------------
  // CMS detection
  // -----------------------------

  // WordPress
  if (lower.includes('wp-content/') || lower.includes('wp-includes')) {
    addFinding(
      'CMS',
      'WordPress',
      'high',
      "Found 'wp-content/' or 'wp-includes' path in HTML."
    );
  }
  if (
    lower.includes('meta name="generator" content="wordpress') ||
    lower.includes("meta name='generator' content='wordpress")
  ) {
    addFinding(
      'CMS',
      'WordPress',
      'high',
      'Meta generator tag indicates WordPress.'
    );
  }
  if (lower.includes('wp-json')) {
    addFinding(
      'CMS',
      'WordPress',
      'medium',
      "Found 'wp-json' API path, commonly exposed by WordPress."
    );
  }

  // Drupal
  if (
    lower.includes('drupal.settings') ||
    lower.includes('sites/default/files')
  ) {
    addFinding(
      'CMS',
      'Drupal',
      'medium',
      'Found Drupal-specific paths or drupal.settings reference.'
    );
  }
  if (
    lower.includes('meta name="generator" content="drupal') ||
    lower.includes("meta name='generator' content='drupal")
  ) {
    addFinding(
      'CMS',
      'Drupal',
      'high',
      'Meta generator tag indicates Drupal.'
    );
  }

  // Joomla
  if (
    lower.includes('content="joomla!') ||
    lower.includes('/media/system/js/')
  ) {
    addFinding(
      'CMS',
      'Joomla',
      'medium',
      'Found Joomla generator meta or /media/system/js/ assets.'
    );
  }

  // -----------------------------
  // E-commerce platforms
  // -----------------------------

  // Shopify
  if (lower.includes('cdn.shopify.com') || lower.includes('myshopify.com')) {
    addFinding(
      'E-commerce',
      'Shopify',
      'high',
      'Assets loaded from cdn.shopify.com or myshopify.com.'
    );
  }

  // WooCommerce (WordPress plugin)
  if (lower.includes('woocommerce') || lower.includes('wc-cart-fragments')) {
    addFinding(
      'E-commerce',
      'WooCommerce',
      'medium',
      'WooCommerce-specific strings detected in HTML or scripts.'
    );
  }

  // -----------------------------
  // JS frameworks
  // -----------------------------

  // Next.js
  const hasNextJsFingerprint =
    html.includes('__NEXT_DATA__') ||
    html.includes('id="__next"') ||
    lower.includes('/_next/static/') ||
    lower.includes('self.__next_f.push');

  if (hasNextJsFingerprint) {
    addFinding(
      'JS Framework',
      'Next.js',
      'medium',
      'Detected __NEXT_DATA__, #__next, /_next/static/ assets or Next.js streaming runtime markers.'
    );
  }

  // Nuxt.js
  const hasNuxtFingerprint =
    html.includes('id="__nuxt"') ||
    lower.includes('id="__nuxt"') ||
    lower.includes('/_nuxt/') ||
    lower.includes('window.__nuxt=');

  if (hasNuxtFingerprint) {
    addFinding(
      'JS Framework',
      'Nuxt.js',
      'medium',
      'Detected __nuxt app root or /_nuxt/ asset paths, typical of Nuxt.js applications.'
    );
  }

  // React
  if (
    !hasNextJsFingerprint &&
    (html.includes('data-reactroot') ||
      html.includes('data-reactid') ||
      lower.includes('react.production.min.js') ||
      lower.includes('react.development.js'))
  ) {
    addFinding(
      'JS Framework',
      'React',
      'medium',
      'Found React-specific attributes or React runtime script.'
    );
  }

  // Angular / AngularJS
  if (/\sng-app(\s|=)/i.test(html) || lower.includes('angular.min.js')) {
    addFinding(
      'JS Framework',
      'AngularJS/Angular',
      'medium',
      'Detected ng-app attribute or angular.min.js.'
    );
  }

  // Vue.js
  if (
    /\sdata-v-[0-9a-f]{5}/i.test(html) ||
    lower.includes('vue.runtime.') ||
    lower.includes('vue.global.prod.js')
  ) {
    addFinding(
      'JS Framework',
      'Vue.js',
      'medium',
      'Detected Vue-specific scoped data-v-* attributes or Vue runtime scripts.'
    );
  }

  // Quasar
  const hasQuasarClasses = /\bq-(btn|card|layout|page|toolbar|drawer|input|checkbox|chip|avatar|table)\b/.test(
    html
  );
  const hasQuasarAssets =
    lower.includes('quasar.prod.css') ||
    lower.includes('quasar.esm.prod.js') ||
    lower.includes('quasar.cjs.prod.js') ||
    lower.includes('cdn.jsdelivr.net/npm/quasar') ||
    lower.includes('unpkg.com/quasar');
  const hasQuasarRoot = html.includes('id="q-app"');

  if (hasQuasarRoot || hasQuasarAssets || hasQuasarClasses) {
    addFinding(
      'JS Framework',
      'Quasar (Vue UI framework)',
      'medium',
      'Detected Quasar root (#q-app), Quasar CDN assets or q-* component classes.'
    );
  }

  // Svelte / SvelteKit
  const hasSvelteKitFingerprint =
    html.includes('data-sveltekit-hydrate') ||
    html.includes('data-sveltekit-prefetch') ||
    lower.includes('svelte-hmr-runtime');

  if (hasSvelteKitFingerprint) {
    addFinding(
      'JS Framework',
      'Svelte / SvelteKit',
      'medium',
      'Detected SvelteKit hydration markers or Svelte runtime references.'
    );
  }

  // Astro (islands + /_astro/ bundle paths)
  if (
    lower.includes('<astro-island') ||
    lower.includes('/_astro/') ||
    lower.includes('astro.render(')
  ) {
    addFinding(
      'JS Framework',
      'Astro',
      'medium',
      'Detected Astro islands markup or /_astro/ asset paths.'
    );
  }

  // Remix
  if (
    lower.includes('window.__remixmanifest') ||
    lower.includes('window.__remixroutemodules') ||
    lower.includes('window.__remixcontext')
  ) {
    addFinding(
      'JS Framework',
      'Remix (React framework)',
      'medium',
      'Detected Remix runtime globals like window.__remixManifest / window.__remixRouteModules.'
    );
  }

  // Ember.js
  if (/\bember-view\b/.test(html)) {
    addFinding(
      'JS Framework',
      'Ember.js',
      'medium',
      'Found Ember container elements with ember-view class.'
    );
  }

  // Alpine.js
  if (/<[^>]+\s(x-data|x-init|x-on:|x-model|x-show)\s*=/i.test(html)) {
    addFinding(
      'JS Framework',
      'Alpine.js',
      'medium',
      'Detected Alpine.js directives like x-data, x-init, x-on, x-model or x-show.'
    );
  }

  // jQuery (library)
  if (
    lower.includes('jquery.min.js') ||
    lower.includes('jquery.js') ||
    lower.includes('ajax.googleapis.com/ajax/libs/jquery') ||
    lower.includes('code.jquery.com/jquery-') ||
    lower.includes('cdnjs.cloudflare.com/ajax/libs/jquery')
  ) {
    addFinding(
      'JS Framework',
      'jQuery',
      'low',
      'jQuery library loaded via common CDN/script names.'
    );
  }

  // Custom SPA / JS app (fallback if no mainstream framework was identified)
  const hasKnownFramework = techFindings.some(
    (f) => f.category === 'JS Framework'
  );
  if (
    !hasKnownFramework &&
    (scriptBlockCount >= 6 || inlineScriptChars > 1000 || hasAppRoot)
  ) {
    const inlineKb = Math.round(inlineScriptChars / 1024);
    addFinding(
      'JS Framework',
      'Custom JS application / SPA',
      'low',
      `Many script tags and inline JavaScript detected (${scriptBlockCount} script blocks, ~${inlineKb} KB of inline JS), but no mainstream framework or CMS fingerprints.`
    );
  }

  // -----------------------------
  // Rendering mode (heuristic)
  // -----------------------------

  const hasServerRenderedMarkers =
    /data-server-rendered=["']true["']/i.test(html) ||
    /data-hydrate=["']true["']/i.test(html);

  // SSR/hydrated if strong SSR-ish frameworks or hydration markers
  if (
    (hasNextJsFingerprint || hasNuxtFingerprint || hasSvelteKitFingerprint) &&
    !hasFinding('Rendering', 'SSR / hydrated HTML (heuristic)')
  ) {
    addFinding(
      'Rendering',
      'SSR / hydrated HTML (heuristic)',
      'low',
      'Detected SSR-capable framework fingerprints (Next.js / Nuxt / SvelteKit) and/or hydration markers, suggesting server-rendered HTML hydrated on the client.'
    );
  } else if (
    hasServerRenderedMarkers &&
    !hasFinding('Rendering', 'SSR / hydrated HTML (heuristic)')
  ) {
    addFinding(
      'Rendering',
      'SSR / hydrated HTML (heuristic)',
      'low',
      'Detected server-rendered HTML with hydration markers (e.g. data-server-rendered / data-hydrate).'
    );
  }

  // SPA/CSR if app root + scripts but no obvious SSR markers
  if (
    hasAppRoot &&
    scriptBlockCount > 0 &&
    !hasServerRenderedMarkers &&
    !hasNextJsFingerprint &&
    !hasNuxtFingerprint &&
    !hasSvelteKitFingerprint &&
    !hasFinding('Rendering', 'Likely SPA / CSR')
  ) {
    addFinding(
      'Rendering',
      'Likely SPA / CSR',
      'low',
      'App-style root element with client-side scripts detected and no clear server-rendered markers, suggesting primarily client-side rendering.'
    );
  }

  // -----------------------------
  // Generic web platform / backend hints
  // -----------------------------

  // GitLab (SaaS or self-hosted)
  if (
    lower.includes('content="gitlab"') ||
    lower.includes('gitlab favicon') ||
    lower.includes('data-page="projects:') ||
    lower.includes('window.gon') ||
    lower.includes('gon={') ||
    lower.includes('gitlab/assets/webpack')
  ) {
    addFinding(
      'Platform',
      'GitLab',
      'medium',
      'Detected GitLab-specific meta tags, window.gon, data-page markers or GitLab asset paths.'
    );
  }

  // Webflow (site builder)
  if (
    /data-wf-page=["'][^"']+["']/i.test(html) ||
    /data-wf-site=["'][^"']+["']/i.test(html) ||
    lower.includes('webflow.js')
  ) {
    addFinding(
      'Platform',
      'Webflow',
      'medium',
      'Detected Webflow data-wf-page/site attributes or webflow.js script.'
    );
  }

  // Ruby on Rails
  if (
    lower.includes('content="ruby on rails') ||
    lower.includes('rails-ujs') ||
    (lower.includes('data-remote="true"') && lower.includes('csrf-param'))
  ) {
    addFinding(
      'Backend',
      'Ruby on Rails',
      'low',
      'Rails-style CSRF meta tags or rails-ujs helpers detected.'
    );
  }

  // Laravel
  if (lower.includes('name="csrf-token"') && lower.includes('laravel')) {
    addFinding(
      'Backend',
      'Laravel (PHP)',
      'low',
      'Laravel-style CSRF token meta tag and Laravel references detected.'
    );
  }

  // Additional backend fingerprints via hint table
  const BACKEND_HINT_PATTERNS = [
    {
      category: 'Backend',
      label: 'PHP (generic)',
      confidence: 'low',
      evidence:
        'Links/forms reference .php endpoints or PHP session identifiers, suggesting a PHP-backed application.',
      test: (html) => {
        const hasPhpEndpoints = /\b(?:href|src|action)=["'][^"'>]+\.(php)(?:[?#"'>]|$)/i.test(
          html
        );
        const hasPhpSessionField = /name=["']phpsessid["']/i.test(html);
        return hasPhpEndpoints || hasPhpSessionField;
      },
    },
    {
      category: 'Backend',
      label: 'CodeIgniter (PHP)',
      confidence: 'medium',
      evidence:
        'Detected CodeIgniter-style CSRF field name (ci_csrf_token) or generator metadata.',
      test: (html, lower) => {
        return /name=["']ci_csrf_token["']/i.test(html) ||
          lower.includes('codeigniter')
          ? true
          : false;
      },
    },
    {
      category: 'Backend',
      label: 'ASP.NET',
      confidence: 'medium',
      evidence:
        'Detected ASP.NET WebForms artifacts (aspnetForm, __VIEWSTATE / __EVENTVALIDATION or WebResource.axd/ScriptResource.axd).',
      test: (html) => {
        const hasAspNetForm = /<form[^>]+id=["']aspnetform["']/i.test(html);
        const hasAspNetViewState =
          /name=["']__viewstate["']/i.test(html) ||
          /name=["']__eventvalidation["']/i.test(html) ||
          /\/(webresource|scriptresource)\.axd\b/i.test(html);
        return hasAspNetForm || hasAspNetViewState;
      },
    },
    {
      category: 'Backend',
      label: 'Django (Python)',
      confidence: 'medium',
      evidence:
        'Detected Django-specific CSRF tokens or Django debug artifacts in the markup.',
      test: (html, lower) => {
        const hasCsrfField = /name=["']csrfmiddlewaretoken["']/i.test(html);
        const hasDebugToolbar = lower.includes('django-debug-toolbar');
        const hasAdminStatic = /\/static\/admin\/(css|js)\//i.test(lower);
        return hasCsrfField || hasDebugToolbar || hasAdminStatic;
      },
    },
  ];

  applyHintPatterns(BACKEND_HINT_PATTERNS);

  // -----------------------------
  // Hosting / CDN
  // -----------------------------

  // Cloudflare
  if (
    lower.includes('cloudflare') ||
    lower.includes('/cdn-cgi/') ||
    lower.includes('data-cf-beacon')
  ) {
    addFinding(
      'Hosting/CDN',
      'Cloudflare',
      'medium',
      'Cloudflare-related paths, scripts or data-cf-beacon attributes detected.'
    );
  }

  // Netlify
  if (lower.includes('netlify.app')) {
    addFinding(
      'Hosting/CDN',
      'Netlify',
      'low',
      'References to netlify.app detected in HTML or asset URLs.'
    );
  }

  // Vercel
  if (lower.includes('vercel.app') || lower.includes('vercel-insights')) {
    addFinding(
      'Hosting/CDN',
      'Vercel',
      'low',
      'References to vercel.app or Vercel analytics detected.'
    );
  }

  // Generic CDN markers
  if (
    lower.includes('cdn.jsdelivr.net') ||
    lower.includes('cdnjs.cloudflare.com')
  ) {
    addFinding(
      'Hosting/CDN',
      'Generic CDN',
      'low',
      'Assets loaded from common public CDNs like jsDelivr or cdnjs.'
    );
  }

  // -----------------------------
  // Analytics / tracking
  // -----------------------------

  let hasAnalytics = false;

  if (
    lower.includes('www.googletagmanager.com') ||
    lower.includes('www.google-analytics.com/analytics.js') ||
    lower.includes('gtag(')
  ) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Google Analytics / Tag Manager',
      'medium',
      'Google Tag Manager or Google Analytics scripts detected.'
    );
  }

  if (lower.includes('connect.facebook.net/en_us/fbevents.js')) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Facebook Pixel',
      'medium',
      'Facebook Pixel tracking script detected.'
    );
  }

  if (lower.includes('plausible.io/js') || lower.includes('plausible.io/api')) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Plausible Analytics',
      'medium',
      'Plausible analytics script detected.'
    );
  }

  if (lower.includes('umami.is') || lower.includes('us.umami.is')) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Umami Analytics',
      'medium',
      'Umami analytics script detected.'
    );
  }

  if (lower.includes('cdn.segment.com/analytics.js')) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Segment',
      'medium',
      'Segment analytics loader script detected.'
    );
  }

  if (lower.includes('api.mixpanel.com') || lower.includes('cdn.mxpnl.com')) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Mixpanel',
      'medium',
      'Mixpanel analytics endpoints or scripts detected.'
    );
  }

  // HubSpot tracking
  if (
    lower.includes('js.hs-analytics.net') ||
    lower.includes('js.hs-scripts.com') ||
    lower.includes('hs-script-loader')
  ) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'HubSpot tracking',
      'medium',
      'HubSpot tracking/analytics script detected (js.hs-analytics.net / js.hs-scripts.com).'
    );
  }

  // Hotjar
  if (
    lower.includes('static.hotjar.com') ||
    lower.includes('script.hotjar.com')
  ) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Hotjar',
      'medium',
      'Hotjar tracking script detected (static.hotjar.com / script.hotjar.com).'
    );
  }

  // Intercom
  if (
    lower.includes('widget.intercom.io') ||
    lower.includes('js.intercomcdn.com')
  ) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Intercom Messenger',
      'medium',
      'Intercom Messenger script detected (widget.intercom.io / js.intercomcdn.com).'
    );
  }

  // FullStory
  if (
    lower.includes('fullstory.com') ||
    lower.includes('edge.fullstory.com') ||
    lower.includes('fs.js')
  ) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'FullStory session replay',
      'medium',
      'FullStory recording script detected (fs.js / fullstory.com).'
    );
  }

  // Sentry JS SDK
  if (lower.includes('browser.sentry-cdn.com')) {
    hasAnalytics = true;
    addFinding(
      'Analytics',
      'Sentry (JS error monitoring)',
      'medium',
      'Sentry browser SDK loaded from browser.sentry-cdn.com.'
    );
  }

  // -----------------------------
  // Version / generator leakage
  // -----------------------------

  const generatorMatch = lower.match(
    /<meta\s+name=["']generator["'][^>]*content=["']([^"']+)["'][^>]*>/i
  );
  if (generatorMatch && generatorMatch[1]) {
    const generatorValue = generatorMatch[1].trim();

    if (/\d/.test(generatorValue)) {
      addFinding(
        'Metadata',
        'Exposed generator/version',
        'medium',
        `Meta generator tag exposes software and version: "${generatorValue}".`
      );
    }

     if (generatorValue.includes('hugo')) {
      addFinding(
        'Platform',
        'Hugo (static site generator)',
        'medium',
        `Meta generator tag suggests Hugo: "${generatorValue}".`
      );
    } else if (generatorValue.includes('jekyll')) {
      addFinding(
        'Platform',
        'Jekyll (static site generator)',
        'medium',
        `Meta generator tag suggests Jekyll: "${generatorValue}".`
      );
    } else if (generatorValue.includes('ghost')) {
      addFinding(
        'CMS',
        'Ghost',
        'medium',
        `Meta generator tag suggests Ghost: "${generatorValue}".`
      );
    } else if (generatorValue.includes('wix')) {
      addFinding(
        'Platform',
        'Wix',
        'medium',
        `Meta generator tag suggests Wix: "${generatorValue}".`
      );
    } else if (generatorValue.includes('squarespace')) {
      addFinding(
        'Platform',
        'Squarespace',
        'medium',
        `Meta generator tag suggests Squarespace: "${generatorValue}".`
      );
    } else if (generatorValue.includes('hubspot')) {
      // HubSpot CMS via generator
      addFinding(
        'CMS',
        'HubSpot CMS',
        'medium',
        `Meta generator tag suggests HubSpot: "${generatorValue}".`
      );
    } else if (generatorValue.includes('webflow')) {
      // Webflow via generator
      addFinding(
        'Platform',
        'Webflow',
        'medium',
        `Meta generator tag suggests Webflow: "${generatorValue}".`
      );
    } else if (generatorValue.includes('symfony')) {
      // Symfony (PHP) via generator
      addFinding(
        'Backend',
        'Symfony (PHP)',
        'medium',
        `Meta generator tag suggests Symfony: "${generatorValue}".`
      );
    } else if (generatorValue.includes('typo3')) {
      // TYPO3 CMS
      addFinding(
        'CMS',
        'TYPO3',
        'medium',
        `Meta generator tag suggests TYPO3 CMS: "${generatorValue}".`
      );
    } else if (generatorValue.includes('mediawiki')) {
      // MediaWiki
      addFinding(
        'CMS',
        'MediaWiki',
        'medium',
        `Meta generator tag suggests MediaWiki: "${generatorValue}".`
      );
    } else if (generatorValue.includes('codeigniter')) {
      // CodeIgniter via generator
      addFinding(
        'Backend',
        'CodeIgniter (PHP)',
        'medium',
        `Meta generator tag suggests CodeIgniter: "${generatorValue}".`
      );
    }
  }

  // -----------------------------
  // Third-party script domains (attack surface hint)
  // -----------------------------

  const thirdPartyDomains = new Set();
  const scriptSrcRegex = /<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;
  let match;

  while ((match = scriptSrcRegex.exec(html)) !== null) {
    const src = match[1];
    if (!src) continue;

    // Only absolute URLs or protocol-relative URLs
    if (
      src.startsWith('http://') ||
      src.startsWith('https://') ||
      src.startsWith('//')
    ) {
      try {
        const url = new URL(src.startsWith('//') ? `https:${src}` : src);
        thirdPartyDomains.add(url.hostname);
      } catch {
        // Ignore invalid URLs
      }
    }
  }

  if (thirdPartyDomains.size > 3) {
    const sampleHosts = Array.from(thirdPartyDomains).slice(0, 5);
    addFinding(
      'Third-party',
      'Multiple external script domains',
      'low',
      `More than three distinct external script domains detected (${thirdPartyDomains.size} hosts). Examples: ${sampleHosts.join(
        ', '
      )}.`
    );
  }

  // -----------------------------
  // Build summary text
  // -----------------------------

  let summary;

  if (techFindings.length === 0) {
    summary =
      'No obvious technology fingerprints were detected in the pasted HTML. The page might be minimal, heavily customized or intentionally obfuscated.';
  } else {
    const cmsLabels = uniqueLabelsForCategory(techFindings, 'CMS');
    const jsLabels = uniqueLabelsForCategory(techFindings, 'JS Framework');
    const hostingLabels = uniqueLabelsForCategory(techFindings, 'Hosting/CDN');
    const ecommerceLabels = uniqueLabelsForCategory(techFindings, 'E-commerce');
    const platformLabels = uniqueLabelsForCategory(techFindings, 'Platform');
    const backendLabels = uniqueLabelsForCategory(techFindings, 'Backend');
    const analyticsLabels = uniqueLabelsForCategory(techFindings, 'Analytics');

    const parts = [];

    if (cmsLabels.length > 0) {
      parts.push(`Likely CMS: ${cmsLabels.join(', ')}.`);
    }
    if (ecommerceLabels.length > 0) {
      parts.push(`E-commerce platform hints: ${ecommerceLabels.join(', ')}.`);
    }
    if (jsLabels.length > 0) {
      parts.push(`JavaScript framework hints: ${jsLabels.join(', ')}.`);
    }
    if (hostingLabels.length > 0) {
      parts.push(`Hosting/CDN hints: ${hostingLabels.join(', ')}.`);
    }
    if (platformLabels.length > 0) {
      parts.push(`Application platform hints: ${platformLabels.join(', ')}.`);
    }
    if (backendLabels.length > 0) {
      parts.push(`Backend framework hints: ${backendLabels.join(', ')}.`);
    }
    if (analyticsLabels.length > 0) {
      parts.push(
        `Analytics / tracking tools detected: ${analyticsLabels.join(', ')}.`
      );
    }

    if (parts.length === 0) {
      parts.push(
        'Detected several generic technology fingerprints (CDN/analytics/scripts), but no strong CMS or framework signature.'
      );
    }

    summary = parts.join(' ');
  }

  // -----------------------------
  // Exposure profile (low / moderate / elevated)
  // -----------------------------

  const { exposureLevel, exposureFactors } = deriveExposureProfile(
    html,
    techFindings,
    thirdPartyDomains,
    hasAnalytics,
    scriptBlockCount
  );

  return {
    summary,
    techFindings,
    exposureLevel,
    exposureFactors,
  };
}

function uniqueLabelsForCategory(techFindings, category) {
  const set = new Set();
  for (const finding of techFindings) {
    if (finding.category === category) {
      set.add(finding.label);
    }
  }
  return Array.from(set);
}

function deriveExposureProfile(
  html,
  techFindings,
  thirdPartyDomains,
  hasAnalytics,
  scriptBlockCount
) {
  let score = 0;
  const factors = [];

  const cmsLabels = uniqueLabelsForCategory(techFindings, 'CMS');
  const ecommerceLabels = uniqueLabelsForCategory(techFindings, 'E-commerce');
  const jsLabels = uniqueLabelsForCategory(techFindings, 'JS Framework');
  const platformLabels = uniqueLabelsForCategory(techFindings, 'Platform');
  const backendLabels = uniqueLabelsForCategory(techFindings, 'Backend');

  const hasCms = cmsLabels.length > 0;
  const hasEcommerce = ecommerceLabels.length > 0;
  const hasJsFramework = jsLabels.length > 0;
  const hasPlatform = platformLabels.length > 0;
  const hasBackend = backendLabels.length > 0;
  const hasVersionLeak = techFindings.some(
    (f) => f.category === 'Metadata' && f.label === 'Exposed generator/version'
  );

  const thirdPartyCount = thirdPartyDomains
    ? thirdPartyDomains.size || 0
    : 0;
  const hasHeavyThirdParty = thirdPartyCount > 3;

  if (hasCms) {
    score += 2;
    factors.push(
      `Popular CMS detected (${cmsLabels.join(
        ', '
      )}), which is a common target for automated scans and plugin exploits.`
    );
  }

  if (hasEcommerce) {
    score += 2;
    factors.push(
      `E-commerce platform hints (${ecommerceLabels.join(
        ', '
      )}) increase potential impact if compromised.`
    );
  }

  if (hasJsFramework) {
    score += 1;
    factors.push(
      `Client-side JavaScript framework detected (${jsLabels.join(
        ', '
      )}), which expands the attack surface for XSS and supply-chain issues.`
    );
  }

  if (hasPlatform || hasBackend) {
    score += 1;
    const labels = [...platformLabels, ...backendLabels];
    factors.push(
      `Application or backend platform hints detected (${labels.join(
        ', '
      )}), which may indicate a richer attack surface (admin panels, CI/CD, etc.).`
    );
  }

  if (hasVersionLeak) {
    score += 1;
    factors.push(
      'Meta generator or similar metadata appears to expose software/version information, aiding basic fingerprinting.'
    );
  }

  if (hasHeavyThirdParty) {
    score += 1;
    factors.push(
      `Multiple external script domains detected (${thirdPartyCount}), increasing reliance on third-party JavaScript.`
    );
  }

  if (hasAnalytics) {
    score += 1;
    factors.push(
      'Analytics/tracking scripts detected, indicating additional third-party JavaScript dependencies and potential data flows.'
    );
  }

  // Large inline JS + SPA-ish layout as a softer signal
  const looksLikeSpaShell =
    /<div[^>]+id=["'](root|app|__next)["'][^>]*>/i.test(html) &&
    /<script\b/i.test(html);
  if (looksLikeSpaShell) {
    factors.push(
      'Page structure looks like a JavaScript application shell (root/app div with script-driven rendering).'
    );
  }

  let level = 'low';
  if (score >= 5) level = 'elevated';
  else if (score >= 2) level = 'moderate';

  // Special case: very small static pages with no scripts or third-party JS
  const hasNoScripts = !scriptBlockCount;
  const hasNoThirdParty = thirdPartyCount === 0;

  if (hasNoScripts && hasNoThirdParty) {
    level = 'low';
    factors.push(
      'Minimal scripting and no third-party JavaScript detected, suggesting a simpler attack surface on the client side.'
    );
  }

  // Fallback
  if (factors.length === 0) {
    factors.push(
      'No clear CMS, e-commerce platform, framework version or heavy third-party scripting detected from HTML alone.'
    );
  }

  const exposureFactors = Array.from(
    new Set(factors.map((f) => f.trim()))
  );

  return { exposureLevel: level, exposureFactors };
}
