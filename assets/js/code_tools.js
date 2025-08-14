// Enhance code blocks: add Copy and Download, set vertical scrolling
(function () {
  function hasPrevCommentMarker(node, regex) {
    let container = node;
    // If this is the inner .highlight, prefer scanning from the outer .highlighter-rouge wrapper
    const outer = node && node.closest && node.closest('.highlighter-rouge');
    if (outer) container = outer;

    // Case A: the comment was inserted as the first child inside the container (common with Kramdown/Rouge)
    try {
      let first = container && container.firstChild;
      while (first && first.nodeType === Node.TEXT_NODE && String(first.textContent || '').trim() === '') {
        first = first.nextSibling;
      }
      if (first && first.nodeType === Node.COMMENT_NODE) {
        const val = String(first.nodeValue || '');
        if (regex.test(val)) return true;
      }
    } catch (_) {}

    // Find the nearest previous sibling that is not whitespace-only text
    let prev = container && container.previousSibling;
    while (prev) {
      if (prev.nodeType === Node.TEXT_NODE && String(prev.textContent || '').trim() === '') {
        prev = prev.previousSibling;
        continue;
      }
      break;
    }
    // Case B: immediate previous sibling is a comment
    if (prev && prev.nodeType === Node.COMMENT_NODE) {
      const val = String(prev.nodeValue || '');
      return regex.test(val);
    }
    // Case C: immediate previous element sibling ends with the comment
    if (prev && prev.nodeType === Node.ELEMENT_NODE) {
      let last = prev.lastChild;
      while (last && last.nodeType === Node.TEXT_NODE && String(last.textContent || '').trim() === '') {
        last = last.previousSibling;
      }
      if (last && last.nodeType === Node.COMMENT_NODE) {
        const val = String(last.nodeValue || '');
        return regex.test(val);
      }
    }
    return false;
  }

  function hasPrevNegativeMarker(node) {
    return hasPrevCommentMarker(node, /\bnot-llm\b/i) ||
           (node && (node.getAttribute && node.getAttribute('data-llm') === 'false'));
  }
  function getLanguage(fig) {
    const known = ['console', 'stdout', 'hexdump', 'python', 'bash', 'shell', 'sh', 'shell-session', 'text', 'plaintext'];

    function extractFrom(el) {
      if (!el) return '';
      const classes = Array.from(el.classList || []);

      // Prefer exact known languages from language-* tokens
      const languageTokens = classes.filter((c) => c.startsWith('language-')).map((c) => c.replace('language-', ''));
      const preferred = languageTokens.find((tok) => known.includes(tok));
      if (preferred) return preferred;

      // Otherwise, if any language-* present, but unknown (e.g., 'llm'), ignore it and try direct known class
      if (languageTokens.length > 0) {
        const directKnown = classes.find((c) => known.includes(c));
        if (directKnown) return directKnown;
      }

      // Fallback: Some themes put raw language name on the element (e.g., 'console')
      const direct = classes.find((c) => known.includes(c));
      return direct || '';
    }

    const code = fig.querySelector('code');
    const pre = fig.querySelector('pre');
    const wrapper = fig.closest('.highlighter-rouge');
    return (
      extractFrom(code) ||
      extractFrom(pre) ||
      extractFrom(fig) ||
      extractFrom(wrapper)
    );
  }

  function textFromPre(pre) {
    // Rouge wraps code as <pre><code>...</code></pre>
    const code = pre.querySelector('code');
    return code ? code.innerText : pre.innerText;
  }

  function createButton(label) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = label;
    return btn;
  }

  function createToolsContainer() {
    const tools = document.createElement('div');
    tools.className = 'code-tools';
    return tools;
  }

  function findDownloadName(fig, fallback) {
    // 1) Attribute on wrapper or code
    const code = fig.querySelector('code');
    const attr =
      fig.getAttribute('data-filename') ||
      (code && (code.getAttribute('data-filename') || code.getAttribute('filename')));
    if (attr && attr.trim()) return attr.trim();

    // 2) Class hint like filename-foo_py or download-name-foo_py
    const classes = new Set([
      ...Array.from(fig.classList || []),
      ...Array.from((code && code.classList) || []),
    ]);
    for (const cls of classes) {
      if (cls.startsWith('filename-')) {
        return cls.replace('filename-', '').replace(/_/g, '.');
      }
      if (cls.startsWith('download-name-')) {
        return cls.replace('download-name-', '').replace(/_/g, '.');
      }
    }

    // 3) Scan preceding siblings for HTML comments like <!-- download: name.py -->
    function scanPrevSiblings(node, maxHops) {
      let prev = node.previousSibling;
      let hops = 0;
      while (prev && hops < maxHops) {
        if (prev.nodeType === Node.COMMENT_NODE) {
          const m = String(prev.nodeValue || '').match(/\b(?:download|filename)\s*:\s*([^\s]+)\b/i);
          if (m && m[1]) return m[1].trim();
        }
        prev = prev.previousSibling;
        hops += 1;
      }
      return '';
    }
    const fromFig = scanPrevSiblings(fig, 10);
    if (fromFig) return fromFig;
    if (fig.parentNode) {
      const fromParent = scanPrevSiblings(fig.parentNode, 10);
      if (fromParent) return fromParent;
    }

    // 4) Magic comment inside the code itself (first 5 lines)
    try {
      const text = textFromPre(fig.querySelector('pre') || { innerText: '' });
      const lines = text.split(/\r?\n/).slice(0, 5);
      for (const line of lines) {
        const m = line.match(/^(?:#|\/\/|;|--|%)\s*(?:download|filename)\s*:\s*([^\s]+)\b/i);
        if (m && m[1]) return m[1].trim();
      }
    } catch (_) {}

    // 5) Default
    return fallback;
  }

  function addToolsToHighlight(fig) {
    if (fig.querySelector('.code-tools')) return;
    const pre = fig.querySelector('pre');
    if (!pre) return;

    // Ensure vertical scroll constraint
    pre.style.maxHeight = '420px';
    pre.style.overflowY = 'auto';
    pre.style.padding = '0.5rem 0.75rem';

    const tools = createToolsContainer();

    // Copy button
    const copyBtn = createButton('Copy');
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(textFromPre(pre));
        copyBtn.textContent = 'Copied!';
        setTimeout(() => (copyBtn.textContent = 'Copy'), 1200);
      } catch (e) {
        copyBtn.textContent = 'Failed';
        setTimeout(() => (copyBtn.textContent = 'Copy'), 1200);
      }
    });

    // Download button
    const dlBtn = createButton('Download');
    dlBtn.addEventListener('click', () => {
      const blob = new Blob([textFromPre(pre)], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      // Propose a smarter default based on language
      const lang = getLanguage(fig);
      const ext = lang === 'python' ? 'py' : 'txt';
      a.download = findDownloadName(fig, `code.${ext}`);
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });

    tools.appendChild(copyBtn);
    tools.appendChild(dlBtn);
    fig.insertBefore(tools, fig.firstChild);
  }

  function enhanceAll() {
    // Respect per-post toggle via data attribute on article
    const post = document.querySelector('article.blog-post');
    const postDisabled = post && String(post.getAttribute('data-code-tools')).toLowerCase() === 'false';

    if (postDisabled) {
      // Only add to blocks explicitly marked with-tools on wrapper, ancestor, or inner <code>
      document
        .querySelectorAll('figure.highlight, .highlighter-rouge > .highlight')
        .forEach((fig) => {
          if (fig.classList.contains('with-tools')) return addToolsToHighlight(fig);
          if (fig.closest('.with-tools')) return addToolsToHighlight(fig);
          const code = fig.querySelector('code');
          if (code && code.classList.contains('with-tools')) return addToolsToHighlight(fig);
        });
      return;
    }

    // Default: add to all, except those marked no-tools
    document
      .querySelectorAll('figure.highlight, .highlighter-rouge > .highlight')
      .forEach((fig) => {
        // Only add to Python blocks; skip console/stdout/hexdump/plaintext entirely
        const lang = getLanguage(fig);
        const container = fig.closest('.highlighter-rouge') || fig;
        const code = fig.querySelector('code');
        const preEl = fig.querySelector('pre');
        const classes = new Set([
          ...Array.from(fig.classList || []),
          ...Array.from((code && code.classList) || []),
          ...Array.from((preEl && preEl.classList) || []),
          ...Array.from((container && container.classList) || [])
        ]);
        const hasLLMClass = classes.has('llm') || classes.has('is-llm') || classes.has('role-llm');
        const isLLMByComment = hasPrevCommentMarker(container, /\bllm\b/i);
        const isLLMByAttr = container.getAttribute('data-llm') === 'true';
        const isOverriddenNot = hasPrevNegativeMarker(container);

        if (!isOverriddenNot && (hasLLMClass || isLLMByComment || isLLMByAttr)) {
          fig.classList.add('no-tools');
          fig.classList.add('is-output');
          fig.classList.add('is-llm');
          if (!fig.getAttribute('data-output-label')) {
            fig.setAttribute('data-output-label', 'LLM');
          }
          return;
        }

        if (['console', 'stdout', 'hexdump', 'text', 'plaintext'].includes(lang)) {
          // mark as no-tools so CSS can reduce top padding and style as output
          fig.classList.add('no-tools');
          fig.classList.add('is-output');
          // Provide a label hint for CSS via data attribute
          const labelMap = {
            console: 'STDOUT',
            stdout: 'STDOUT',
            text: 'STDOUT',
            plaintext: 'STDOUT',
            hexdump: 'HEX'
          };
          const label = labelMap[lang] || 'OUTPUT';
          fig.setAttribute('data-output-label', label);
          // Detect LLM responses alongside console and add variant
          try {
            if (!isOverriddenNot && (hasLLMClass || isLLMByComment || isLLMByAttr)) {
              fig.classList.add('is-llm');
              fig.setAttribute('data-output-label', 'LLM');
            }
          } catch (_) {}
          return;
        }
        if (lang && lang !== 'python') return;
        if (fig.classList.contains('no-tools')) return;
        if (fig.closest('.no-tools')) return;
        const innerCode = fig.querySelector('code');
        if (innerCode && innerCode.classList.contains('no-tools')) return;
        addToolsToHighlight(fig);
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', enhanceAll);
  } else {
    enhanceAll();
  }
})();


