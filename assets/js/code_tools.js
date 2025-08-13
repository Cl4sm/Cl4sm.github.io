// Enhance code blocks: add Copy and Download, set vertical scrolling
(function () {
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
      a.download = 'code.txt';
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
        if (fig.classList.contains('no-tools')) return;
        if (fig.closest('.no-tools')) return;
        const code = fig.querySelector('code');
        if (code && code.classList.contains('no-tools')) return;
        addToolsToHighlight(fig);
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', enhanceAll);
  } else {
    enhanceAll();
  }
})();


