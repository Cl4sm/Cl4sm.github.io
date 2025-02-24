document.addEventListener('DOMContentLoaded', () => {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
      }
    });
  }, {
    threshold: 0.1
  });

  // Set character count for each command
  document.querySelectorAll('.command').forEach(el => {
    el.style.setProperty('--char-count', el.textContent.length);
  });

  // Observe all typing headers and containers
  document.querySelectorAll('.typing-header, .typing-container').forEach(el => {
    observer.observe(el);
  });

}); 