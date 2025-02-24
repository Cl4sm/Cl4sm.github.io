document.addEventListener('DOMContentLoaded', function() {
  // Handle cite buttons
  document.querySelectorAll('.cite-button').forEach(button => {
    button.addEventListener('click', function() {
      const popup = this.closest('.publication').querySelector('.citation-popup');
      popup.classList.add('active');
    });
  });

  // Handle close buttons
  document.querySelectorAll('.close-button').forEach(button => {
    button.addEventListener('click', function() {
      const popup = this.closest('.citation-popup');
      popup.classList.remove('active');
    });
  });

  // Handle clicking outside modal
  document.querySelectorAll('.citation-overlay').forEach(overlay => {
    overlay.addEventListener('click', function() {
      const popup = this.closest('.citation-popup');
      popup.classList.remove('active');
    });
  });

  // Handle copy buttons
  document.querySelectorAll('.copy-button').forEach(button => {
    button.addEventListener('click', function() {
      const citation = this.closest('.citation-content').querySelector('code').textContent;
      navigator.clipboard.writeText(citation).then(() => {
        const originalText = this.textContent;
        this.textContent = 'Copied!';
        setTimeout(() => {
          this.textContent = originalText;
        }, 2000);
      });
    });
  });

  // Handle close-x buttons
  document.querySelectorAll('.close-x').forEach(button => {
    button.addEventListener('click', function() {
      const popup = this.closest('.citation-popup');
      popup.classList.remove('active');
    });
  });

  // Handle escape key
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      const activePopup = document.querySelector('.citation-popup.active');
      if (activePopup) {
        activePopup.classList.remove('active');
      }
    }
  });
});