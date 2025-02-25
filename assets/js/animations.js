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
  
  // Create binary background
  createBinaryGrid();
});

// Create a grid of binary characters with smooth parallax effect
function createBinaryGrid() {
  // Create the container for binary display
  const overlay = document.createElement('div');
  overlay.className = 'binary-overlay';
  document.body.appendChild(overlay);
  
  // Force block display and ensure no grid properties remain
  overlay.style.display = 'block';
  overlay.style.gridTemplateColumns = 'none';
  overlay.style.gridTemplateRows = 'none';
  overlay.style.gap = '0';
  
  // Calculate grid size with slight randomness
  const baseCellSize = 25; // Slightly larger cell size
  const cols = Math.ceil(window.innerWidth / baseCellSize) + 5; // Add extra cells
  const rows = Math.ceil(window.innerHeight / baseCellSize) + 5;
  
  // Create cells with slight position randomness
  const cells = [];
  for (let i = 0; i < rows; i++) {
    for (let j = 0; j < cols; j++) {
      const cell = document.createElement('div');
      cell.className = 'binary-cell';
      cell.textContent = Math.random() > 0.5 ? '1' : '0';
      
      // Add slight randomness to break grid pattern
      const randomOffset = Math.random() * 5 - 2.5; // -2.5px to +2.5px
      
      // Position with absolute values and slight randomness
      cell.style.position = 'absolute';
      cell.style.left = `${(j * baseCellSize) + randomOffset}px`;
      cell.style.top = `${(i * baseCellSize) + randomOffset}px`;
      cell.style.width = `${baseCellSize}px`;
      cell.style.height = `${baseCellSize}px`;
      cell.style.display = 'flex';
      cell.style.justifyContent = 'center';
      cell.style.alignItems = 'center';
      
      // Extensive reset of properties that could cause grid lines
      cell.style.border = '0';
      cell.style.outline = '0';
      cell.style.boxShadow = 'none';
      cell.style.boxSizing = 'border-box';
      cell.style.margin = '0';
      cell.style.padding = '0';
      cell.style.textAlign = 'center';
      cell.style.backgroundColor = 'transparent';
      
      // Random chance for alternate color
      if (Math.random() < 0.1) {
        cell.classList.add('alt-color');
      }
      
      overlay.appendChild(cell);
      cells.push(cell);
    }
  }
  
  // Animate random cells
  setInterval(() => {
    const updateCount = Math.floor(cells.length * 0.0002); // 1% of cells
    
    for (let i = 0; i < updateCount; i++) {
      const randomIndex = Math.floor(Math.random() * cells.length);
      const cell = cells[randomIndex];
      
      cell.classList.remove('highlight', 'highlight-bright');
      cell.textContent = cell.textContent === '1' ? '0' : '1';
      
      const highlightType = Math.random();
      if (highlightType > 0.7) {
        cell.classList.add('highlight-bright');
      } else {
        cell.classList.add('highlight');
      }
      
      setTimeout(() => {
        cell.classList.remove('highlight', 'highlight-bright');
      }, 2000 + Math.random() * 4000);
    }
  }, 100);
  
  // Smooth parallax scrolling with requestAnimationFrame
  let lastScrollY = window.scrollY;
  let ticking = false;

  function updateParallax() {
    // More subtle parallax multiplier
    const parallaxMultiplier = 0.03; 
    // Use translate3d for hardware acceleration
    overlay.style.transform = `translate3d(0, ${lastScrollY * parallaxMultiplier}px, 0)`;
    ticking = false;
  }

  window.addEventListener('scroll', () => {
    lastScrollY = window.scrollY;
    
    if (!ticking) {
      // Use requestAnimationFrame for smoother animation
      requestAnimationFrame(updateParallax);
      ticking = true;
    }
  });
  
  // Efficient resize handler
  let resizeTimeout;
  window.addEventListener('resize', () => {
    // Debounce resize events
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
      overlay.remove();
      createBinaryGrid();
    }, 250); // Wait 250ms after resize stops
  });
}
