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
  
  // Create binary background or initialize animation if it already exists
  const existingOverlay = document.querySelector('.binary-overlay');
  if (!existingOverlay) {
    createBinaryGrid();
  } else {
    // If grid exists but animation might have stopped, reinitialize it
    initializeBinaryAnimation(existingOverlay);
  }
});

// Create a grid of binary characters with smooth parallax effect
function createBinaryGrid() {
  // Remove any existing binary overlay first
  const existingOverlay = document.querySelector('.binary-overlay');
  if (existingOverlay) {
    existingOverlay.remove();
  }
  
  // Create the container for binary display
  const overlay = document.createElement('div');
  overlay.className = 'binary-overlay';
  document.body.appendChild(overlay);
  
  // Force block display and ensure no grid properties remain
  overlay.style.display = 'block';
  overlay.style.gridTemplateColumns = 'none';
  overlay.style.gridTemplateRows = 'none';
  overlay.style.gap = '0';
  
  // Adjust cell size based on screen size for better mobile experience
  const baseCellSize = window.innerWidth < 768 ? 20 : 25; // Smaller on mobile
  
  // Use viewport units + percentage to ensure full coverage regardless of zoom
  const viewportWidth = Math.max(document.documentElement.clientWidth, window.innerWidth || 0);
  const viewportHeight = Math.max(document.documentElement.clientHeight, window.innerHeight || 0);
  
  // Calculate with generous margins to ensure coverage during scroll/zoom
  const cols = Math.ceil(viewportWidth / baseCellSize) + 10; // More extra cells
  const rows = Math.ceil(viewportHeight / baseCellSize) + 10;
  
  // Ensure overlay covers the entire screen with extra margin
  overlay.style.width = `${cols * baseCellSize}px`;
  overlay.style.height = `${rows * baseCellSize}px`;
  
  // Center the overlay and ensure it's larger than viewport
  overlay.style.position = 'fixed';
  overlay.style.top = `-${baseCellSize * 5}px`;  // 5 cells worth of margin
  overlay.style.left = `-${baseCellSize * 5}px`; // 5 cells worth of margin
  
  // Create cells with slight position randomness
  const cells = [];
  
  // Reduce cell density on mobile for better performance
  const density = window.innerWidth < 768 ? 0.7 : 1; // 70% density on mobile
  
  for (let i = 0; i < rows; i++) {
    for (let j = 0; j < cols; j++) {
      // Skip some cells on mobile for better performance
      if (window.innerWidth < 768 && Math.random() > density) continue;
      
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
  
  // Add periodic check to ensure animation exists
  if (!window._binaryCheckInterval) {
    window._binaryCheckInterval = setInterval(() => {
      const overlay = document.querySelector('.binary-overlay');
      // If overlay exists but has no visible cells or is off-screen, recreate it
      if (overlay) {
        const visibleCells = overlay.querySelectorAll('.binary-cell:not(.hidden)');
        if (visibleCells.length === 0 || 
            !isElementInViewport(overlay)) {
          console.log('Binary grid needs recreation');
          overlay.remove();
          createBinaryGrid();
        }
      } else {
        // If overlay doesn't exist at all, create it
        createBinaryGrid();
      }
    }, 10000); // Check every 10 seconds
  }
  
  // Initialize animation for the newly created grid
  initializeBinaryAnimation(overlay);
}

// Helper function to check if element is in viewport
function isElementInViewport(el) {
  const rect = el.getBoundingClientRect();
  return (
    rect.top <= (window.innerHeight || document.documentElement.clientHeight) &&
    rect.left <= (window.innerWidth || document.documentElement.clientWidth) &&
    rect.bottom >= 0 &&
    rect.right >= 0
  );
}

// Separate function to handle animation initialization
function initializeBinaryAnimation(overlay) {
  // Store cells array as a property of the overlay for reuse
  if (!overlay.cells) {
    overlay.cells = Array.from(overlay.querySelectorAll('.binary-cell'));
  }
  
  // Clear any existing animation intervals to prevent duplicates
  if (overlay.animationInterval) {
    clearInterval(overlay.animationInterval);
  }
  
  // Adjust animation speed based on device capabilities
  const isMobile = window.innerWidth < 768;
  const animationInterval = isMobile ? 150 : 100; // Slower on mobile
  const cellUpdatePercentage = isMobile ? 0.0001 : 0.0002; // Fewer updates on mobile
  
  overlay.animationInterval = setInterval(() => {
    const updateCount = Math.max(1, Math.floor(overlay.cells.length * cellUpdatePercentage));
    
    for (let i = 0; i < updateCount; i++) {
      const randomIndex = Math.floor(Math.random() * overlay.cells.length);
      const cell = overlay.cells[randomIndex];
      
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
  }, animationInterval);
  
  // Clear any existing scroll listeners to prevent duplicates
  if (window._binaryScrollHandler) {
    window.removeEventListener('scroll', window._binaryScrollHandler);
  }
  
  // Smooth parallax scrolling with requestAnimationFrame
  let lastScrollY = window.scrollY;
  let ticking = false;

  function updateParallax() {
    // More subtle parallax multiplier, even more subtle on mobile
    const parallaxMultiplier = isMobile ? 0.02 : 0.03;
    overlay.style.transform = `translate3d(0, ${lastScrollY * parallaxMultiplier}px, 0)`;
    ticking = false;
  }

  window._binaryScrollHandler = () => {
    lastScrollY = window.scrollY;
    
    if (!ticking) {
      // Use requestAnimationFrame for smoother animation
      requestAnimationFrame(updateParallax);
      ticking = true;
    }
  };

  window.addEventListener('scroll', window._binaryScrollHandler);
  
  // Clear any existing resize handler to prevent duplicates
  if (window._binaryResizeTimeout) {
    clearTimeout(window._binaryResizeTimeout);
  }
  
  // Efficient resize handler
  window.addEventListener('resize', () => {
    // Debounce resize events
    clearTimeout(window._binaryResizeTimeout);
    window._binaryResizeTimeout = setTimeout(() => {
      overlay.remove();
      createBinaryGrid();
    }, 250); // Wait 250ms after resize stops
  });

  // Add resize handler with immediate check for orientation change on mobile
  window.addEventListener('orientationchange', () => {
    // On orientation change, immediately recreate the grid
    setTimeout(() => {
      overlay.remove();
      createBinaryGrid();
    }, 100); // Short delay to allow browser to complete orientation
  });
}

// Add visibility change detection to handle tab switching
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    // When tab becomes visible again, check if binary overlay needs recreation
    const overlay = document.querySelector('.binary-overlay');
    if (!overlay) {
      createBinaryGrid();
    } else {
      // Reinitialize animation to ensure it's running
      initializeBinaryAnimation(overlay);
    }
  }
});
