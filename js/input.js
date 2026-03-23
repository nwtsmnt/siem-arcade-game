// Keyboard & touch input handler

const keys = {};
const justPressed = {};
let lastDirection = { x: 0, y: 1 }; // default facing down

export function initInput() {
  window.addEventListener('keydown', (e) => {
    const key = e.key.toLowerCase();
    if (!keys[key]) {
      justPressed[key] = true;
    }
    keys[key] = true;
    if (['arrowup','arrowdown','arrowleft','arrowright',' '].includes(e.key)) {
      e.preventDefault();
    }
  });

  window.addEventListener('keyup', (e) => {
    keys[e.key.toLowerCase()] = false;
  });

  // Touch controls
  if ('ontouchstart' in window) {
    const touchEl = document.getElementById('touch-controls');
    if (touchEl) {
      touchEl.classList.remove('hidden');
      touchEl.classList.add('visible');
    }

    document.querySelectorAll('.touch-btn').forEach(btn => {
      const key = btn.dataset.key;

      btn.addEventListener('touchstart', (e) => {
        e.preventDefault();
        if (!keys[key]) justPressed[key] = true;
        keys[key] = true;
      });

      btn.addEventListener('touchend', (e) => {
        e.preventDefault();
        keys[key] = false;
      });
    });
  }
}

export function isKeyDown(key) {
  return !!keys[key.toLowerCase()];
}

export function isJustPressed(key) {
  return !!justPressed[key.toLowerCase()];
}

export function clearJustPressed() {
  for (const k in justPressed) {
    delete justPressed[k];
  }
}

export function getMovementVector() {
  let x = 0, y = 0;

  if (isKeyDown('w') || isKeyDown('arrowup')) y = -1;
  if (isKeyDown('s') || isKeyDown('arrowdown')) y = 1;
  if (isKeyDown('a') || isKeyDown('arrowleft')) x = -1;
  if (isKeyDown('d') || isKeyDown('arrowright')) x = 1;

  if (x !== 0 || y !== 0) {
    lastDirection = { x, y };
    // Normalize diagonal movement
    const len = Math.sqrt(x * x + y * y);
    x /= len;
    y /= len;
  }

  return { x, y };
}

export function getLastDirection() {
  return lastDirection;
}
