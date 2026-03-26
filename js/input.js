// Keyboard, mouse & touch input handler

const keys = {};
const justPressed = {};
let lastDirection = { x: 0, y: 1 }; // default facing down

// Mouse state
let mousePos = { x: 0, y: 0 }; // position relative to canvas
let mouseActive = false;
let canvasRef = null;

// Virtual joystick state
let joystick = { active: false, dx: 0, dy: 0, touchId: null };
let joystickOrigin = { x: 0, y: 0 };
const JOYSTICK_RADIUS = 60;
const JOYSTICK_DEAD_ZONE = 0.15;

// Track action button touches separately
const actionTouches = {};

// Menu state flag — set by engine to control touch behavior
let inMenuState = true;
export function setMenuState(val) { inMenuState = val; }

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

  // Mouse controls
  initMouseControls();

  // Mobile touch controls
  if ('ontouchstart' in window || navigator.maxTouchPoints > 0) {
    initTouchControls();
  }
}

function initMouseControls() {
  canvasRef = document.getElementById('game-canvas');
  if (!canvasRef) return;

  canvasRef.addEventListener('mousemove', (e) => {
    const rect = canvasRef.getBoundingClientRect();
    // Scale mouse position to canvas coordinates (canvas is 1000x650 but may be scaled)
    mousePos.x = (e.clientX - rect.left) / rect.width * 1000;
    mousePos.y = (e.clientY - rect.top) / rect.height * 650;
    mouseActive = true;
  });

  canvasRef.addEventListener('mousedown', (e) => {
    e.preventDefault();
    if (e.button === 0) {
      // Left click = fire (space)
      if (!keys[' ']) justPressed[' '] = true;
      keys[' '] = true;
    } else if (e.button === 2) {
      // Right click = interact (e)
      if (!keys['e']) justPressed['e'] = true;
      keys['e'] = true;
    }
  });

  canvasRef.addEventListener('mouseup', (e) => {
    if (e.button === 0) {
      keys[' '] = false;
    } else if (e.button === 2) {
      keys['e'] = false;
    }
  });

  // Disable context menu on canvas
  canvasRef.addEventListener('contextmenu', (e) => {
    e.preventDefault();
  });
}

function initTouchControls() {
  const touchEl = document.getElementById('touch-controls');
  if (touchEl) {
    touchEl.classList.remove('hidden');
    touchEl.classList.add('visible');
  }

  const joystickZone = document.getElementById('joystick-zone');
  const joystickBase = document.getElementById('joystick-base');
  const joystickKnob = document.getElementById('joystick-knob');

  if (joystickZone) {
    // Fixed joystick — always visible, centered in zone
    if (joystickBase) {
      joystickBase.style.display = 'flex';
      joystickBase.style.left = '20px';
      joystickBase.style.top = '20px';
    }

    // Calculate fixed center of the joystick base
    function getJoystickCenter() {
      const rect = joystickBase.getBoundingClientRect();
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    }

    joystickZone.addEventListener('touchstart', (e) => {
      e.preventDefault();
      if (joystick.active) return;
      const touch = e.changedTouches[0];
      joystick.active = true;
      joystick.touchId = touch.identifier;
      joystickOrigin = getJoystickCenter();

      const dx = touch.clientX - joystickOrigin.x;
      const dy = touch.clientY - joystickOrigin.y;
      updateJoystickFromDelta(dx, dy);
    }, { passive: false });

    joystickZone.addEventListener('touchmove', (e) => {
      e.preventDefault();
      for (const touch of e.changedTouches) {
        if (touch.identifier === joystick.touchId) {
          const dx = touch.clientX - joystickOrigin.x;
          const dy = touch.clientY - joystickOrigin.y;
          updateJoystickFromDelta(dx, dy);
        }
      }
    }, { passive: false });

    function updateJoystickFromDelta(dx, dy) {
      const dist = Math.sqrt(dx * dx + dy * dy);
      const clampedDist = Math.min(dist, JOYSTICK_RADIUS);
      const angle = Math.atan2(dy, dx);

      joystick.dx = (clampedDist / JOYSTICK_RADIUS) * Math.cos(angle);
      joystick.dy = (clampedDist / JOYSTICK_RADIUS) * Math.sin(angle);

      if (Math.abs(joystick.dx) < JOYSTICK_DEAD_ZONE) joystick.dx = 0;
      if (Math.abs(joystick.dy) < JOYSTICK_DEAD_ZONE) joystick.dy = 0;

      updateJoystickKnob(
        Math.cos(angle) * clampedDist,
        Math.sin(angle) * clampedDist
      );

      checkJoystickMenuKeys();
    }

    // Track if we already fired a menu key for this joystick gesture
    let joystickMenuFired = false;

    function checkJoystickMenuKeys() {
      // When joystick is pushed left/right, fire a/d as justPressed (for char select etc.)
      if (!joystickMenuFired && Math.abs(joystick.dx) > 0.5) {
        const key = joystick.dx < 0 ? 'a' : 'd';
        if (!keys[key]) justPressed[key] = true;
        keys[key] = true;
        setTimeout(() => { keys[key] = false; }, 100);
        joystickMenuFired = true;
      }
    }

    const endJoystick = (e) => {
      for (const touch of e.changedTouches) {
        if (touch.identifier === joystick.touchId) {
          joystick.active = false;
          joystick.dx = 0;
          joystick.dy = 0;
          joystick.touchId = null;
          joystickMenuFired = false;
          updateJoystickKnob(0, 0);
        }
      }
    };

    joystickZone.addEventListener('touchend', endJoystick);
    joystickZone.addEventListener('touchcancel', endJoystick);
  }

  function updateJoystickKnob(offsetX, offsetY) {
    if (!joystickKnob || !joystickBase) return;
    joystickKnob.style.transform = `translate(${offsetX}px, ${offsetY}px)`;
  }

  // Action buttons
  document.querySelectorAll('.touch-btn').forEach(btn => {
    const key = btn.dataset.key;

    btn.addEventListener('touchstart', (e) => {
      e.preventDefault();
      const touch = e.changedTouches[0];
      actionTouches[touch.identifier] = key;
      if (!keys[key]) justPressed[key] = true;
      keys[key] = true;
      btn.classList.add('touch-active');
    }, { passive: false });

    btn.addEventListener('touchend', (e) => {
      e.preventDefault();
      for (const touch of e.changedTouches) {
        const k = actionTouches[touch.identifier];
        if (k) {
          keys[k] = false;
          delete actionTouches[touch.identifier];
        }
      }
      btn.classList.remove('touch-active');
    });

    btn.addEventListener('touchcancel', (e) => {
      for (const touch of e.changedTouches) {
        const k = actionTouches[touch.identifier];
        if (k) {
          keys[k] = false;
          delete actionTouches[touch.identifier];
        }
      }
      btn.classList.remove('touch-active');
    });
  });

  // Tap anywhere on screen for menu / char select / game over ONLY
  document.addEventListener('touchstart', (e) => {
    if (!inMenuState) return; // Don't fire during gameplay

    const wrapper = document.getElementById('game-wrapper');
    if (!wrapper || wrapper.classList.contains('hidden')) return;

    // Don't interfere with action buttons or joystick
    const target = e.target;
    if (target.classList.contains('touch-btn') ||
        target.id === 'joystick-zone' ||
        target.id === 'joystick-base' ||
        target.id === 'joystick-knob') return;

    const touch = e.changedTouches[0];
    const screenW = window.innerWidth;
    const tapX = touch.clientX / screenW;

    // Left third = left, right third = right, middle = confirm/space
    if (tapX < 0.33) {
      if (!keys['a']) justPressed['a'] = true;
      keys['a'] = true;
      setTimeout(() => { keys['a'] = false; }, 100);
    } else if (tapX > 0.66) {
      if (!keys['d']) justPressed['d'] = true;
      keys['d'] = true;
      setTimeout(() => { keys['d'] = false; }, 100);
    } else {
      if (!keys[' ']) justPressed[' '] = true;
      keys[' '] = true;
      setTimeout(() => { keys[' '] = false; }, 100);
    }
  });

  // Prevent zooming and scrolling during gameplay
  document.addEventListener('touchmove', (e) => {
    if (document.getElementById('game-wrapper') &&
        !document.getElementById('game-wrapper').classList.contains('hidden')) {
      e.preventDefault();
    }
  }, { passive: false });
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

  // Keyboard
  if (isKeyDown('w') || isKeyDown('arrowup')) y = -1;
  if (isKeyDown('s') || isKeyDown('arrowdown')) y = 1;
  if (isKeyDown('a') || isKeyDown('arrowleft')) x = -1;
  if (isKeyDown('d') || isKeyDown('arrowright')) x = 1;

  // Virtual joystick (overrides keyboard if active)
  if (joystick.active && (joystick.dx !== 0 || joystick.dy !== 0)) {
    x = joystick.dx;
    y = joystick.dy;
  }

  if (x !== 0 || y !== 0) {
    lastDirection = { x: x > 0 ? 1 : x < 0 ? -1 : 0, y: y > 0 ? 1 : y < 0 ? -1 : 0 };
    // Normalize
    const len = Math.sqrt(x * x + y * y);
    if (len > 1) {
      x /= len;
      y /= len;
    }
  }

  return { x, y };
}


export function getLastDirection() {
  return lastDirection;
}

export function getMousePos() {
  return mouseActive ? mousePos : null;
}

// Call from player update to aim toward mouse
export function updateMouseDirection(playerX, playerY, playerW, playerH) {
  if (!mouseActive) return;
  const cx = playerX + playerW / 2;
  const cy = playerY + playerH / 2;
  const dx = mousePos.x - cx;
  const dy = mousePos.y - cy;
  const len = Math.sqrt(dx * dx + dy * dy);
  if (len > 5) {
    lastDirection = {
      x: dx / len > 0.3 ? 1 : dx / len < -0.3 ? -1 : 0,
      y: dy / len > 0.3 ? 1 : dy / len < -0.3 ? -1 : 0,
    };
    // Also store the precise normalized direction for shooting
    lastDirection._precise = { x: dx / len, y: dy / len };
  }
}

export function isTouchDevice() {
  return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
}
