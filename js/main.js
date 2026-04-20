// Entry point — handles auth then starts game
import { initGame } from './engine.js';
import { setAuthUser } from './log-engine.js';

// TESTING: skip auth, go straight to game
const SKIP_AUTH = false;

window.addEventListener('DOMContentLoaded', () => {
  const loginScreen = document.getElementById('login-screen');
  const gameWrapper = document.getElementById('game-wrapper');

  if (SKIP_AUTH) {
    setAuthUser('test_player', '127.0.0.1', 1);
    loginScreen.classList.add('hidden');
    gameWrapper.classList.remove('hidden');
    initGame();
    return;
  }

  const usernameInput = document.getElementById('login-username');
  const passwordInput = document.getElementById('login-password');
  const loginBtn = document.getElementById('login-btn');
  const errorEl = document.getElementById('login-error');
  const successEl = document.getElementById('login-success');

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.classList.remove('hidden');
    successEl.classList.add('hidden');
  }

  function showSuccess(msg) {
    successEl.textContent = msg;
    successEl.classList.remove('hidden');
    errorEl.classList.add('hidden');
  }

  async function doLogin() {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
      showError('Enter both username and password.');
      return;
    }

    loginBtn.disabled = true;
    loginBtn.textContent = 'AUTHENTICATING...';
    errorEl.classList.add('hidden');
    successEl.classList.add('hidden');

    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();

      if (data.status === 'success' || data.status === 'created') {
        showSuccess(data.message);

        // Admin redirect
        if (data.isAdmin) {
          showSuccess('Admin access granted. Redirecting to control panel...');
          setTimeout(() => { window.location.href = '/admin.html'; }, 800);
          return;
        }

        // Pass auth info to log engine
        setAuthUser(data.username, data.ip, data.login_count);

        // Transition to game after brief delay
        setTimeout(() => {
          loginScreen.classList.add('hidden');
          gameWrapper.classList.remove('hidden');
          initGame();
        }, 800);

      } else if (data.status === 'wrong_password') {
        showError(data.message);
        loginBtn.disabled = false;
        loginBtn.textContent = 'AUTHENTICATE';
        passwordInput.value = '';
        passwordInput.focus();
      } else {
        showError(data.error || 'Authentication failed.');
        loginBtn.disabled = false;
        loginBtn.textContent = 'AUTHENTICATE';
      }

    } catch (err) {
      showError('Server unreachable. Is log-server.py running?');
      loginBtn.disabled = false;
      loginBtn.textContent = 'AUTHENTICATE';
    }
  }

  loginBtn.addEventListener('click', doLogin);

  // Enter key submits
  passwordInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doLogin();
  });
  usernameInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') passwordInput.focus();
  });

  // Auto-focus username
  usernameInput.focus();
});
