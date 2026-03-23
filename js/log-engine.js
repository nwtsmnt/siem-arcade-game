// ECS Log Engine: generates Elastic Common Schema logs from game events

import { getRank } from './engine.js';

const MAX_LOGS = 2000;
const LOG_API_URL = '/api/logs';
const SEND_BATCH_INTERVAL = 1000; // flush to server every 1 second

let logs = [];
let sendQueue = [];
let realPlayer = null;
let sendTimer = null;
let authUser = null; // { username, ip, loginCount }

// Event mapping: game event → ECS fields
const EVENT_MAP = {
  // Authentication
  user_login: {
    category: ['authentication'],
    type: ['start'],
    severity: (data) => data.outcome === 'success' ? 0 : 3,
    level: (data) => data.outcome === 'success' ? 'info' : 'warn',
    message: (p, data) => data.outcome === 'success'
      ? `User ${p.name} logged in successfully from ${p.ip}`
      : `Failed login attempt for ${p.name} from ${p.ip}`,
  },
  user_register: {
    category: ['authentication', 'iam'],
    type: ['creation'],
    severity: 0,
    level: 'info',
    message: (p) => `New account registered: ${p.name} from ${p.ip}`,
  },
  auth_failure: {
    category: ['authentication'],
    type: ['start'],
    severity: 3,
    level: 'warn',
    message: (p, data) => `Authentication failed for user "${data.attemptedUser}" from ${p.ip} — wrong password`,
  },
  user_logout: {
    category: ['authentication'],
    type: ['end'],
    severity: 0,
    level: 'info',
    message: (p) => `User ${p.name} logged out. Session ended.`,
  },
  token_refresh: {
    category: ['authentication'],
    type: ['change'],
    severity: 0,
    level: 'info',
    message: (p) => `Session token refreshed for ${p.name}`,
  },

  // Session
  session_start: {
    category: ['session'],
    type: ['start'],
    severity: 0,
    level: 'info',
    message: (p) => `New session started for ${p.name} [${p.sessionId}]`,
  },
  session_end: {
    category: ['session'],
    type: ['end'],
    severity: 0,
    level: 'info',
    message: (p, data) => `Session ended for ${p.name}. Final score: ${data.score || 0}`,
  },
  session_idle: {
    category: ['session'],
    type: ['info'],
    severity: 2,
    level: 'warn',
    message: (p) => `Player ${p.name} is now idle`,
  },
  session_resume: {
    category: ['session'],
    type: ['info'],
    severity: 0,
    level: 'info',
    message: (p, data) => `Player ${p.name} resumed after ${data.idleDuration || 0}s idle`,
  },

  // Game actions
  player_move: {
    category: ['process'],
    type: ['info'],
    severity: 0,
    level: 'info',
    message: (p, data) => `Player ${p.name} moved to position (${data.position?.x}, ${data.position?.y})`,
  },
  player_shoot: {
    category: ['process'],
    type: ['info'],
    severity: 0,
    level: 'info',
    message: (p, data) => `Player ${p.name} fired weapon (shot #${data.shotCount})`,
  },
  enemy_kill: {
    category: ['process'],
    type: ['info'],
    severity: 0,
    level: 'info',
    message: (p, data) => `Player ${p.name} destroyed enemy drone (+${data.score} pts)${data.method ? ` via ${data.method}` : ''}`,
  },
  boss_engage: {
    category: ['process'],
    type: ['start'],
    severity: 2,
    level: 'warn',
    message: (p) => `ALERT: System Warden engaged by ${p.name}`,
  },
  boss_damage: {
    category: ['process'],
    type: ['info'],
    severity: 0,
    level: 'info',
    message: (p, data) => `Boss took damage from ${p.name}. HP: ${data.bossHp}/${data.bossMaxHp}${data.method ? ` (${data.method})` : ''}`,
  },
  boss_defeat: {
    category: ['process'],
    type: ['end'],
    severity: 0,
    level: 'info',
    message: (p) => `System Warden DEFEATED by ${p.name}! Terminals unlocked.`,
  },
  terminal_access: {
    category: ['process'],
    type: ['access'],
    severity: 0,
    level: 'info',
    message: (p, data) => `Player ${p.name} accessed terminal: ${data.terminal}`,
  },
  special_ability: {
    category: ['process'],
    type: ['info'],
    severity: 0,
    level: 'info',
    message: (p, data) => `Player ${p.name} deployed shockwave (${data.shockwavesRemaining} remaining)`,
  },
  player_death: {
    category: ['process'],
    type: ['info'],
    severity: 3,
    level: 'warn',
    message: (p, data) => `Player ${p.name} lost a life. Lives remaining: ${data.livesRemaining}`,
  },
  game_over: {
    category: ['process'],
    type: ['end'],
    severity: 3,
    level: 'warn',
    message: (p, data) => `GAME OVER for ${p.name}. Final score: ${data.score}`,
  },

};

export function setAuthUser(username, ip, loginCount) {
  authUser = { username, ip, loginCount };
}

function generateSessionId() {
  let s = 'sess-';
  for (let i = 0; i < 8; i++) s += Math.floor(Math.random() * 16).toString(16);
  return s;
}

function generateUserId() {
  let s = 'usr-';
  for (let i = 0; i < 8; i++) s += Math.floor(Math.random() * 16).toString(16);
  return s;
}

export function initLogEngine() {
  logs = [];
  sendQueue = [];

  realPlayer = {
    name: authUser?.username || 'anonymous',
    userId: generateUserId(),
    sessionId: generateSessionId(),
    ip: authUser?.ip || '0.0.0.0',
    country: { name: 'Unknown', code: 'XX' },
    rank: 'Bronze',
    score: 0,
    authAttempts: authUser?.loginCount || 0,
    status: 'active',
  };

  // Show session ID in HUD
  const sessionEl = document.getElementById('hud-session');
  if (sessionEl) sessionEl.textContent = realPlayer.sessionId;

  // Start real-time send loop
  if (sendTimer) clearInterval(sendTimer);
  sendTimer = setInterval(flushLogs, SEND_BATCH_INTERVAL);
}

export function getRealPlayer() {
  return realPlayer;
}

export function emitGameEvent(action, data = {}) {
  if (!realPlayer) return;
  createLog(realPlayer, action, data);
}

export function createLog(player, action, data = {}) {
  const mapping = EVENT_MAP[action];
  if (!mapping) {
    console.warn(`Unknown log action: ${action}`);
    return;
  }

  const severity = typeof mapping.severity === 'function' ? mapping.severity(data) : mapping.severity;
  const level = typeof mapping.level === 'function' ? mapping.level(data) : mapping.level;
  const message = typeof mapping.message === 'function' ? mapping.message(player, data) : mapping.message;
  const outcome = data.outcome || (severity >= 3 ? 'failure' : 'success');

  const record = {
    '@timestamp': new Date().toISOString(),
    event: {
      kind: 'event',
      category: mapping.category,
      type: mapping.type,
      action,
      severity,
      outcome,
      duration: data.duration || 0,
    },
    user: {
      name: player.name,
      id: player.userId,
      roles: ['player'],
    },
    source: {
      ip: player.ip,
      geo: {
        country_name: player.country.name,
        country_iso_code: player.country.code,
      },
    },
    session: {
      id: player.sessionId,
    },
    message,
    log: {
      level,
    },
    labels: {
      game_rank: player.rank || getRank(player.score || 0),
      game_score: player.score || 0,
      auth_attempts: player.authAttempts || 0,
      player_status: player.status || 'active',
    },
    ecs: {
      version: '8.11',
    },
  };

  // Add to store
  logs.push(record);
  if (logs.length > MAX_LOGS) {
    logs.splice(0, logs.length - MAX_LOGS);
  }

  // Queue for real-time sending
  sendQueue.push(record);

  // Console output
  console.log(`[SIEM] ${level.toUpperCase()} | ${action} | ${message}`);

  return record;
}

export function getLogCount() {
  return logs.length;
}

export function getLogs() {
  return logs;
}

export function exportLogs() {
  if (logs.length === 0) {
    alert('No logs to export yet. Play the game first!');
    return;
  }

  const ndjson = logs.map(log => JSON.stringify(log)).join('\n');
  const blob = new Blob([ndjson], { type: 'application/x-ndjson' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `siem-game-logs-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.ndjson`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  console.log(`[SIEM] Exported ${logs.length} logs as NDJSON`);
}

function flushLogs() {
  if (sendQueue.length === 0) return;

  const batch = sendQueue.splice(0);

  fetch(LOG_API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(batch),
  }).catch(() => {
    // Server not running — silently ignore, logs still accumulate in-memory
  });
}
