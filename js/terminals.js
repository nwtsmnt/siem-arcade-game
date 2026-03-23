// Data terminals: proximity interaction, locked/unlocked state, data overlay

import { drawSprite, drawText, COLORS } from './renderer.js';
import { isJustPressed } from './input.js';
import { emitGameEvent } from './log-engine.js';
import { playSound } from './audio.js';

const TERMINAL_SIZE = 36;
const INTERACT_RANGE = 60;

const TERMINAL_DATA = [
  {
    title: 'NETWORK TOPOLOGY',
    content: `> SCANNING NETWORK...
> NODES DISCOVERED: 47
> SEGMENTS: DMZ, INTERNAL, RESTRICTED
> FIREWALL RULES: 312 active
> OPEN PORTS: 22, 80, 443, 8080, 3306
> VPN TUNNELS: 3 active
> ANOMALY: Unregistered node at 10.0.3.99
> STATUS: MAPPING COMPLETE`,
  },
  {
    title: 'USER DATABASE',
    content: `> ACCESSING USER RECORDS...
> TOTAL ACCOUNTS: 1,247
> ACTIVE: 892 | LOCKED: 43 | SUSPENDED: 312
> ADMIN ACCOUNTS: 7
> SERVICE ACCOUNTS: 28
> LAST PASSWORD POLICY UPDATE: 47 days ago
> WARNING: 12 accounts using default credentials
> 2FA ADOPTION: 64%`,
  },
  {
    title: 'INCIDENT LOG',
    content: `> LOADING INCIDENT HISTORY...
> INC-2024-001: Phishing campaign (resolved)
> INC-2024-007: Ransomware attempt (blocked)
> INC-2024-012: Data exfiltration (investigating)
> INC-2024-019: Insider threat (monitoring)
> INC-2024-023: DDoS attack (mitigated)
> OPEN INCIDENTS: 2
> AVG RESPONSE TIME: 4.2 hours`,
  },
  {
    title: 'THREAT INTELLIGENCE',
    content: `> FETCHING THREAT FEEDS...
> KNOWN THREAT ACTORS: 14 active
> IOCs LOADED: 8,432
> MALWARE SIGNATURES: Updated 2h ago
> BLOCKED IPs (24h): 1,847
> TOP THREAT: APT-GHOST (nation-state)
> RISK LEVEL: ELEVATED
> NEXT SCAN: 00:15:00`,
  },
  {
    title: 'SYSTEM AUDIT',
    content: `> RUNNING COMPLIANCE CHECK...
> PATCHES PENDING: 23
> CRITICAL PATCHES: 4
> LAST AUDIT: 12 days ago
> COMPLIANCE SCORE: 78/100
> FAILED CONTROLS: CIS 5.2, 6.1, 8.4
> ENCRYPTION AT REST: 91%
> LOG RETENTION: 90 days`,
  },
  {
    title: 'ENCRYPTION KEYS',
    content: `> ACCESSING KEY VAULT...
> RSA-4096 KEYS: 12
> AES-256 KEYS: 34
> CERTIFICATES EXPIRING < 30d: 3
> HSM STATUS: ONLINE
> KEY ROTATION: Every 90 days
> LAST ROTATION: 2024-02-15
> COMPROMISED KEYS: 0
> ACCESS: LEVEL-5 CLEARANCE REQUIRED`,
  },
];

let terminals = [];
let activeTerminal = null;
let overlayVisible = false;

export function initTerminals(canvasW, canvasH, unlocked = false) {
  const positions = [
    { x: 80, y: 80 },
    { x: canvasW - 120, y: 80 },
    { x: 80, y: canvasH - 120 },
    { x: canvasW - 120, y: canvasH - 120 },
    { x: canvasW / 2 - 18, y: 80 },
    { x: canvasW / 2 - 18, y: canvasH - 120 },
  ];

  terminals = positions.map((pos, i) => ({
    x: pos.x,
    y: pos.y,
    w: TERMINAL_SIZE,
    h: TERMINAL_SIZE,
    unlocked,
    accessed: false,
    data: TERMINAL_DATA[i],
  }));
  activeTerminal = null;
  overlayVisible = false;
  hideOverlay();
}

export function updateTerminals(player) {
  if (!player) return;

  // Close overlay
  if (overlayVisible && (isJustPressed('e') || isJustPressed('escape'))) {
    hideOverlay();
    overlayVisible = false;
    activeTerminal = null;
    return;
  }

  if (overlayVisible) return;

  // Check proximity and interaction
  for (const t of terminals) {
    const dx = (player.x + player.w / 2) - (t.x + t.w / 2);
    const dy = (player.y + player.h / 2) - (t.y + t.h / 2);
    const dist = Math.sqrt(dx * dx + dy * dy);
    t.nearby = dist < INTERACT_RANGE;

    if (t.nearby && isJustPressed('e')) {
      if (t.unlocked) {
        activeTerminal = t;
        overlayVisible = true;
        t.accessed = true;
        showOverlay(t.data);
        playSound('terminal');
        emitGameEvent('terminal_access', { terminal: t.data.title });
      } else {
        playSound('denied');
      }
    }
  }
}

export function drawTerminals(ctx) {
  for (const t of terminals) {
    const colorSet = t.unlocked
      ? (t.accessed ? ['#339933', '#226622', '#114411'] : COLORS.terminal)
      : COLORS.terminalLocked;

    drawSprite(ctx, 'terminal', t.x, t.y, t.w, colorSet);

    // Proximity prompt
    if (t.nearby && !overlayVisible) {
      const label = t.unlocked ? '[E] ACCESS' : 'LOCKED';
      const color = t.unlocked ? '#ffcc00' : '#ff3333';
      drawText(ctx, label, t.x + t.w / 2, t.y - 8, 16, color, 'center');
    }
  }
}

function showOverlay(data) {
  const overlay = document.getElementById('terminal-overlay');
  const header = document.getElementById('terminal-header');
  const body = document.getElementById('terminal-body');
  header.textContent = data.title;
  body.textContent = data.content;
  overlay.classList.remove('hidden');
}

function hideOverlay() {
  document.getElementById('terminal-overlay').classList.add('hidden');
}
