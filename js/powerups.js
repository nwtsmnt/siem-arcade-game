// Power-up crates: spawn, proximity pickup, weapon upgrades

import { drawSprite, drawText, spawnParticles } from './renderer.js';
import { isJustPressed } from './input.js';
import { emitGameEvent } from './log-engine.js';
import { playSound } from './audio.js';

const CRATE_SIZE = 30;
const INTERACT_RANGE = 55;
const SPAWN_INTERVAL = 600; // every 10 seconds
const MAX_CRATES = 3;

// Power-up definitions
const POWERUP_TYPES = {
  triple_shot: {
    name: 'TRIPLE SHOT',
    desc: 'Fires 3 projectiles in a spread',
    duration: 600, // 10 seconds
    color: '#ff4444',
    crateColors: ['#ff4444', '#cc2222', '#ffaa33'],
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,2,2,2,2,1,0],
      [1,2,3,2,2,3,2,1],
      [1,2,2,2,2,2,2,1],
      [1,2,3,2,2,3,2,1],
      [1,2,2,3,3,2,2,1],
      [0,1,2,2,2,2,1,0],
      [0,0,1,1,1,1,0,0],
    ],
  },
  rapid_fire: {
    name: 'RAPID FIRE',
    desc: 'Doubles fire rate',
    duration: 600,
    color: '#ffcc00',
    crateColors: ['#ffcc00', '#ff9900', '#cc6600'],
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,2,2,2,2,1,0],
      [1,2,2,3,3,2,2,1],
      [1,2,3,2,2,3,2,1],
      [1,2,2,3,3,2,2,1],
      [1,2,3,2,2,3,2,1],
      [0,1,2,2,2,2,1,0],
      [0,0,1,1,1,1,0,0],
    ],
  },
  auto_attack: {
    name: 'AUTO TURRET',
    desc: 'Auto-fires at nearest enemy',
    duration: 480, // 8 seconds
    color: '#00ffff',
    crateColors: ['#00ffff', '#0099cc', '#006688'],
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,2,2,2,2,1,0],
      [1,2,2,2,2,2,2,1],
      [1,2,3,3,3,3,2,1],
      [1,2,2,3,3,2,2,1],
      [1,2,2,2,2,2,2,1],
      [0,1,2,2,2,2,1,0],
      [0,0,1,1,1,1,0,0],
    ],
  },
  piercing: {
    name: 'PIERCING ROUNDS',
    desc: 'Shots pass through enemies',
    duration: 480,
    color: '#cc44ff',
    crateColors: ['#cc44ff', '#9933cc', '#661199'],
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,2,2,2,2,1,0],
      [1,2,2,3,2,2,2,1],
      [1,2,2,2,3,2,2,1],
      [1,2,2,3,2,2,2,1],
      [1,2,3,2,2,2,2,1],
      [0,1,2,2,2,2,1,0],
      [0,0,1,1,1,1,0,0],
    ],
  },
  shield: {
    name: 'ENERGY SHIELD',
    desc: 'Blocks next 3 hits',
    duration: 0, // charge-based, not timed
    charges: 3,
    color: '#39ff14',
    crateColors: ['#39ff14', '#2bcc0f', '#1a8a09'],
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,2,2,2,2,1,0],
      [1,2,3,3,3,3,2,1],
      [1,2,3,2,2,3,2,1],
      [1,2,3,2,2,3,2,1],
      [1,2,3,3,3,3,2,1],
      [0,1,2,2,2,2,1,0],
      [0,0,1,1,1,1,0,0],
    ],
  },
};

const POWERUP_IDS = Object.keys(POWERUP_TYPES);

let crates = [];
let spawnTimer = 0;
let activePowerup = null; // { type, timer, charges }
let canvasW = 1000, canvasH = 650;

export function initPowerups(cw, ch) {
  canvasW = cw;
  canvasH = ch;
  crates = [];
  activePowerup = null;
  spawnTimer = 300; // first crate after 5 seconds
}

export function updatePowerups(player, enemies) {
  if (!player) return;

  // Spawn timer
  spawnTimer--;
  if (spawnTimer <= 0 && crates.length < MAX_CRATES) {
    spawnCrate();
    spawnTimer = SPAWN_INTERVAL + Math.floor(Math.random() * 300);
  }

  // Check proximity and interaction
  for (let i = crates.length - 1; i >= 0; i--) {
    const c = crates[i];

    // Animate float
    c.floatPhase += 0.05;

    const dx = (player.x + player.w / 2) - (c.x + CRATE_SIZE / 2);
    const dy = (player.y + player.h / 2) - (c.y + CRATE_SIZE / 2);
    const dist = Math.sqrt(dx * dx + dy * dy);
    c.nearby = dist < INTERACT_RANGE;

    if (c.nearby && isJustPressed('e')) {
      // Pick up power-up
      const type = POWERUP_TYPES[c.typeId];
      activePowerup = {
        typeId: c.typeId,
        type: type,
        timer: type.duration,
        charges: type.charges || 0,
      };

      spawnParticles(c.x + CRATE_SIZE / 2, c.y + CRATE_SIZE / 2, 20, 3);
      playSound('terminal');
      emitGameEvent('powerup_pickup', {
        powerup: type.name,
        description: type.desc,
        duration: type.duration > 0 ? (type.duration / 60).toFixed(1) + 's' : type.charges + ' charges',
      });

      crates.splice(i, 1);
    }

    // Despawn after 20 seconds
    c.life--;
    if (c.life <= 0) {
      crates.splice(i, 1);
    }
  }

  // Update active power-up timer
  if (activePowerup) {
    if (activePowerup.timer > 0) {
      activePowerup.timer--;
      if (activePowerup.timer <= 0 && activePowerup.charges <= 0) {
        emitGameEvent('powerup_expired', { powerup: activePowerup.type.name });
        activePowerup = null;
      }
    }
    // Shield expires when charges are used up (handled by useShieldCharge)
    if (activePowerup && activePowerup.typeId === 'shield' && activePowerup.charges <= 0) {
      emitGameEvent('powerup_expired', { powerup: activePowerup.type.name, reason: 'charges_depleted' });
      activePowerup = null;
    }
  }
}

export function drawPowerups(ctx) {
  // Draw crates
  for (const c of crates) {
    const type = POWERUP_TYPES[c.typeId];
    const floatY = Math.sin(c.floatPhase) * 3;

    drawSprite(ctx, null, c.x, c.y + floatY, CRATE_SIZE, type.crateColors, type.sprite);

    // Proximity prompt
    if (c.nearby) {
      drawText(ctx, `[E] ${type.name}`, c.x + CRATE_SIZE / 2, c.y - 12, 14, type.color, 'center');
    }

    // Despawn warning (flash when < 3 seconds left)
    if (c.life < 180 && Math.floor(c.life / 15) % 2 === 0) {
      ctx.globalAlpha = 0.5;
      drawSprite(ctx, null, c.x, c.y + floatY, CRATE_SIZE, type.crateColors, type.sprite);
      ctx.globalAlpha = 1;
    }
  }

  // Draw active power-up indicator
  if (activePowerup) {
    const type = activePowerup.type;
    const barW = 120;
    const barH = 8;
    const barX = 10;
    const barY = 44;

    // Label
    drawText(ctx, type.name, barX, barY - 4, 14, type.color, 'left');

    if (activePowerup.timer > 0) {
      // Timer bar
      const ratio = activePowerup.timer / type.duration;
      ctx.fillStyle = '#222';
      ctx.fillRect(barX, barY, barW, barH);
      ctx.fillStyle = type.color;
      ctx.fillRect(barX, barY, barW * ratio, barH);
    } else if (activePowerup.charges > 0) {
      // Charge dots
      for (let i = 0; i < activePowerup.charges; i++) {
        ctx.fillStyle = type.color;
        ctx.beginPath();
        ctx.arc(barX + 8 + i * 16, barY + 4, 5, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }
}

function spawnCrate() {
  const typeId = POWERUP_IDS[Math.floor(Math.random() * POWERUP_IDS.length)];
  const margin = 60;
  const x = margin + Math.random() * (canvasW - CRATE_SIZE - margin * 2);
  const y = margin + Math.random() * (canvasH - CRATE_SIZE - margin * 2);

  crates.push({
    x, y,
    typeId,
    nearby: false,
    life: 1200, // 20 seconds
    floatPhase: Math.random() * Math.PI * 2,
  });
}

// --- Public API for player.js to query active power-up ---

export function getActivePowerup() {
  return activePowerup;
}

export function useShieldCharge() {
  if (activePowerup && activePowerup.typeId === 'shield' && activePowerup.charges > 0) {
    activePowerup.charges--;
    emitGameEvent('powerup_use', {
      powerup: 'ENERGY SHIELD',
      chargesRemaining: activePowerup.charges,
    });
    return true;
  }
  return false;
}
