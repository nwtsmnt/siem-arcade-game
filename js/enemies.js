// Enemy drones: patrol AI, collision, respawn

import { drawSprite, spawnParticles, COLORS, getEnemyType, getRandomEnemyTypeId } from './renderer.js';
import { getProjectiles, removeProjectile, getShockwave, damagePlayer, addScore, getPlayerBounds } from './player.js';
import { emitGameEvent } from './log-engine.js';
import { playSound } from './audio.js';

const ENEMY_SIZE = 32;
const ENEMY_SPEED = 1.5;
const ENEMY_COUNT = 3;
const RESPAWN_DELAY = 180; // 3 seconds

let enemies = [];
let respawnTimers = [];

export function initEnemies(canvasW, canvasH) {
  enemies = [];
  respawnTimers = [];
  for (let i = 0; i < ENEMY_COUNT; i++) {
    enemies.push(spawnEnemy(canvasW, canvasH, i));
  }
}

function spawnEnemy(canvasW, canvasH, index) {
  // Spawn at edges
  const side = index % 4;
  let x, y;
  switch (side) {
    case 0: x = Math.random() * (canvasW - 100) + 50; y = 40; break;
    case 1: x = canvasW - ENEMY_SIZE - 10; y = Math.random() * (canvasH - 100) + 50; break;
    case 2: x = Math.random() * (canvasW - 100) + 50; y = canvasH - ENEMY_SIZE - 20; break;
    default: x = 10; y = Math.random() * (canvasH - 100) + 50; break;
  }

  const angle = Math.random() * Math.PI * 2;
  const typeId = getRandomEnemyTypeId();
  return {
    x, y,
    w: ENEMY_SIZE,
    h: ENEMY_SIZE,
    vx: Math.cos(angle) * ENEMY_SPEED,
    vy: Math.sin(angle) * ENEMY_SPEED,
    alive: true,
    hp: 1,
    typeId,
  };
}

export function updateEnemies(canvasW, canvasH, player) {
  // Respawn timers
  for (let i = respawnTimers.length - 1; i >= 0; i--) {
    respawnTimers[i]--;
    if (respawnTimers[i] <= 0) {
      respawnTimers.splice(i, 1);
      enemies.push(spawnEnemy(canvasW, canvasH, enemies.length));
    }
  }

  const projectiles = getProjectiles();
  const shockwave = getShockwave();
  const playerBounds = getPlayerBounds();

  for (let i = enemies.length - 1; i >= 0; i--) {
    const e = enemies[i];
    if (!e.alive) continue;

    // Patrol: bounce off edges
    e.x += e.vx;
    e.y += e.vy;

    if (e.x <= 0 || e.x >= canvasW - e.w) {
      e.vx *= -1;
      e.x = Math.max(0, Math.min(canvasW - e.w, e.x));
    }
    if (e.y <= 30 || e.y >= canvasH - e.h - 10) {
      e.vy *= -1;
      e.y = Math.max(30, Math.min(canvasH - e.h - 10, e.y));
    }

    // Check collision with player projectiles
    for (let j = projectiles.length - 1; j >= 0; j--) {
      const p = projectiles[j];
      if (aabb(p.x - 4, p.y - 4, 8, 8, e.x, e.y, e.w, e.h)) {
        e.alive = false;
        if (!p.piercing) {
          removeProjectile(j);
        }
        addScore(200);
        spawnParticles(e.x + e.w / 2, e.y + e.h / 2, 15, 3);
        playSound('explosion');
        emitGameEvent('enemy_kill', { score: 200 });
        respawnTimers.push(RESPAWN_DELAY);
        break;
      }
    }

    // Check shockwave
    if (e.alive && shockwave) {
      const dx = (e.x + e.w / 2) - shockwave.x;
      const dy = (e.y + e.h / 2) - shockwave.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < shockwave.radius + e.w / 2) {
        e.alive = false;
        addScore(200);
        spawnParticles(e.x + e.w / 2, e.y + e.h / 2, 20, 4);
        playSound('explosion');
        emitGameEvent('enemy_kill', { score: 200, method: 'shockwave' });
        respawnTimers.push(RESPAWN_DELAY);
      }
    }

    // Check collision with player
    if (e.alive && playerBounds && aabb(e.x, e.y, e.w, e.h, playerBounds.x, playerBounds.y, playerBounds.w, playerBounds.h)) {
      damagePlayer();
    }
  }

  // Remove dead enemies
  enemies = enemies.filter(e => e.alive);
}

export function drawEnemies(ctx) {
  for (const e of enemies) {
    if (!e.alive) continue;
    const type = getEnemyType(e.typeId);
    if (type) {
      drawSprite(ctx, null, e.x, e.y, e.w, type.colors, type.sprite);
    } else {
      drawSprite(ctx, 'enemy', e.x, e.y, e.w, COLORS.enemy);
    }
  }
}

export function getEnemies() {
  return enemies;
}

function aabb(x1, y1, w1, h1, x2, y2, w2, h2) {
  return x1 < x2 + w2 && x1 + w1 > x2 && y1 < y2 + h2 && y1 + h1 > y2;
}
