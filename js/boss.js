// Boss entity: tracking AI, projectiles, HP, shockwave vulnerability

import { drawSprite, drawProjectile, drawHPBar, spawnParticles, COLORS } from './renderer.js';
import { getProjectiles, removeProjectile, getShockwave, damagePlayer, addScore, getPlayerBounds } from './player.js';
import { emitGameEvent } from './log-engine.js';
import { playSound } from './audio.js';

const BOSS_SIZE = 64;
const BOSS_SPEED = 1.2;
const BOSS_MAX_HP = 15;
const BOSS_SHOOT_INTERVAL = 50;
const BOSS_PROJ_SPEED = 4;
const BOSS_PROJ_RADIUS = 6;

let boss = null;
let bossProjectiles = [];
let shootTimer = 0;
let defeated = false;
let active = false;

export function initBoss(canvasW, canvasH) {
  boss = {
    x: canvasW / 2 - BOSS_SIZE / 2,
    y: 60,
    w: BOSS_SIZE,
    h: BOSS_SIZE,
    hp: BOSS_MAX_HP,
    maxHp: BOSS_MAX_HP,
  };
  bossProjectiles = [];
  shootTimer = 0;
  defeated = false;
  active = true;
}

export function isBossActive() { return active; }
export function isBossDefeated() { return defeated; }

export function getBoss() { return boss; }

export function updateBoss(canvasW, canvasH, player) {
  if (!boss || defeated) return;

  const playerBounds = getPlayerBounds();
  if (!playerBounds) return;

  // Track player (slowly)
  const dx = (playerBounds.x + playerBounds.w / 2) - (boss.x + boss.w / 2);
  const dy = (playerBounds.y + playerBounds.h / 2) - (boss.y + boss.h / 2);
  const dist = Math.sqrt(dx * dx + dy * dy);

  if (dist > 5) {
    boss.x += (dx / dist) * BOSS_SPEED;
    boss.y += (dy / dist) * BOSS_SPEED;
  }

  // Keep boss in bounds
  boss.x = Math.max(0, Math.min(canvasW - boss.w, boss.x));
  boss.y = Math.max(30, Math.min(canvasH - boss.h - 10, boss.y));

  // Shoot at player
  shootTimer++;
  if (shootTimer >= BOSS_SHOOT_INTERVAL) {
    shootTimer = 0;
    const angle = Math.atan2(
      (playerBounds.y + playerBounds.h / 2) - (boss.y + boss.h / 2),
      (playerBounds.x + playerBounds.w / 2) - (boss.x + boss.w / 2)
    );
    bossProjectiles.push({
      x: boss.x + boss.w / 2,
      y: boss.y + boss.h / 2,
      vx: Math.cos(angle) * BOSS_PROJ_SPEED,
      vy: Math.sin(angle) * BOSS_PROJ_SPEED,
    });
    playSound('bossShoot');
  }

  // Update boss projectiles
  for (let i = bossProjectiles.length - 1; i >= 0; i--) {
    const p = bossProjectiles[i];
    p.x += p.vx;
    p.y += p.vy;

    if (p.x < -10 || p.x > canvasW + 10 || p.y < -10 || p.y > canvasH + 10) {
      bossProjectiles.splice(i, 1);
      continue;
    }

    // Hit player
    if (playerBounds && aabb(p.x - BOSS_PROJ_RADIUS, p.y - BOSS_PROJ_RADIUS,
        BOSS_PROJ_RADIUS * 2, BOSS_PROJ_RADIUS * 2,
        playerBounds.x, playerBounds.y, playerBounds.w, playerBounds.h)) {
      damagePlayer();
      bossProjectiles.splice(i, 1);
    }
  }

  // Check player projectile hits on boss
  const projectiles = getProjectiles();
  for (let j = projectiles.length - 1; j >= 0; j--) {
    const p = projectiles[j];
    if (aabb(p.x - 4, p.y - 4, 8, 8, boss.x, boss.y, boss.w, boss.h)) {
      boss.hp--;
      removeProjectile(j);
      spawnParticles(p.x, p.y, 5, 2);
      playSound('bossHit');
      emitGameEvent('boss_damage', { bossHp: boss.hp, bossMaxHp: BOSS_MAX_HP });

      if (boss.hp <= 0) {
        defeated = true;
        active = false;
        addScore(5000);
        spawnParticles(boss.x + boss.w / 2, boss.y + boss.h / 2, 40, 5);
        bossProjectiles = [];
        break;
      }
    }
  }

  // Check shockwave hit
  const shockwave = getShockwave();
  if (shockwave) {
    const sdx = (boss.x + boss.w / 2) - shockwave.x;
    const sdy = (boss.y + boss.h / 2) - shockwave.y;
    const sdist = Math.sqrt(sdx * sdx + sdy * sdy);
    if (sdist < shockwave.radius + boss.w / 2) {
      boss.hp -= 3; // Shockwave deals extra damage to boss
      spawnParticles(boss.x + boss.w / 2, boss.y + boss.h / 2, 20, 4);
      playSound('bossHit');
      emitGameEvent('boss_damage', { bossHp: boss.hp, bossMaxHp: BOSS_MAX_HP, method: 'shockwave' });

      if (boss.hp <= 0) {
        defeated = true;
        active = false;
        addScore(5000);
        spawnParticles(boss.x + boss.w / 2, boss.y + boss.h / 2, 40, 5);
        bossProjectiles = [];
      }
    }
  }

  // Boss collision with player
  if (playerBounds && aabb(boss.x, boss.y, boss.w, boss.h, playerBounds.x, playerBounds.y, playerBounds.w, playerBounds.h)) {
    damagePlayer();
  }
}

export function drawBoss(ctx) {
  if (!boss || defeated) return;

  drawSprite(ctx, 'boss', boss.x, boss.y, boss.w, COLORS.boss);

  // HP bar above boss
  drawHPBar(ctx, boss.x - 10, boss.y - 14, boss.w + 20, 8, boss.hp / boss.maxHp, '#cc44ff');

  // Boss projectiles
  for (const p of bossProjectiles) {
    drawProjectile(ctx, p.x, p.y, BOSS_PROJ_RADIUS, COLORS.projectileBoss);
  }
}

function aabb(x1, y1, w1, h1, x2, y2, w2, h2) {
  return x1 < x2 + w2 && x1 + w1 > x2 && y1 < y2 + h2 && y1 + h1 > y2;
}
