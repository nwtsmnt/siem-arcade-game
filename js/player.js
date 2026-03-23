// Player entity: movement, shooting, lives, invincibility

import { getMovementVector, getLastDirection, isKeyDown, isJustPressed } from './input.js';
import { drawSprite, drawProjectile, drawShockwave, spawnParticles, COLORS } from './renderer.js';
import { emitGameEvent } from './log-engine.js';
import { playSound } from './audio.js';
import { getState } from './engine.js';

const SPEED = 3.5;
const PROJECTILE_SPEED = 7;
const SHOOT_COOLDOWN = 12;
const INVINCIBILITY_FRAMES = 90;
const PLAYER_SIZE = 40;
const PROJECTILE_RADIUS = 4;
const MAX_SHOCKWAVES = 2;
const SHOCKWAVE_MAX_RADIUS = 200;
const SHOCKWAVE_SPEED = 6;

let player = null;
let projectiles = [];
let shockwave = null;
let shootCooldown = 0;
let shotCount = 0;
let moveLogTimer = 0;

export function createPlayer(canvasW, canvasH) {
  player = {
    x: canvasW / 2 - PLAYER_SIZE / 2,
    y: canvasH / 2 - PLAYER_SIZE / 2,
    w: PLAYER_SIZE,
    h: PLAYER_SIZE,
    lives: 3,
    score: 0,
    invincible: 0,
    shockwaves: MAX_SHOCKWAVES,
  };
  projectiles = [];
  shockwave = null;
  shootCooldown = 0;
  shotCount = 0;
  moveLogTimer = 0;
}

export function getPlayerState() {
  return player;
}

export function addScore(points) {
  if (player) player.score += points;
}

export function damagePlayer() {
  if (!player || player.invincible > 0) return false;
  player.lives--;
  player.invincible = INVINCIBILITY_FRAMES;
  spawnParticles(player.x + player.w / 2, player.y + player.h / 2, 10, 2);
  playSound('hit');
  emitGameEvent('player_death', { livesRemaining: player.lives });
  return true;
}

export function updatePlayer(canvasW, canvasH) {
  if (!player) return;

  const state = getState();
  if (state === 'PAUSED' || state === 'MENU' || state === 'GAME_OVER') return;

  // Movement
  const move = getMovementVector();
  player.x += move.x * SPEED;
  player.y += move.y * SPEED;

  // Clamp to canvas
  player.x = Math.max(0, Math.min(canvasW - player.w, player.x));
  player.y = Math.max(30, Math.min(canvasH - player.h - 10, player.y));

  // Movement logging (batched every 5 seconds = 300 frames)
  if (move.x !== 0 || move.y !== 0) {
    moveLogTimer++;
    if (moveLogTimer >= 300) {
      moveLogTimer = 0;
      emitGameEvent('player_move', {
        position: { x: Math.round(player.x), y: Math.round(player.y) },
      });
    }
  }

  // Invincibility
  if (player.invincible > 0) player.invincible--;

  // Shooting
  shootCooldown = Math.max(0, shootCooldown - 1);
  if (isKeyDown(' ') && shootCooldown === 0) {
    const dir = getLastDirection();
    const cx = player.x + player.w / 2;
    const cy = player.y + player.h / 2;
    projectiles.push({
      x: cx,
      y: cy,
      vx: dir.x * PROJECTILE_SPEED,
      vy: dir.y * PROJECTILE_SPEED,
    });
    shootCooldown = SHOOT_COOLDOWN;
    playSound('shoot');

    shotCount++;
    if (shotCount % 3 === 0) {
      emitGameEvent('player_shoot', { shotCount });
    }
  }

  // Shockwave
  if (isJustPressed('q') && player.shockwaves > 0 && !shockwave) {
    player.shockwaves--;
    shockwave = {
      x: player.x + player.w / 2,
      y: player.y + player.h / 2,
      radius: 10,
      alpha: 1,
    };
    playSound('shockwave');
    emitGameEvent('special_ability', { shockwavesRemaining: player.shockwaves });
  }

  // Update shockwave
  if (shockwave) {
    shockwave.radius += SHOCKWAVE_SPEED;
    shockwave.alpha = 1 - (shockwave.radius / SHOCKWAVE_MAX_RADIUS);
    if (shockwave.radius >= SHOCKWAVE_MAX_RADIUS) {
      shockwave = null;
    }
  }

  // Update projectiles
  for (let i = projectiles.length - 1; i >= 0; i--) {
    const p = projectiles[i];
    p.x += p.vx;
    p.y += p.vy;
    if (p.x < -10 || p.x > canvasW + 10 || p.y < -10 || p.y > canvasH + 10) {
      projectiles.splice(i, 1);
    }
  }
}

export function drawPlayer(ctx) {
  if (!player) return;

  // Invincibility flicker
  if (player.invincible > 0 && Math.floor(player.invincible / 4) % 2 === 0) {
    return; // skip draw for flicker effect
  }

  drawSprite(ctx, 'player', player.x, player.y, player.w);

  // Projectiles
  for (const p of projectiles) {
    drawProjectile(ctx, p.x, p.y, PROJECTILE_RADIUS, COLORS.projectilePlayer);
  }

  // Shockwave
  if (shockwave) {
    drawShockwave(ctx, shockwave.x, shockwave.y, shockwave.radius, shockwave.alpha);
  }
}

export function getProjectiles() {
  return projectiles;
}

export function removeProjectile(index) {
  projectiles.splice(index, 1);
}

export function getShockwave() {
  return shockwave;
}

export function getPlayerBounds() {
  if (!player) return null;
  return { x: player.x, y: player.y, w: player.w, h: player.h };
}
