// Game loop, state machine, canvas management

import { initInput, clearJustPressed, isJustPressed } from './input.js';
import { drawBackground, updateAndDrawParticles, clearParticles, drawText } from './renderer.js';
import { createPlayer, updatePlayer, drawPlayer, getPlayerState } from './player.js';
import { initEnemies, updateEnemies, drawEnemies, getEnemies } from './enemies.js';
import { initBoss, updateBoss, drawBoss, getBoss, isBossActive, isBossDefeated } from './boss.js';
import { initTerminals, updateTerminals, drawTerminals } from './terminals.js';
import { drawHUD } from './hud.js';
import { initAudio, playSound } from './audio.js';
import { initLogEngine, emitGameEvent, exportLogs, getLogCount } from './log-engine.js';

export const CANVAS_W = 1000;
export const CANVAS_H = 650;

export const STATES = {
  MENU: 'MENU',
  PLAYING: 'PLAYING',
  BOSS_INTRO: 'BOSS_INTRO',
  BOSS_FIGHT: 'BOSS_FIGHT',
  PAUSED: 'PAUSED',
  GAME_OVER: 'GAME_OVER',
};

let state = STATES.MENU;
let prevState = null;
let canvas, ctx;
let frameCount = 0;
let bossIntroTimer = 0;
let menuBlink = 0;

// Score threshold to trigger boss
const BOSS_SCORE_THRESHOLD = 2000;
let bossTriggered = false;

export function getState() { return state; }

export function setState(s) {
  prevState = state;
  state = s;
}

export function getFrameCount() { return frameCount; }

export function initGame() {
  canvas = document.getElementById('game-canvas');
  ctx = canvas.getContext('2d');

  initInput();
  initAudio();
  initLogEngine();

  // Export button
  document.getElementById('export-btn').addEventListener('click', () => {
    exportLogs();
  });

  // Flush logs on page unload
  window.addEventListener('beforeunload', () => {
    const player = getPlayerState();
    if (player && state !== STATES.MENU) {
      emitGameEvent('session_end', { score: player.score, reason: 'page_unload' });
    }
  });

  // Start game loop
  requestAnimationFrame(gameLoop);
}

function startGame() {
  state = STATES.PLAYING;
  bossTriggered = false;
  frameCount = 0;
  clearParticles();

  createPlayer(CANVAS_W, CANVAS_H);
  initEnemies(CANVAS_W, CANVAS_H);
  initTerminals(CANVAS_W, CANVAS_H);

  emitGameEvent('session_start', {});
  emitGameEvent('user_login', { outcome: 'success' });

  document.getElementById('controls-legend').classList.remove('hidden');
}

function gameLoop(timestamp) {
  requestAnimationFrame(gameLoop);
  frameCount++;

  update();
  draw();
  clearJustPressed();
  updateLogBadge();
}

function update() {
  switch (state) {
    case STATES.MENU:
      menuBlink++;
      if (isJustPressed(' ') || isJustPressed('enter')) {
        playSound('start');
        startGame();
      }
      break;

    case STATES.PLAYING: {
      const player = getPlayerState();
      updatePlayer(CANVAS_W, CANVAS_H, ctx);
      updateEnemies(CANVAS_W, CANVAS_H, player);
      updateTerminals(player);

      // Check if boss should spawn
      if (!bossTriggered && player.score >= BOSS_SCORE_THRESHOLD) {
        bossTriggered = true;
        state = STATES.BOSS_INTRO;
        bossIntroTimer = 120; // 2 seconds
        emitGameEvent('boss_engage', { bossHp: 15 });
        playSound('bossIntro');
      }

      if (player.lives <= 0) {
        state = STATES.GAME_OVER;
        emitGameEvent('game_over', { score: player.score });
        emitGameEvent('session_end', { score: player.score });
        playSound('gameOver');
      }
      break;
    }

    case STATES.BOSS_INTRO:
      bossIntroTimer--;
      if (bossIntroTimer <= 0) {
        state = STATES.BOSS_FIGHT;
        initBoss(CANVAS_W, CANVAS_H);
      }
      break;

    case STATES.BOSS_FIGHT: {
      const player = getPlayerState();
      updatePlayer(CANVAS_W, CANVAS_H, ctx);
      updateBoss(CANVAS_W, CANVAS_H, player);

      if (isBossDefeated()) {
        state = STATES.PLAYING;
        emitGameEvent('boss_defeat', { score: player.score });
        playSound('bossDefeat');
        // Unlock terminals
        initTerminals(CANVAS_W, CANVAS_H, true);
      }

      if (player.lives <= 0) {
        state = STATES.GAME_OVER;
        emitGameEvent('game_over', { score: player.score });
        emitGameEvent('session_end', { score: player.score });
        playSound('gameOver');
      }
      break;
    }

    case STATES.PAUSED:
      if (isJustPressed('escape')) {
        state = prevState || STATES.PLAYING;
      }
      break;

    case STATES.GAME_OVER:
      if (isJustPressed(' ') || isJustPressed('enter')) {
        startGame();
      }
      break;
  }

  // Pause toggle (from playing states)
  if ((state === STATES.PLAYING || state === STATES.BOSS_FIGHT) && isJustPressed('escape')) {
    prevState = state;
    state = STATES.PAUSED;
  }
}

function draw() {
  drawBackground(ctx, CANVAS_W, CANVAS_H);

  switch (state) {
    case STATES.MENU:
      drawMenuScreen(ctx);
      break;

    case STATES.PLAYING:
      drawTerminals(ctx);
      drawEnemies(ctx);
      drawPlayer(ctx);
      updateAndDrawParticles(ctx);
      drawHUD(ctx, CANVAS_W);
      break;

    case STATES.BOSS_INTRO:
      drawPlayer(ctx);
      updateAndDrawParticles(ctx);
      drawBossIntro(ctx);
      drawHUD(ctx, CANVAS_W);
      break;

    case STATES.BOSS_FIGHT:
      drawTerminals(ctx);
      drawBoss(ctx);
      drawPlayer(ctx);
      updateAndDrawParticles(ctx);
      drawHUD(ctx, CANVAS_W);
      break;

    case STATES.PAUSED:
      // Draw game state underneath
      drawTerminals(ctx);
      if (isBossActive()) drawBoss(ctx);
      else drawEnemies(ctx);
      drawPlayer(ctx);
      drawHUD(ctx, CANVAS_W);
      // Pause overlay
      ctx.fillStyle = 'rgba(0, 0, 0, 0.6)';
      ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);
      drawText(ctx, '// SYSTEM PAUSED //', CANVAS_W / 2, CANVAS_H / 2 - 20, 40, '#ffcc00', 'center');
      drawText(ctx, '[ESC] to resume', CANVAS_W / 2, CANVAS_H / 2 + 30, 24, '#556655', 'center');
      break;

    case STATES.GAME_OVER:
      drawGameOverScreen(ctx);
      break;
  }
}

function drawMenuScreen(ctx) {
  // Title
  drawText(ctx, 'SYSTEM BREACH', CANVAS_W / 2, 180, 64, '#39ff14', 'center');
  drawText(ctx, 'ARCADE PROTOCOL v1.0', CANVAS_W / 2, 230, 28, '#00ffff', 'center');

  // Blinking prompt
  if (Math.floor(menuBlink / 30) % 2 === 0) {
    drawText(ctx, '>> PRESS [SPACE] TO INITIATE <<', CANVAS_W / 2, 350, 30, '#ffcc00', 'center');
  }

  // Instructions
  drawText(ctx, 'MISSION: Destroy enemy drones. Defeat the System Warden.', CANVAS_W / 2, 430, 22, '#556655', 'center');
  drawText(ctx, 'Access data terminals to extract intelligence.', CANVAS_W / 2, 460, 22, '#556655', 'center');
  drawText(ctx, 'All actions are logged for SIEM analysis.', CANVAS_W / 2, 500, 20, '#cc44ff', 'center');

  // Controls
  drawText(ctx, '[WASD] Move   [SPACE] Fire   [Q] Shockwave   [E] Interact', CANVAS_W / 2, 560, 20, '#334433', 'center');
}

function drawBossIntro(ctx) {
  ctx.fillStyle = 'rgba(0, 0, 0, 0.5)';
  ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);

  const flash = Math.floor(bossIntroTimer / 8) % 2 === 0;
  const color = flash ? '#ff3333' : '#cc44ff';
  drawText(ctx, '!! WARNING !!', CANVAS_W / 2, CANVAS_H / 2 - 40, 48, color, 'center');
  drawText(ctx, 'SYSTEM WARDEN DETECTED', CANVAS_W / 2, CANVAS_H / 2 + 20, 32, '#ffcc00', 'center');
}

function drawGameOverScreen(ctx) {
  const player = getPlayerState();
  ctx.fillStyle = 'rgba(42, 0, 0, 0.85)';
  ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);

  drawText(ctx, 'SYSTEM BREACH FAILED', CANVAS_W / 2, 200, 48, '#ff3333', 'center');
  drawText(ctx, `FINAL SCORE: ${player.score}`, CANVAS_W / 2, 280, 32, '#ffcc00', 'center');
  drawText(ctx, `RANK: ${getRank(player.score)}`, CANVAS_W / 2, 330, 28, '#00ffff', 'center');
  drawText(ctx, `LOGS GENERATED: ${getLogCount()}`, CANVAS_W / 2, 380, 24, '#cc44ff', 'center');

  if (Math.floor(frameCount / 30) % 2 === 0) {
    drawText(ctx, '>> PRESS [SPACE] TO RETRY <<', CANVAS_W / 2, 460, 28, '#ffcc00', 'center');
  }
}

export function getRank(score) {
  if (score >= 10000) return 'DIAMOND';
  if (score >= 6000) return 'PLATINUM';
  if (score >= 3000) return 'GOLD';
  if (score >= 1000) return 'SILVER';
  return 'BRONZE';
}

function updateLogBadge() {
  const badge = document.getElementById('log-count-badge');
  if (badge) badge.textContent = getLogCount();
}
