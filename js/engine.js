// Game loop, state machine, canvas management

import { initInput, clearJustPressed, isJustPressed, isTouchDevice, setMenuState } from './input.js';
import { drawBackground, updateAndDrawParticles, clearParticles, drawText, drawSprite, getCharacters, setSelectedCharacter, getSelectedCharacter } from './renderer.js';
import { createPlayer, updatePlayer, drawPlayer, getPlayerState } from './player.js';
import { initEnemies, updateEnemies, drawEnemies, getEnemies } from './enemies.js';
import { initBoss, updateBoss, drawBoss, getBoss, isBossActive, isBossDefeated } from './boss.js';
import { initTerminals, updateTerminals, drawTerminals } from './terminals.js';
import { initPowerups, updatePowerups, drawPowerups } from './powerups.js';
import { drawHUD } from './hud.js';
import { initAudio, playSound } from './audio.js';
import { initLogEngine, emitGameEvent, exportLogs, getLogCount } from './log-engine.js';

export const CANVAS_W = 1000;
export const CANVAS_H = 650;

export const STATES = {
  MENU: 'MENU',
  CHAR_SELECT: 'CHAR_SELECT',
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
let charSelectIndex = 0;
const charIds = ['ghost', 'viper', 'cipher', 'nova', 'hex'];

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
  setMenuState(false);
  bossTriggered = false;
  frameCount = 0;
  clearParticles();

  createPlayer(CANVAS_W, CANVAS_H);
  initEnemies(CANVAS_W, CANVAS_H);
  initTerminals(CANVAS_W, CANVAS_H);
  initPowerups(CANVAS_W, CANVAS_H);

  emitGameEvent('session_start', {});
  emitGameEvent('user_login', { outcome: 'success' });

  document.getElementById('controls-legend').classList.remove('hidden');
}

let __gameKicked = false;
window.addEventListener('siem:kicked', () => { __gameKicked = true; });

function gameLoop(timestamp) {
  if (__gameKicked) return;  // SOC killed the session — stop the loop
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
      setMenuState(true);
      menuBlink++;
      if (isJustPressed(' ') || isJustPressed('enter')) {
        playSound('start');
        state = STATES.CHAR_SELECT;
      }
      break;

    case STATES.CHAR_SELECT:
      if (isJustPressed('a') || isJustPressed('arrowleft')) {
        charSelectIndex = (charSelectIndex - 1 + charIds.length) % charIds.length;
        playSound('shoot');
      }
      if (isJustPressed('d') || isJustPressed('arrowright')) {
        charSelectIndex = (charSelectIndex + 1) % charIds.length;
        playSound('shoot');
      }
      if (isJustPressed(' ') || isJustPressed('enter')) {
        setSelectedCharacter(charIds[charSelectIndex]);
        playSound('start');
        startGame();
      }
      break;

    case STATES.PLAYING: {
      if (isJustPressed('escape')) {
        prevState = state;
        state = STATES.PAUSED;
        break;
      }
      const player = getPlayerState();
      const enemies = getEnemies();
      window.__gameEnemies = enemies; // expose for auto-attack
      updatePlayer(CANVAS_W, CANVAS_H, ctx);
      updateEnemies(CANVAS_W, CANVAS_H, player);
      updateTerminals(player);
      updatePowerups(player, enemies);

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
      if (isJustPressed('escape')) {
        prevState = state;
        state = STATES.PAUSED;
        break;
      }
      const player = getPlayerState();
      window.__gameEnemies = []; // no regular enemies during boss
      updatePlayer(CANVAS_W, CANVAS_H, ctx);
      updateBoss(CANVAS_W, CANVAS_H, player);
      updatePowerups(player, []);

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
      setMenuState(true);
      if (isJustPressed('escape')) {
        state = prevState || STATES.PLAYING;
        setMenuState(false);
      }
      break;

    case STATES.GAME_OVER:
      setMenuState(true);
      if (isJustPressed(' ') || isJustPressed('enter')) {
        state = STATES.CHAR_SELECT;
      }
      break;
  }
}

function draw() {
  drawBackground(ctx, CANVAS_W, CANVAS_H);

  switch (state) {
    case STATES.MENU:
      drawMenuScreen(ctx);
      break;

    case STATES.CHAR_SELECT:
      drawCharSelectScreen(ctx);
      break;

    case STATES.PLAYING:
      drawTerminals(ctx);
      drawPowerups(ctx);
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
      drawPowerups(ctx);
      drawBoss(ctx);
      drawPlayer(ctx);
      updateAndDrawParticles(ctx);
      drawHUD(ctx, CANVAS_W);
      break;

    case STATES.PAUSED:
      // Draw game state underneath
      drawTerminals(ctx);
      drawPowerups(ctx);
      if (isBossActive()) drawBoss(ctx);
      else drawEnemies(ctx);
      drawPlayer(ctx);
      drawHUD(ctx, CANVAS_W);
      // Pause overlay
      ctx.fillStyle = 'rgba(0, 0, 0, 0.6)';
      ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);
      drawText(ctx, '// SYSTEM PAUSED //', CANVAS_W / 2, CANVAS_H / 2 - 20, 40, '#ffcc00', 'center');
      const resumeMsg = isTouchDevice() ? 'Tap PAUSE to resume' : '[ESC] to resume';
      drawText(ctx, resumeMsg, CANVAS_W / 2, CANVAS_H / 2 + 30, 24, '#556655', 'center');
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
    const startMsg = isTouchDevice() ? '>> TAP TO INITIATE <<' : '>> PRESS [SPACE] TO INITIATE <<';
    drawText(ctx, startMsg, CANVAS_W / 2, 350, 30, '#ffcc00', 'center');
  }

  // Instructions
  drawText(ctx, 'MISSION: Destroy enemy drones. Defeat the System Warden.', CANVAS_W / 2, 430, 22, '#556655', 'center');
  drawText(ctx, 'Access data terminals to extract intelligence.', CANVAS_W / 2, 460, 22, '#556655', 'center');
  drawText(ctx, 'All actions are logged for SIEM analysis.', CANVAS_W / 2, 500, 20, '#cc44ff', 'center');

  // Controls
  if (!isTouchDevice()) {
    drawText(ctx, '[WASD] Move   [SPACE] Fire   [Q] Shockwave   [E] Interact', CANVAS_W / 2, 560, 20, '#334433', 'center');
  }
}

function drawCharSelectScreen(ctx) {
  const chars = getCharacters();
  const ids = charIds;

  drawText(ctx, 'SELECT OPERATIVE', CANVAS_W / 2, 80, 42, '#ffcc00', 'center');

  const cardW = 140;
  const totalW = ids.length * cardW + (ids.length - 1) * 16;
  const startX = (CANVAS_W - totalW) / 2;
  const cardY = 140;

  ids.forEach((id, i) => {
    const char = chars[id];
    const x = startX + i * (cardW + 16);
    const selected = i === charSelectIndex;

    // Card background
    ctx.fillStyle = selected ? 'rgba(57, 255, 20, 0.15)' : 'rgba(255,255,255,0.03)';
    ctx.fillRect(x, cardY, cardW, 340);

    // Border
    ctx.strokeStyle = selected ? char.colors[0] : '#334433';
    ctx.lineWidth = selected ? 3 : 1;
    ctx.strokeRect(x, cardY, cardW, 340);

    // Draw sprite large (centered in card)
    const spriteSize = 80;
    const spriteX = x + (cardW - spriteSize) / 2;
    const spriteY = cardY + 30;

    // Glow effect for selected
    if (selected) {
      ctx.shadowColor = char.colors[0];
      ctx.shadowBlur = 20;
      ctx.fillStyle = char.colors[0];
      ctx.fillRect(spriteX + spriteSize/2 - 2, spriteY + spriteSize/2 - 2, 4, 4);
      ctx.shadowBlur = 0;
    }

    drawSprite(ctx, null, spriteX, spriteY, spriteSize, char.colors, char.sprite);

    // Name
    drawText(ctx, char.name, x + cardW / 2, cardY + 140, selected ? 28 : 24, selected ? char.colors[0] : '#556655', 'center');

    // Description
    drawText(ctx, char.desc, x + cardW / 2, cardY + 170, 16, '#556655', 'center');

    // Color preview dots
    char.colors.forEach((c, ci) => {
      ctx.fillStyle = c;
      ctx.beginPath();
      ctx.arc(x + cardW/2 - 20 + ci * 20, cardY + 200, 6, 0, Math.PI * 2);
      ctx.fill();
    });

    // Selection arrow
    if (selected) {
      const arrowY = cardY + 300;
      if (Math.floor(frameCount / 20) % 2 === 0) {
        drawText(ctx, '▲', x + cardW / 2, arrowY, 28, char.colors[0], 'center');
      }
    }
  });

  // Instructions
  const mobile = isTouchDevice();
  if (mobile) {
    drawText(ctx, '◄ USE STICK TO SELECT ►', CANVAS_W / 2, 540, 26, '#556655', 'center');
    drawText(ctx, 'PRESS FIRE TO CONFIRM', CANVAS_W / 2, 575, 22, '#ffcc00', 'center');
  } else {
    drawText(ctx, '◄ [A/D] TO SELECT   [SPACE] TO CONFIRM ►', CANVAS_W / 2, 560, 24, '#556655', 'center');
  }
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
    const retryMsg = isTouchDevice() ? '>> TAP TO RETRY <<' : '>> PRESS [SPACE] TO RETRY <<';
    drawText(ctx, retryMsg, CANVAS_W / 2, 460, 28, '#ffcc00', 'center');
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
