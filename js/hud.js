// HUD: score, lives, rank, shockwave counter — rendered via DOM elements

import { getPlayerState } from './player.js';
import { getRank } from './engine.js';

let lastScore = -1;
let lastLives = -1;
let lastRank = '';

export function drawHUD(ctx, canvasW) {
  const player = getPlayerState();
  if (!player) return;

  // Update DOM HUD elements (only on change for performance)
  if (player.score !== lastScore) {
    lastScore = player.score;
    document.getElementById('hud-score').textContent = `SCORE: ${player.score}`;
  }

  if (player.lives !== lastLives) {
    lastLives = player.lives;
    const hearts = '\u2665'.repeat(Math.max(0, player.lives));
    document.getElementById('hud-lives').textContent = hearts;
  }

  const rank = getRank(player.score);
  if (rank !== lastRank) {
    lastRank = rank;
    document.getElementById('hud-rank').textContent = `RANK: ${rank}`;
  }

  // Draw shockwave counter on canvas (bottom-left area)
  if (player.shockwaves !== undefined) {
    ctx.font = '18px VT323';
    ctx.fillStyle = '#00ffff';
    ctx.textAlign = 'left';
    ctx.fillText(`SHOCKWAVE: ${player.shockwaves}`, 10, canvasW > 500 ? 640 : 620);
  }
}
