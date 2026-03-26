// Canvas rendering: background, effects, sprites, particles

const COLORS = {
  bg: '#050507',
  gridDot: '#0a1a0a',
  gridLine: '#0a150a',
  player: ['#39ff14', '#2bcc0f', '#1a8a09'],
  enemy: ['#ff3333', '#cc2222', '#881111'],
  boss: ['#cc44ff', '#9933cc', '#661199'],
  terminal: ['#ffcc00', '#cc9900', '#886600'],
  terminalLocked: ['#556655', '#334433', '#223322'],
  projectilePlayer: '#39ff14',
  projectileEnemy: '#ff3333',
  projectileBoss: '#cc44ff',
  shockwave: '#00ffff',
  particle: ['#ff6600', '#ffcc00', '#ff3333', '#ff9900'],
};

// Character definitions
const CHARACTERS = {
  ghost: {
    name: 'GHOST',
    nameUa: 'ПРИВИД',
    desc: 'Stealth operative',
    colors: ['#39ff14', '#2bcc0f', '#1a8a09'],
    projectile: '#39ff14',
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,2,1,1,2,1,0],
      [1,1,1,1,1,1,1,1],
      [1,1,1,2,2,1,1,1],
      [0,1,1,1,1,1,1,0],
      [0,0,1,1,1,1,0,0],
      [0,1,3,0,0,3,1,0],
      [0,1,0,0,0,0,1,0],
    ],
  },
  viper: {
    name: 'VIPER',
    nameUa: 'ГАДЮКА',
    desc: 'Assault specialist',
    colors: ['#ff3333', '#ff6644', '#ffaa33'],
    projectile: '#ff4444',
    sprite: [
      [0,0,0,1,1,0,0,0],
      [0,0,1,2,2,1,0,0],
      [0,1,1,1,1,1,1,0],
      [1,3,1,1,1,1,3,1],
      [1,1,1,2,2,1,1,1],
      [0,1,1,1,1,1,1,0],
      [0,0,1,0,0,1,0,0],
      [0,1,3,0,0,3,1,0],
    ],
  },
  cipher: {
    name: 'CIPHER',
    nameUa: 'ШИФР',
    desc: 'Crypto analyst',
    colors: ['#00ffff', '#0099cc', '#006688'],
    projectile: '#00ffff',
    sprite: [
      [0,1,1,1,1,1,1,0],
      [1,2,2,1,1,2,2,1],
      [1,1,1,1,1,1,1,1],
      [0,1,3,1,1,3,1,0],
      [0,1,1,2,2,1,1,0],
      [0,0,1,1,1,1,0,0],
      [0,0,1,3,3,1,0,0],
      [0,1,1,0,0,1,1,0],
    ],
  },
  nova: {
    name: 'NOVA',
    nameUa: 'НОВА',
    desc: 'Energy weapons expert',
    colors: ['#cc44ff', '#ff44aa', '#ff88cc'],
    projectile: '#cc44ff',
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,3,2,2,3,1,0],
      [0,1,1,1,1,1,1,0],
      [1,1,1,1,1,1,1,1],
      [1,3,1,2,2,1,3,1],
      [0,1,1,1,1,1,1,0],
      [0,0,1,0,0,1,0,0],
      [0,0,3,0,0,3,0,0],
    ],
  },
  hex: {
    name: 'HEX',
    nameUa: 'ХЕКС',
    desc: 'Systems hacker',
    colors: ['#ffcc00', '#ff9900', '#cc6600'],
    projectile: '#ffcc00',
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,1,2,2,1,1,0],
      [1,2,1,1,1,1,2,1],
      [1,1,1,3,3,1,1,1],
      [1,1,1,1,1,1,1,1],
      [0,1,3,1,1,3,1,0],
      [0,0,1,1,1,1,0,0],
      [0,1,0,0,0,0,1,0],
    ],
  },
};

let selectedCharacter = 'ghost';

export function getCharacters() { return CHARACTERS; }
export function getSelectedCharacter() { return selectedCharacter; }
export function setSelectedCharacter(id) {
  selectedCharacter = id;
  const char = CHARACTERS[id];
  if (char) {
    COLORS.player = char.colors;
    COLORS.projectilePlayer = char.projectile;
    SPRITES.player = char.sprite;
  }
}

// Enemy type definitions
const ENEMY_TYPES = {
  drone: {
    name: 'Drone',
    colors: ['#ff3333', '#cc2222', '#881111'],
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,1,2,2,1,1,0],
      [1,1,2,1,1,2,1,1],
      [1,1,1,1,1,1,1,1],
      [0,1,3,1,1,3,1,0],
      [0,0,1,1,1,1,0,0],
      [0,0,0,1,1,0,0,0],
      [0,0,1,0,0,1,0,0],
    ],
  },
  spider: {
    name: 'Spider',
    colors: ['#ff6600', '#cc4400', '#993300'],
    sprite: [
      [1,0,0,1,1,0,0,1],
      [0,1,0,1,1,0,1,0],
      [0,0,1,2,2,1,0,0],
      [1,1,1,1,1,1,1,1],
      [0,0,1,2,2,1,0,0],
      [0,1,0,1,1,0,1,0],
      [1,0,0,1,1,0,0,1],
      [0,0,0,3,3,0,0,0],
    ],
  },
  skull: {
    name: 'Skull',
    colors: ['#ffffff', '#aaaaaa', '#ff3333'],
    sprite: [
      [0,0,1,1,1,1,0,0],
      [0,1,1,1,1,1,1,0],
      [1,1,2,1,1,2,1,1],
      [1,1,3,1,1,3,1,1],
      [0,1,1,1,1,1,1,0],
      [0,0,1,2,2,1,0,0],
      [0,0,2,1,1,2,0,0],
      [0,0,0,2,2,0,0,0],
    ],
  },
  bug: {
    name: 'Bug',
    colors: ['#44ff44', '#22aa22', '#116611'],
    sprite: [
      [0,1,0,0,0,0,1,0],
      [0,0,1,1,1,1,0,0],
      [0,1,2,1,1,2,1,0],
      [1,1,1,1,1,1,1,1],
      [1,3,1,1,1,1,3,1],
      [1,1,1,1,1,1,1,1],
      [0,1,0,1,1,0,1,0],
      [1,0,0,0,0,0,0,1],
    ],
  },
  sentinel: {
    name: 'Sentinel',
    colors: ['#ffcc00', '#ff9900', '#cc6600'],
    sprite: [
      [0,0,0,1,1,0,0,0],
      [0,0,1,2,2,1,0,0],
      [0,1,1,1,1,1,1,0],
      [1,3,1,2,2,1,3,1],
      [1,1,1,1,1,1,1,1],
      [0,1,1,3,3,1,1,0],
      [0,0,1,1,1,1,0,0],
      [0,1,0,0,0,0,1,0],
    ],
  },
};

const ENEMY_TYPE_IDS = Object.keys(ENEMY_TYPES);

export function getEnemyType(id) { return ENEMY_TYPES[id]; }
export function getRandomEnemyTypeId() {
  return ENEMY_TYPE_IDS[Math.floor(Math.random() * ENEMY_TYPE_IDS.length)];
}

// 8x8 sprite definitions (1 = primary, 2 = secondary, 3 = tertiary)
const SPRITES = {
  player: CHARACTERS.ghost.sprite,
  enemy: ENEMY_TYPES.drone.sprite,
  boss: [
    [0,1,1,1,1,1,1,0],
    [1,2,1,1,1,1,2,1],
    [1,1,2,3,3,2,1,1],
    [1,1,1,1,1,1,1,1],
    [1,3,1,1,1,1,3,1],
    [1,1,1,3,3,1,1,1],
    [0,1,1,1,1,1,1,0],
    [0,0,1,0,0,1,0,0],
  ],
  terminal: [
    [1,1,1,1,1,1,1,1],
    [1,2,2,2,2,2,2,1],
    [1,2,3,2,3,2,2,1],
    [1,2,2,2,2,3,2,1],
    [1,2,3,3,2,2,2,1],
    [1,2,2,2,2,2,2,1],
    [1,1,1,1,1,1,1,1],
    [0,0,1,1,1,1,0,0],
  ],
};

let particles = [];

export function drawBackground(ctx, w, h) {
  ctx.fillStyle = COLORS.bg;
  ctx.fillRect(0, 0, w, h);

  // Grid dots
  ctx.fillStyle = COLORS.gridDot;
  const spacing = 40;
  for (let x = 0; x < w; x += spacing) {
    for (let y = 0; y < h; y += spacing) {
      ctx.fillRect(x, y, 2, 2);
    }
  }
}

export function drawSprite(ctx, name, x, y, size, colorSet, spriteData) {
  const sprite = spriteData || SPRITES[name];
  if (!sprite) return;

  const colors = colorSet || COLORS[name] || COLORS.player;
  const px = size / 8;

  for (let row = 0; row < 8; row++) {
    for (let col = 0; col < 8; col++) {
      const val = sprite[row][col];
      if (val > 0) {
        ctx.fillStyle = colors[val - 1] || colors[0];
        ctx.fillRect(
          x + col * px,
          y + row * px,
          px + 0.5,
          px + 0.5
        );
      }
    }
  }
}

export function drawProjectile(ctx, x, y, radius, color) {
  ctx.fillStyle = color || COLORS.projectilePlayer;
  ctx.shadowColor = color || COLORS.projectilePlayer;
  ctx.shadowBlur = 8;
  ctx.beginPath();
  ctx.arc(x, y, radius, 0, Math.PI * 2);
  ctx.fill();
  ctx.shadowBlur = 0;
}

export function drawShockwave(ctx, x, y, radius, alpha) {
  ctx.strokeStyle = COLORS.shockwave;
  ctx.globalAlpha = alpha;
  ctx.lineWidth = 3;
  ctx.shadowColor = COLORS.shockwave;
  ctx.shadowBlur = 15;
  ctx.beginPath();
  ctx.arc(x, y, radius, 0, Math.PI * 2);
  ctx.stroke();
  ctx.globalAlpha = 1;
  ctx.shadowBlur = 0;
}

export function drawHPBar(ctx, x, y, w, h, ratio, color) {
  ctx.fillStyle = '#222';
  ctx.fillRect(x, y, w, h);
  ctx.fillStyle = color || '#ff3333';
  ctx.fillRect(x, y, w * ratio, h);
  ctx.strokeStyle = '#666';
  ctx.lineWidth = 1;
  ctx.strokeRect(x, y, w, h);
}

export function drawText(ctx, text, x, y, size, color, align) {
  ctx.font = `${size}px VT323`;
  ctx.fillStyle = color || '#39ff14';
  ctx.textAlign = align || 'left';
  ctx.fillText(text, x, y);
  ctx.textAlign = 'left';
}

// Particles
export function spawnParticles(x, y, count, speed) {
  for (let i = 0; i < (count || 15); i++) {
    const angle = Math.random() * Math.PI * 2;
    const vel = (speed || 3) * (0.5 + Math.random());
    particles.push({
      x, y,
      vx: Math.cos(angle) * vel,
      vy: Math.sin(angle) * vel,
      life: 30 + Math.random() * 20,
      maxLife: 50,
      color: COLORS.particle[Math.floor(Math.random() * COLORS.particle.length)],
      size: 2 + Math.random() * 3,
    });
  }
}

export function updateAndDrawParticles(ctx) {
  for (let i = particles.length - 1; i >= 0; i--) {
    const p = particles[i];
    p.x += p.vx;
    p.y += p.vy;
    p.vx *= 0.96;
    p.vy *= 0.96;
    p.life--;

    if (p.life <= 0) {
      particles.splice(i, 1);
      continue;
    }

    ctx.globalAlpha = p.life / p.maxLife;
    ctx.fillStyle = p.color;
    ctx.fillRect(p.x - p.size / 2, p.y - p.size / 2, p.size, p.size);
  }
  ctx.globalAlpha = 1;
}

export function clearParticles() {
  particles = [];
}

export { COLORS };
