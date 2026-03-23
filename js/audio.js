// Procedural audio using Web Audio API

let audioCtx = null;
let masterGain = null;
let initialized = false;

export function initAudio() {
  // Defer AudioContext creation to first user interaction
  const unlock = () => {
    if (!initialized) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      masterGain = audioCtx.createGain();
      masterGain.gain.value = 0.3;
      masterGain.connect(audioCtx.destination);
      initialized = true;
    }
    document.removeEventListener('click', unlock);
    document.removeEventListener('keydown', unlock);
  };
  document.addEventListener('click', unlock);
  document.addEventListener('keydown', unlock);
}

function tone(freq, duration, type = 'square', volume = 0.3) {
  if (!audioCtx || !initialized) return;

  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();

  osc.type = type;
  osc.frequency.value = freq;
  gain.gain.value = volume;
  gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);

  osc.connect(gain);
  gain.connect(masterGain);

  osc.start(audioCtx.currentTime);
  osc.stop(audioCtx.currentTime + duration);
}

function noise(duration, volume = 0.1) {
  if (!audioCtx || !initialized) return;

  const bufferSize = audioCtx.sampleRate * duration;
  const buffer = audioCtx.createBuffer(1, bufferSize, audioCtx.sampleRate);
  const data = buffer.getChannelData(0);
  for (let i = 0; i < bufferSize; i++) {
    data[i] = Math.random() * 2 - 1;
  }

  const source = audioCtx.createBufferSource();
  const gain = audioCtx.createGain();
  source.buffer = buffer;
  gain.gain.value = volume;
  gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);

  source.connect(gain);
  gain.connect(masterGain);
  source.start(audioCtx.currentTime);
}

const SOUNDS = {
  shoot: () => {
    tone(800, 0.08, 'square', 0.15);
    tone(600, 0.05, 'square', 0.1);
  },
  hit: () => {
    tone(200, 0.15, 'sawtooth', 0.2);
    noise(0.1, 0.15);
  },
  explosion: () => {
    noise(0.3, 0.25);
    tone(100, 0.2, 'sawtooth', 0.2);
    tone(60, 0.3, 'sawtooth', 0.15);
  },
  terminal: () => {
    tone(600, 0.08, 'sine', 0.15);
    setTimeout(() => tone(800, 0.08, 'sine', 0.15), 80);
    setTimeout(() => tone(900, 0.1, 'sine', 0.15), 160);
  },
  denied: () => {
    tone(200, 0.15, 'square', 0.2);
    setTimeout(() => tone(150, 0.2, 'square', 0.2), 150);
  },
  shockwave: () => {
    tone(400, 0.1, 'sine', 0.2);
    tone(200, 0.3, 'sine', 0.3);
    noise(0.2, 0.1);
  },
  bossIntro: () => {
    tone(80, 0.5, 'sawtooth', 0.25);
    tone(60, 0.8, 'sawtooth', 0.2);
    noise(0.4, 0.1);
  },
  bossShoot: () => {
    tone(300, 0.1, 'square', 0.12);
    tone(200, 0.08, 'sawtooth', 0.1);
  },
  bossHit: () => {
    tone(150, 0.1, 'square', 0.2);
    noise(0.08, 0.15);
  },
  bossDefeat: () => {
    noise(0.5, 0.3);
    tone(100, 0.4, 'sawtooth', 0.25);
    setTimeout(() => tone(200, 0.3, 'sine', 0.2), 300);
    setTimeout(() => tone(400, 0.3, 'sine', 0.2), 500);
    setTimeout(() => tone(600, 0.4, 'sine', 0.25), 700);
  },
  start: () => {
    tone(400, 0.1, 'square', 0.15);
    setTimeout(() => tone(600, 0.1, 'square', 0.15), 100);
    setTimeout(() => tone(800, 0.15, 'square', 0.2), 200);
  },
  gameOver: () => {
    tone(400, 0.2, 'square', 0.2);
    setTimeout(() => tone(300, 0.2, 'square', 0.2), 200);
    setTimeout(() => tone(200, 0.3, 'square', 0.2), 400);
    setTimeout(() => tone(100, 0.5, 'sawtooth', 0.25), 600);
  },
};

export function playSound(name) {
  const soundFn = SOUNDS[name];
  if (soundFn) {
    try { soundFn(); } catch (e) { /* ignore audio errors */ }
  }
}
