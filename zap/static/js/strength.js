'use strict';

const input = document.getElementById('password');
const meter = document.getElementById('strength');

const LEVELS = [
  ['Very weak', 'strength-0'],
  ['Weak', 'strength-1'],
  ['Fair', 'strength-2'],
  ['Strong', 'strength-3'],
  ['Very strong', 'strength-4'],
];

function score(password) {
  if (!password) return 0;
  let variety = 0;
  if (/[a-z]/.test(password)) variety += 1;
  if (/[A-Z]/.test(password)) variety += 1;
  if (/\d/.test(password)) variety += 1;
  if (/[^A-Za-z0-9]/.test(password)) variety += 1;
  let s = 0;
  if (password.length >= 12) s += 1;
  if (password.length >= 16) s += 1;
  if (variety >= 3) s += 1;
  if (variety === 4 && password.length >= 14) s += 1;
  return s;
}

input.addEventListener('input', () => {
  const password = input.value;
  const hints = [];
  if (password.length < 12) hints.push('use at least 12 characters');
  if (!/[A-Za-z]/.test(password)) hints.push('add letters');
  if (!/\d/.test(password)) hints.push('add a digit');
  if (!/[^A-Za-z0-9]/.test(password)) hints.push('symbols help');
  const [label, cls] = LEVELS[score(password)];
  meter.className = `strength ${cls}`;
  meter.textContent = password
    ? `Strength: ${label}${hints.length ? ' (' + hints.join(', ') + ')' : ''}`
    : '';
});
