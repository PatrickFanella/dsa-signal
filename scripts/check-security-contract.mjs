import { readFileSync } from 'node:fs';

const contract = readFileSync('docs/reference/privacy-and-threat-contract.md', 'utf8');
const adr = readFileSync('docs/adr/0002-matrix-e2ee-substrate.md', 'utf8');
const readme = readFileSync('README.md', 'utf8');
const plan = readFileSync('docs/superpowers/plans/2026-07-16-membership-gated-e2ee-chat.md', 'utf8');
const contractText = contract.replace(/\s+/g, ' ');

function requireText(document, description, text) {
  if (!document.includes(text)) {
    throw new Error(`missing ${description}: ${text}`);
  }
}

for (const heading of [
  '# Privacy and Threat Contract',
  '## Scope and acceptance',
  '## Explicit limits and invariants',
  '## Trust-boundary register',
  '## Operational assertions',
]) requireText(contract, 'contract heading', heading);

for (const boundary of [
  'Participating client', 'Web origin', 'Node control plane',
  'Membership credential issuer', '`dsa-proto`', 'MAS', 'Synapse',
  'Control-plane and Matrix databases', 'Media storage', 'Push infrastructure',
  'Logs, metrics, traces, and support tooling', 'Backups',
  'TLS terminators and reverse proxies', 'TURN/SFU and calls infrastructure',
  'Network observer', 'Malicious member', 'Stolen device',
  'Compromised operator', 'Client dependency compromise',
  'Server/build dependency compromise',
]) requireText(contract, 'trust-boundary row', `| ${boundary} |`);

for (const statement of [
  'Only server-side `dsa-signal` services must not receive',
  'participating PWA necessarily decrypts',
  'must not store membership/entitlement credentials, downstream Matrix credentials',
  'legitimately holds its own ATProto session credentials',
  'clients encrypt before upload and verify the ciphertext hash before use',
  'Storage only authenticates access and stores opaque bytes',
  'Acceptance was recorded on 2026-07-16',
  'This acceptance authorizes Task 2 only',
]) requireText(contractText, 'required contract statement', statement);

requireText(
  plan.replace(/\s+/g, ' '),
  'plan credential boundary',
  '`dsa-proto` never stores membership/entitlement credentials, downstream Matrix credentials, rosters, chat metadata, or messages. It may retain its own encrypted ATProto session credentials',
);

for (const marker of [
  '# ADR 0002: Use Matrix as the E2EE Communications Substrate',
  '## Status', 'Accepted conditionally for the G0 design gate.', '## Decision',
  'Use a private, non-federating Matrix deployment as the messaging substrate:',
  '## Consequences', '## Alternatives considered',
  '### Greenfield OpenMLS', 'Rejected for the initial product.',
  '### Server-readable chat', 'Rejected.',
]) requireText(adr, 'ADR decision marker', marker);

requireText(
  readme,
  'README warning',
  '> This project is not affiliated or interoperable with Signal. Matrix E2EE protects message content, not service-visible account, room, device, timing, IP, or access metadata. The web client remains vulnerable to a compromised application origin.',
);
