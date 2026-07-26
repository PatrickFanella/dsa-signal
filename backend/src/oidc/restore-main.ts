import { main } from './restore-cli.js';

void main(process.argv.slice(2)).then(code => { process.exitCode = code; }, () => {
  process.stderr.write('OIDC restore unavailable\n');
  process.exitCode = 1;
});
