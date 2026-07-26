import { main } from './activation-cli.js';

void main(process.argv.slice(2)).then(code => { process.exitCode = code; }, () => {
  process.stderr.write('OIDC activation unavailable\n');
  process.exitCode = 1;
});
