import { createApp, getConfig } from './server.js';

const config = getConfig();
createApp().listen(config.PORT, () => {
  console.log(`api listening on ${config.PORT}`);
});
