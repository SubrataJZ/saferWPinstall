const path = require('path');
const express = require('express');
const sitesRouter = require('./routes/sites');
const overviewRouter = require('./routes/overview');
const scheduler = require('./scheduler');

const app = express();
app.use(express.json());

app.use('/api', sitesRouter);
app.use('/api', overviewRouter);

app.use(express.static(path.join(__dirname, '..', 'public')));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`SaferWP dashboard listening on http://localhost:${PORT}`);
  if (!process.env.WPSCAN_API_TOKEN) {
    console.warn('WARNING: WPSCAN_API_TOKEN is not set. Vulnerability lookups will fail until you set it (get a free key at https://wpscan.com/api).');
  }
  scheduler.startAllEnabled();
});
