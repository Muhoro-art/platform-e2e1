const { createApp } = require('./app');

const app = createApp();
const port = Number(process.env.PORT || 3000);

app.locals.ready.then(() => {
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Server listening on port ${port}`);
  });
});
