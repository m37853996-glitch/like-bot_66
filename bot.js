const express = require('express');
const app = express();
const PORT = process.env.PORT || 10000;

// سيرفر ويب وهمي للرد على طلبات استضافة رندر ومنع انقطاع البوت
app.get('/', (req, res) => {
    res.send('Bot is active and running 24/7!');
});

app.listen(PORT, () => {
    console.log(`Web server is running on port ${PORT}`);
});
