const mongoose = require('mongoose');
mongoose.set('useCreateIndex', true);

mongoose.set('useFindAndModify', false);
mongoose.connect('mongodb://localhost/noderest', { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.Promise = global.Promise;

module.exports = mongoose;