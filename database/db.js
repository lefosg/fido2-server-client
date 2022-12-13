const mongoose = require('mongoose');
mongoose.set('strictQuery', false);

mongoose.connect('mongodb://localhost:27017/fido2credentials')
    .then(() => console.log('connected to database'))
    .catch((err) => console.log(err));