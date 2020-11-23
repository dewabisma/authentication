// Require Library
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
// const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

// Bcrypt Options
// const saltRounds = 10;

// Secret
const secret = process.env.SECRET;

// Use Express

const app = express();

app.use(bodyParser.urlencoded({
    extended: true
}));

app.set('view engine', 'ejs');
app.use(express.static('public'));

app.use(session({
    secret: secret,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Set Up DB Connection
mongoose.connect('mongodb://localhost:27017/userDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

userSchema.plugin(passportLocalMongoose);

// userSchema.plugin(encrypt, {
//     secret: secret,
//     encryptedFields: ['password']
// });

const User = mongoose.model('user', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Set Up Route
app.get('/', (req, res) => {
    res.render('home');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const userData = req.body;

    User.findOne({
        email: userData.username
    }, (err, found) => {
        if (!found) {
            console.log(err);
            console.log("There is no such email registered yet!");
        } else {
            bcrypt.compare(userData.password, found.password, (err, match) => {
                if (match) {
                    res.render('secrets');
                } else {
                    console.log("Wrong Password");
                }
            });
        }
    })
})

app.get('/register', (req, res) => {
    res.render('register');
})

app.post('/register', (req, res) => {
    User.register({username:req.body.username}, req.body.password, (err, user) {
        if (err) {
            console.log(err);
            res.redirect('/login');
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('secrets');
            })
        }
    })

});

app.get('/secrets', (req, res) => {
    res.render('secrets');
})

app.get('/submit', (req, res) => {
    res.render('submit');
});

// Set Up Connection
app.listen(5050, (req, res) => {
    console.log('connected to port 5050');
});