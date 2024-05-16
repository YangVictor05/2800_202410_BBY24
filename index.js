require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');

const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

// database setup
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');
app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.set('view engine', 'ejs');  // Set EJS as the templating engine
app.set('views', './views'); // default path for EJS templates

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.use('/img', express.static(__dirname + '/public/img'));
app.use('/css', express.static(__dirname + '/public/css'));

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});

//Home Page
app.get('/', (req, res) => {
    // Check if user is logged in from the session
    const loggedIn = req.session.authenticated;
    // Render the homepage template with the loggedIn status
    res.render('pages/index', { loggedIn });

});

//Login Page
app.get('/login', (req, res) => {
    const missingCredentials = req.query.missing;
	console.log("0");
    res.render('pages/login', { missingCredentials });
	
});

// app.get('/loginError', (req, res) => {
//     res.render('pages/loginError')
// });

app.post('/submitLogin', async (req, res) => {
	console.log(req.body);
    const { email, password } = req.body;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const query = { email: email };
    const options = {
        // Sort matched documents in descending order by rating
        sort: { "name": -1 },
        // Include only the `title` and `imdb` fields in the returned document
        projection: { name: 1, password: 1, user_type: 1, _id: 1 },
    };
    const result = await userCollection.findOne(query, options);

    if (result === null) {
        console.log('No document matches the provided query.');
        //res.redirect('/loginError');
		res.send("login error")
    } else {
        if (password==result.password) {
            console.log("correct password");
            req.session.authenticated = true;
            req.session.name = result.name;
            req.session.user_type = result.user_type;
            req.session.cookie.maxAge = expireTime;
            //res.redirect('/memberpage/');
			res.send("login success")
        } else {
            console.log('worng password.');
            //res.redirect('/loginError');
			res.send("login error")
        }
    }
});

//Events skeleton
app.get('/events', (req, res) => {
    // Check if user is logged in from the session
    const loggedIn = req.session.authenticated;
    // Render the homepage template with the loggedIn status
    res.render('pages/events', { loggedIn });

});