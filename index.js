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

//Landing page 
app.get('/', (req, res) => {
   
    res.render('pages/landing');

});

//Home Page
app.get('/home', (req, res) => {
    // Check if user is logged in from the session
    const loggedIn = req.session.authenticated;
    if (loggedIn){
        res.render('pages/index', {name: req.session.name});
    }else{
        res.render('pages/landing');
    }
    // Render the homepage template with the loggedIn status
    

});

//Sign Up
app.get('/signup', (req, res) => {
    res.render('pages/signup');
});

app.post('/signupSubmit', async (req, res) => {

    const { name, email, password, age } = req.body;
    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(20).required(),
            password: Joi.string().max(20).required(),
            age: Joi.number().integer().min(1).max(120).required()
        });

    const validationResult = schema.validate({ name, email, password, age });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
    //Set the session as authenticated, Store the user's name in the session for future use and Set the expiration time of the session cookie
    await userCollection.insertOne({ name: name, email: email, password: hashedPassword, age: age, user_type: "user"});
    req.session.authenticated = true;
    req.session.name = name;
    req.session.age = age;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/profile');
    //res.send("create user success")
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

    //const schema = Joi.string().max(20).required();
    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    // const query = { email: email };
    // const options = {
        // Sort matched documents in descending order by rating
        // sort: { "name": -1 },
        // Include only the `title` and `imdb` fields in the returned document
       // projection: { name: 1, password: 1, user_type: 1, _id: 1 },
    // };
    // const result = await userCollection.findOne(query, options);

    const result = await userCollection.findOne({ email: email });
    console.log("Fetched user:", result);
    if (result) {
        console.log("Email from DB:", result.email);
    }

    if (result === null) {
        console.log('No document matches the provided query.');
        //res.redirect('/loginError');
		res.send("login error")
    } else {
        if (await bcrypt.compare(password, result.password)) {
            console.log("correct password");
            req.session.authenticated = true;
            req.session.name = result.name;
            req.session.age = result.age;
            req.session.email = result.email;
            req.session.biography = result.biography;
            req.session.user_type = result.user_type;
            req.session.cookie.maxAge = expireTime;
            console.log("Session email set to:", req.session.email)
            res.redirect('/home');
			//res.send("login success")
        } else {
            console.log('wrong password.');
            //res.redirect('/loginError');
			res.send("login error")
        }
    }
});

//Profiles page. 
app.get('/profile', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    console.log("Fetching profile for email:", req.session.email);  // Debugging output

    try {
        const userProfile = await userCollection.findOne({ email: req.session.email });
        if (!userProfile) {
            console.log('User profile not found for email:', req.session.email);
            res.status(404).send("Profile not found");  // More appropriate HTTP status code for not found
            return;
        }

        res.render('pages/profile', {
            name: userProfile.name,
            email: userProfile.email,
            age: userProfile.age,
            biography: userProfile.biography || ''  // Provide an empty string if biography is undefined
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).send("Failed to fetch profile.");  // Internal Server Error for unexpected issues
    }
});



//Edit Profile
app.post('/updateProfile', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    const { biography } = req.body;
    try {
        await userCollection.updateOne(
            { email: req.session.email }, // use email to identify the user document
            { $set: { biography: biography } }
        );
        req.session.biography = biography; // Update session with new biography
        res.redirect('/profile');
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.send("Failed to update profile.");
    }
});

//signout
app.get('/signout', function (req, res) {
    req.session.destroy(function (err) {
        if (err) {
            console.log(err);
            res.send("Error signing out");
        } else {
            let loggedIn = false;
            res.render('pages/landing'); 
        }
    });
});

//Events skeleton
app.get('/events', (req, res) => {
    // Check if user is logged in from the session
    const loggedIn = req.session.authenticated;
    // Render the homepage template with the loggedIn status
    res.render('pages/events', { loggedIn, currentPath: req.path });

});