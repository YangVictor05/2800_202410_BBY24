require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const { ObjectId } = require('mongodb');

// JWT Setup
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

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

//Set up mailing service
const nodemailer = require('nodemailer')
const { google } = require('googleapis')
// const config = require('./config.js')
const OAuth2 = google.auth.OAuth2

const OAuth2_client = new OAuth2(process.env.EMAIL_CLIENT_ID, process.env.EMAIL_CLIENT_SECRET)
OAuth2_client.setCredentials( { refresh_token : process.env.EMAIL_REFRESH_TOKEN })

function send_mail(name, recipient, text) {
  const accessToken = OAuth2_client.getAccessToken()

  const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      type: 'OAuth2',
      user: process.env.EMAIL_USER,
      clientId: process.env.EMAIL_CLIENT_ID,
      clientSecret: process.env.EMAIL_CLIENT_SECRET,
      refreshToken: process.env.EMAIL_REFRESH_TOKEN,
      accessToken: accessToken

    }

  })

  const mail_options = {
    from: 'LinkUp <${process.env.EMAIL_USER}>',
    to: recipient,
    subject: 'Reset LinkUp Password',
    html: get_html_message(name, text)
  }

  transport.sendMail(mail_options, function (error, result) {
    if (error) {
      console.log('Error: ', error)
    } else {
      console.log('Success: ', result)
    }
    transport.close()

  })

}

function get_html_message(name, text) {
  return `
  <p>Hi ${name}, </p>
  <p> <a href="${text}">${text}</a> </p>
  `
}



app.get('/reset', (req, res) => {
    var message  = req.query.msg ? req.query.msg : '';
    res.render('pages/forgot-password', {msg:message});

});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    
    try {
        const oldUser = await userCollection.findOne({ email });
        if (!oldUser) {
            console.log("Use Not found");
          return res.redirect("/reset?msg=This is not a valid email.");
        }
        const secret = JWT_SECRET + oldUser.password;
        const token = jwt.sign({ email: oldUser.email, id: oldUser._id }, secret, {
          expiresIn: "5m",
        });
        const link = `${process.env.HOST_URL}/reset-password/${oldUser._id}/${token}`;
        

        console.log(oldUser);

        send_mail(oldUser.name, email, link);
        return res.redirect("/reset?msg=An email to reset your password has been set to your inbox. Please check your email to proceed.");
        
        
      } catch (error) {}
});

app.get("/reset-password/:id/:token", async (req, res) => {
    const { id, token } = req.params;
    console.log(req.params);
    const allUserIds = await userCollection.find({}, { _id: 1 }).toArray();
    console.log(allUserIds);
    const userId = ObjectId(id);


    const oldUser = await userCollection.findOne({ _id: userId });
    if (!oldUser) {

      return res.json({ status: "User Not Exists!!" });
    }
    const secret = JWT_SECRET + oldUser.password;
    try {
      const verify = jwt.verify(token, secret);
      res.render('pages/reset-password', { email: verify.email, status: "Not verified" });
    } catch (error) {
      console.log(error);
      res.send("Not Verified");
    }
  });
  
  app.post("/reset-password/:id/:token", async (req, res) => {
    const { id, token } = req.params;
    const { password } = req.body;

    const userId = ObjectId(id);
  
    const oldUser = await userCollection.findOne({ _id: userId });
    if (!oldUser) {
      return res.json({ status: "User Not Exists!!" });
    }
    const secret = JWT_SECRET + oldUser.password;
    try {
      const verify = jwt.verify(token, secret);
      const encryptedPassword = await bcrypt.hash(password, saltRounds);
      await userCollection.updateOne(
        {
          _id: userId,
        },
        {
          $set: {
            password: encryptedPassword,
          },
        }
      );
  
      res.render('pages/reset-password', { email: verify.email, status: "verified" });
    } catch (error) {
      console.log(error);
      res.json({ status: "Something Went Wrong" });
    }
  });

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
        if (await bcrypt.compare(password, result.password)) {
            console.log("correct password");
            req.session.authenticated = true;
            req.session.name = result.name;
            req.session.age = result.age;
            req.session.email = result.email;
            req.session.biography = result.biography;
            req.session.user_type = result.user_type;
            req.session.cookie.maxAge = expireTime;
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

    try {
        // Fetch the complete user profile from the database
        console.log("Looking for user with email:", req.session.email);
        const userProfile = await userCollection.findOne({ email: req.session.email });
        if (!userProfile) {
            console.log('User profile not found.');
            res.send("Profile not found");
            return;
        }

        // Ensure userProfile is defined and use the properties directly
        res.render('pages/profile', {
            name: userProfile.name,
            email: userProfile.email,
            age: userProfile.age,
            biography: userProfile.biography || '' // Provide an empty string if biography is undefined
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.send("Failed to fetch profile.");
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