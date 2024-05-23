/*const firebase = require('firebase/app');
require('firebase/storage'); // If you're using Firebase Storage
const admin = require('firebase-admin');
const serviceAccount = require('./path/to/serviceAccountKey.json');

const firebaseConfig = {
    apiKey: "AIzaSyDsoIadKRYNUrq_4tKIjRleaTR-UpGabzs",
    authDomain: "bby24-c12c5.firebaseapp.com",
    projectId: "bby24-c12c5",
    storageBucket: "bby24-c12c5.appspot.com",
    messagingSenderId: "790246092587",
    appId: "1:790246092587:web:f59b7ffe6e1b3b83ba1f6e"
  };

firebase.initializeApp(firebaseConfig);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: "bby24-c12c5.appspot.com"
});

const bucket = admin.storage().bucket(); */

require("./utils.js");
require('dotenv').config();
//require('firebase/storage');


//const multer = require('multer');
//const upload = multer({ storage: multer.memoryStorage() });
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

// Mongodb setup
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');
const matchuserCollection = database.db(mongodb_database).collection('matchuser');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
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


//Set up mailing service
const nodemailer = require('nodemailer')
const { google } = require('googleapis')
// const config = require('./config.js')
const OAuth2 = google.auth.OAuth2

const OAuth2_client = new OAuth2(process.env.EMAIL_CLIENT_ID, process.env.EMAIL_CLIENT_SECRET)
OAuth2_client.setCredentials({ refresh_token: process.env.EMAIL_REFRESH_TOKEN })

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
  var message = req.query.msg ? req.query.msg : '';
  res.render('pages/forgot-password', { msg: message });

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


  } catch (error) { }
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


//Landing page 
app.get('/', (req, res) => {

  res.render('pages/landing');

});

//Home Page
app.get('/home', async(req, res) => {

  const loggedIn = req.session.authenticated;
  if (loggedIn) {

      const userEmail = req.session.email;
      console.log(userEmail);
      const query = { email: userEmail };
      const user = await matchuserCollection.findOne(query);
      const save = user.matchuser_email;
      const querysave = { email: { $in: save } };
      const saveuser = await userCollection.find(querysave).toArray();
      console.log(saveuser);
      
      res.render('pages/index', {loggedIn, username:req.session.name, users: saveuser, currentPath: req.path });
  } else {
    res.render('pages/landing');
  }
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
  await userCollection.insertOne({ name: name, email: email, password: hashedPassword, age: age, user_type: "user" });
  // const pipeline = [
  //   {
  //       $project: {
  //           _id: 0,
  //           name: 1,
  //           email: 1
  //       }
  //   },
  //   {
  //       $merge: "matchuser"
  //   }
  // ];
  // const cursor = await userCollection.aggregate(pipeline);
  await matchuserCollection.insertOne({ name: name, email: email});   

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
      biography: userProfile.biography || '',  // Provide an empty string if biography is undefined
      profilePicUrl: userProfile.profilePicUrl || '/img/default-profile.png' // Default profile picture
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).send("Failed to fetch profile.");  // Internal Server Error for unexpected issues
  }
});

app.get('/editUserProfile', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }

  // Render the edit user profile page
  res.render('pages/editUserProfile', {
    name: req.session.name,
    email: req.session.email,
    age: req.session.age,
    biography: req.session.biography || ''
  });
});


//Edit Profile
app.post('/updateProfile', async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }

  const { name, age, biography } = req.body;
  try {
    await userCollection.updateOne(
      { email: req.session.email },
      { $set: { name: name, age: age, biography: biography } }
    );
    // Update session variables
    req.session.name = name;
    req.session.age = age;
    req.session.biography = biography;
    res.redirect('/profile');  // Redirect to the profile page after update
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.send("Failed to update profile.");
  }
});

// app.post('/uploadProfilePicture', upload.single('profilePic'), async (req, res) => {
//     if (!req.session.authenticated) {
//         res.redirect('/login');
//         return;
//     }

//     if (!req.file) {
//         return res.status(400).send('No file uploaded.');
//     }

//     const blob = bucket.file(`profile-pictures/${Date.now()}-${req.file.originalname}`);
//     const blobStream = blob.createWriteStream({
//         metadata: {
//             contentType: req.file.mimetype
//         }
//     });

//     blobStream.on('error', (error) => {
//         console.error('Error uploading file to Firebase Storage:', error);
//         res.status(500).send('Unable to upload at the moment.');
//     });

//     blobStream.on('finish', async () => {
//         const publicUrl = `https://storage.googleapis.com/${bucket.name}/${blob.name}`;
//         await userCollection.updateOne(
//             { email: req.session.email },
//             { $set: { profilePicUrl: publicUrl } }
//         );
//         req.session.profilePicUrl = publicUrl;
//         res.redirect('/profile');
//     });

//     blobStream.end(req.file.buffer);
// });

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

app.get('/matching', async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }
  //const { email} = req.session.email;
  const hashedPassword = req.session.hashedPassword;
  let lowAge = +req.session.age - 5
  let highAge = +req.session.age + 5

  try {

    const matchuser = await userCollection.find({
      age: { $gt: "" + lowAge, $lt: "" + highAge },
      email: { $ne: req.session.email },
    }).toArray();

    console.log("=========================");
    console.log(matchuser);
    res.render("pages/matching", { users: matchuser, currentPath: req.path });

  } catch (error) {
    res.status(500).send('Error accessing user data');
  }

});

app.post('/saveUser', async (req, res) => {
 
    const email = req.body.matchEmail;
    console.log(email);
    const query = { email: req.session.email };
    const update = {
      $push: { 
          matchuser_email: email
      }
  };
     await matchuserCollection.updateOne(query,update);
     res.redirect('/matching');
});



