require("./utils.js");
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const { ObjectId } = require('mongodb');
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;
const saltRounds = 12;
const port = process.env.PORT || 3000;
const app = express();
const router = express.Router();
const Joi = require("joi");
const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)
const http = require('http');

//Cloudinary config.
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer configuration
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'profile_pictures',
    format: async (req, file) => 'png', // supports promises as well
    public_id: (req, file) => file.originalname,
  },
});

const parser = multer({ storage: storage });

app.use(express.urlencoded({ extended: false }));





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
const messagesCollection = database.db(mongodb_database).collection("messages");
const eventInfoCollection = database.db(mongodb_database).collection("event_Info");

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



// Socket.io setup
const socketIo = require('socket.io');
const server = http.createServer(app);
const io = socketIo(server);

server.listen(port, () => {
  console.log("Node application listening on port " + port);
});


//Password reset

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
      return res.redirect("/reset?msg=If you have an account with us, an email to reset your password has been sent to your inbox. Please check your email to proceed.");
    }
    const secret = JWT_SECRET + oldUser.password;
    const token = jwt.sign({ email: oldUser.email, id: oldUser._id }, secret, {
      expiresIn: "5m",
    });
    const link = `${process.env.HOST_URL}/reset-password/${oldUser._id}/${token}`;


    console.log(oldUser);

    send_mail(oldUser.name, email, link);
    return res.redirect("/reset?msg=If you have an account with us, an email to reset your password has been sent to your inbox. Please check your email to proceed.");


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
app.get('/home', async (req, res) => {

  const loggedIn = req.session.authenticated;
  if (loggedIn) {
    const userEmail = req.session.email;
    console.log(userEmail);
    const query = { email: userEmail };
    const user = await matchuserCollection.findOne(query);
    const save = user.matchuser_email;
    const querysave = { email: { $in: save } };
    const events = await eventInfoCollection.find().toArray();
  try {
    const saveuser = await userCollection.find(querysave).toArray();
    const usersWithDefaultPics = saveuser.map(user => ({
      ...user,
      profilePicture: user.profilePicture || '/img/defaultprofilepic.png'
    }));

    console.log("==============================");
    console.log(req.session.name);
    res.render('pages/index', { loggedIn, username: req.session.name, event: events, users: usersWithDefaultPics, currentPath: req.path });


  } catch (error) {
    res.status(500).send('Error accessing user data');
  }
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
  const schema = Joi.object({
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

  await userCollection.insertOne({ name: name, email: email, password: hashedPassword, age: age, user_type: "user" });
  await matchuserCollection.insertOne({ name: name, email: email, matchuser_email: [] });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.age = age;
  req.session.email = email;
  req.session.cookie.maxAge = expireTime;
  res.redirect('/profile');
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
      profilePicture: userProfile.profilePicture || '/img/defaultprofilepic.png', // Default profile picture
      currentPath: req.path
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

app.post('/uploadProfilePicture', parser.single('image'), async (req, res) => {
  try {
    const imageUrl = req.file.path; // Cloudinary URL
    const email = req.session.email; // Assuming email is stored in the session

    const result = await userCollection.updateOne(
      { email: email },
      { $set: { profilePicture: imageUrl } }
    );

    if (result.matchedCount === 0) return res.status(404).send('User not found');

    res.redirect('/profile'); // Redirect to the profile page
  } catch (err) {
    res.status(500).send(err.message);
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
app.get('/events', async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }
  const events = await eventInfoCollection.find().toArray();
  res.render('pages/event_all', {currentPath: req.path, events: events});

});

app.get('/event_creation', (req, res) => {

  const loggedIn = req.session.authenticated;

  res.render('pages/event_creation', { loggedIn, currentPath: req.path });

});

app.get('/event_edit', async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }
  res.render('pages/event_edit', { currentPath: req.path });
});


app.post('/submitEvent', parser.single('event_picture'), async (req, res) => {
  const loggedIn = req.session.authenticated;
  const imageUrl = req.file.path; // Cloudinary URL
  const { event_name, event_date, event_time, event_location, event_access, event_description, event_fees, event_capacity } = req.body;

  try {
    await eventInfoCollection.insertOne({
      email: req.session.email,
      eventName: event_name,
      eventDate: event_date,
      eventTime: event_time,
      eventLocation: event_location,
      eventAccess: event_access,
      description: event_description,
      eventFees: event_fees,
      eventCapacity: event_capacity,
      eventPicture: imageUrl
    });

    res.redirect('/events'); // Redirect to the events page after submission
  } catch (error) {
    console.error('Error updating event info:', error);
    res.send("Failed to update event info.");
  }
});

app.post('/view_event', async (req, res) => {
  const loggedIn = req.session.authenticated;
  const eventId = req.body.eventId;
  console.log(eventId);
  const event = await eventInfoCollection.findOne({_id: ObjectId(eventId)});
  res.render('pages/event_view', {loggedIn, currentPath: req.path, event: event})
});

app.post('/editevent', async (req, res) => {
  const loggedIn = req.session.authenticated;

  const { event_name, event_date, event_time, event_location,
    event_access, event_description, event_fees, event_capacity } = req.body;

  await eventInfoCollection.updateOne(
    {
      email: req.session.email,
      eventName: event_name
    },
    {
      $set: {
        eventName: event_name,
        eventDate: event_date, eventTime: event_time,
        eventLocation: event_location, eventAccess: event_access,
        description: event_description, eventFees: event_fees, eventCapacity: event_capacity
      }
    }
  );
  res.render('pages/event_submitted', { loggedIn, currentPath: req.path });
});

app.post('/event_deletebutton', async (req, res) => {
  const loggedIn = req.session.authenticated;
  const { event_name, event_date, event_time, event_location,
    event_access, event_description, event_fees, event_capacity } = req.body;

  const result = await eventInfoCollection.deleteOne(
    {
      email: req.session.email,
      eventName: event_name
    },
  );
  if (result.deletedCount === 0) {
    return res.status(404).send("No event found with the provided criteria");
  }
  res.render('pages/events', { loggedIn, currentPath: req.path });
});

app.post('/event_cancelbutton', (req, res) => {
  const loggedIn = req.session.authenticated;
  res.render('pages/events', { loggedIn, currentPath: req.path });
});


app.get('/matching', async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }

  const hashedPassword = req.session.hashedPassword;
  let lowAge = +req.session.age - 5
  let highAge = +req.session.age + 5

  try {

    const matchuser = await userCollection.find({
      age: { $gt: "" + lowAge, $lt: "" + highAge },
      email: { $ne: req.session.email },
    }).toArray();
    const usersWithDefaultPics = matchuser.map(user => ({
      ...user,
      profilePicture: user.profilePicture || '/img/defaultprofilepic.png'
    }));

    console.log("=========================");
    console.log(matchuser);
    res.render("pages/matching", {
      users: usersWithDefaultPics,
      currentPath: req.path
    });

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
  await matchuserCollection.updateOne(query, update);
  res.redirect('/matching');
});

app.post('/chattingnow', async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }
  
  const matchUserEmail = req.body.matchEmail;
  const currentUserEmail = req.session.email

  console.log(req.session.name);
  // Update current user's matchuser_email array
  const queryCurrentUser  = { email: req.session.email };
  const updateCurrentUser  = {
    $addToSet: {
      matchuser_email: matchUserEmail
    }
  };

  await matchuserCollection.updateOne(queryCurrentUser , updateCurrentUser );
  // Update matched user's matchuser_email array
  const queryMatchedUser = { email: matchUserEmail };
  const updateMatchedUser = {
    $addToSet: {
      matchuser_email: currentUserEmail
    }
  };
  await matchuserCollection.updateOne(queryMatchedUser, updateMatchedUser);
  res.redirect('/chat');
});




// Socekt.io listener
io.on("connection", (socket) => {
  console.log("A user connected");

  socket.on("join", ({ room, matchedUserEmail }) => {
    socket.join(room);

    console.log(`${matchedUserEmail} has joined ${room}!`);

    const message = generateMessage(`${matchedUserEmail} has joined!`);
    message.messageType = "received";
    // socket.broadcast.to(room).emit("message", message);
  });

  socket.on("sendMessage", async (data) => {
    console.log(
      `Sender: ${data.sender} sent to room ${data.room}: ${data.message}`
    );
    const message = generateMessage(data.message);
    message.sender = data.sender;
    io.to(data.room).emit("message", message);

    try {
      // Store the message in MongoDB
      message.room = data.room;

      const result = await messagesCollection.insertOne(message);
      console.log("Message stored in MongoDB with ID:", result.insertedId);
    } catch (error) {
      console.error("Error storing message in MongoDB:", error);
    }
  });

  socket.on("disconnect", () => {
    console.log("A user disconnected");
  });

  socket.on("leave", (room) => {
    socket.leave(room);
  });
});

// Route handler
app.get("/chat", async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }
  const userEmail = req.session.email;
  const query = { email: userEmail };
  const matched_user = await matchuserCollection.findOne(query);

  const matched_users = matched_user.matchuser_email;
  const users = [];
  for (const user_email of matched_users) {
    const current_user = await userCollection.findOne({ email: user_email });
      if(current_user != null) {
        if (!users.some((user) => user.email === current_user.email)) {
          users.push(current_user);
        }
      }
  }

  if (matched_users == null || matched_users.length === 0) {
    console.log("No matched user");
    res.render("pages/chat-empty", {
      currentPath: req.path,
    });
    return;
  }

  console.log("Fetching profile for email:", req.session.email);

  try {
    const userProfile = await userCollection.findOne({
      email: req.session.email,
    });
    if (!userProfile) {
      console.log("User profile not found for email:", req.session.email);
      res.status(404).send("Profile not found");
      return;
    }

    res.render("pages/chat", {
      id: userProfile._id,
      name: userProfile.name,
      email: userProfile.email,
      age: userProfile.age,
      biography: userProfile.biography || "",
      profilePicUrl: userProfile.profilePicUrl || "/img/defaultprofilepic.png",
      currentPath: req.path,
      currentUser: matched_user,
      users: users,
    });
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).send("Failed to fetch profile.");
  }
});

//Chat-empty
app.get("/chat-empty", (req, res) => {
  res.render("pages/chat-empty");
});

// Retrieve messages from DB and pass them to front
app.get("/messages/:roomId", async (req, res) => {
  const { roomId } = req.params;

  try {
    const messages = await messagesCollection.find({ room: roomId }).toArray();

    // Send the retrieved messages as a JSON response
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// Retrieve emails from DB by userIds
app.get("/users/:userId", async (req, res) => {
  const { userId } = req.params;
  const _id = ObjectId(userId);
  try {
    const user = await userCollection.findOne({ _id: _id });
    console.log(user.email);
    
    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }

    res.status(200).send({ email: user.email });
  } catch (error) {
    res.status(500).send({ message: 'Error retrieving user', error });
  }
});


// Delete user and messages from DB 
app.delete('/matchusers/:email', async (req, res) => {
  const email = req.params.email;
  try {
    const result = await matchuserCollection.updateMany(
      {},
      { $pull: { matchuser_email: email } }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).send({ message: 'Email not found in any user match list' });
    }
    res.status(200).send({ message: 'Email removed from match lists successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'An error occurred while updating the user match lists' });
  }

});
const generateMessage = (text) => {
  return {
    text,
    createdAt: new Date().getTime(),
  };
};
