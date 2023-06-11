// imports
const express = require("express")
const mongoose = require("mongoose")
const cookieParser = require("cookie-parser")
const dotenv = require("dotenv")
const jwt = require("jsonwebtoken")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const User = require("./models/User")
const Message = require("./models/Message")
const ws = require("ws")
const fs = require("fs")
const { Router } = require("express")
const { db } = require("./models/User")

// load env variable + db connection
dotenv.config()
mongoose.connect(process.env.MONGO_URL, (err) => {
  console.log("Connected to MongoDB")
  if (err) throw err
})

const jwtSecret = process.env.JWT_SECRET
const bcryptSalt = bcrypt.genSaltSync(10)

// express app setup
const app = express()
app.use("/uploads", express.static(__dirname + "/uploads"))
app.use(express.json()) // parse request bodies as json
app.use(cookieParser()) // parse cookie header and populate req.cookies
app.use(
  cors({
    credentials: true,
    origin: process.env.CLIENT_URL,
  })
)

// extract token from req cookie, verifies, then return userData. Otherwise reject promise
async function getUserDataFromRequest(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token // extract token from request cookie
    if (token) {
      jwt.verify(token, jwtSecret, {}, (err, userData) => {
        // verify token using JWT and secret key
        if (err) throw err
        resolve(userData) // resolve with user data
      })
    } else {
      reject("no token") // reject with "no token" message
    }
  })
}

// testing routes
app.get("/test", (req, res) => {
  res.json("test ok")
})
app.get("/", (req, res) => {
  res.send("Backend API is up and running.")
})

// get all msgs between current user and selected conversation
app.get("/messages/:userId", async (req, res) => {
  const { userId } = req.params // extract userId from request parameters
  const userData = await getUserDataFromRequest(req) // get user data from request
  const ourUserId = userData.userId // extract userId
  const messages = await Message.find({
    sender: { $in: [userId, ourUserId] },
    recipient: { $in: [userId, ourUserId] },
  }).sort({ createdAt: 1 }) // find messages between the two users and sort by createdAt
  res.json(messages) // respond with the messages
})

// get all users from DB, return _id & username
app.get("/people", async (req, res) => {
  const users = await User.find({}, { _id: 1, username: 1 }) // finds all users and return only _id and username
  res.json(users) // respond with the users
})

// get user's data if cookie contains valid token
app.get("/profile", (req, res) => {
  const token = req.cookies?.token // extract token from request cookie
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      // verify token using JWT and secret key
      if (err) throw err
      res.json(userData) // respond with user data
    })
  } else {
    res.status(401).json("no token") // respond with "no token" status code
  }
})

// verifies valid credentials, new token is signed & sent back in response
app.post("/login", async (req, res) => {
  const { username, password } = req.body // extract username and password from request body
  const foundUser = await User.findOne({ username }) // find user by username
  if (foundUser) {
    const passOk = bcrypt.compareSync(password, foundUser.password) // compare passwords using bcrypt
    if (passOk) {
      jwt.sign({ userId: foundUser._id, username }, jwtSecret, {}, (err, token) => {
        // sign new token using JWT and secret key
        res.cookie("token", token, { sameSite: "none", secure: true }).json({
          id: foundUser._id,
        }) // sets token in response cookie and respond with user ID
      })
    }
  }
})

// clear token with an empty string
app.post("/logout", (req, res) => {
  res.cookie("token", "", { sameSite: "none", secure: true }).json("ok") //clear token
})

// hashes password and stores new user in db, new token is signed & sent
app.post("/register", async (req, res) => {
  const { username, password } = req.body // extract username and password from request body
  try {
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt) // hash password using bcrypt
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
    }) // create the new user in the db
    jwt.sign({ userId: createdUser._id, username }, jwtSecret, {}, (err, token) => {
      if (err) throw err
      res.cookie("token", token, { sameSite: "none", secure: true }).status(201).json({
        id: createdUser._id,
      }) // sets token in response cookie,
    })
  } catch (err) {
    if (err) throw err
    res.status(500).json("error")
  }
})

// start express server
const port = process.env.PORT || 4040
const server = app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})
// updated for heroku deploy

// new WS server created on same port
const wss = new ws.WebSocketServer({ server })

// listens for new WS connection
wss.on("connection", (connection, req) => {
  function notifyAboutOnlinePeople() {
    ;[...wss.clients].forEach((client) => {
      client.send(
        JSON.stringify({
          online: [...wss.clients].map((c) => ({ userId: c.userId, username: c.username })),
        })
      )
    })
  }

  // making sure connection is alive
  connection.isAlive = true
  connection.timer = setInterval(() => {
    connection.ping()
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false
      clearInterval(connection.timer)
      connection.terminate()
      notifyAboutOnlinePeople()
      console.log("dead")
    }, 1000)
  }, 5000)

  connection.on("pong", () => {
    clearTimeout(connection.deathTimer)
  })

  // authenticate connection using token
  const cookies = req.headers.cookie // extract cookies from request headers
  if (cookies) {
    const tokenCookieString = cookies.split(";").find((str) => str.startsWith("token=")) // find token cookie string
    if (tokenCookieString) {
      const token = tokenCookieString.split("=")[1] // extract token valuee
      if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
          // vErify token using JWT and secret key
          if (err) throw err
          const { userId, username } = userData
          connection.userId = userId
          connection.username = username
        })
      }
    }
  }

  // listens for msgs from connection
  connection.on("message", async (message) => {
    const messageData = JSON.parse(message.toString()) // parses incoming message data
    const { recipient, text, file } = messageData // Extract message details
    let filename = null
    if (file) {
      console.log("size", file.data.length) // print file size
      const parts = file.name.split(".") // split file name to extract extension
      const ext = parts[parts.length - 1]
      filename = Date.now() + "." + ext
      const path = __dirname + "/uploads/" + filename
      const bufferData = new Buffer(file.data.split(",")[1], "base64") // converts file data from base64 to buffer
      fs.writeFile(path, bufferData, () => {
        console.log("file saved:" + path)
      })
    }
    if (recipient && (text || file)) {
      const messageDoc = await Message.create({
        // adds new message document in the database
        sender: connection.userId,
        recipient,
        text,
        file: file ? filename : null,
      })
      console.log("created message")
      ;[...wss.clients]
        .filter((c) => c.userId === recipient)
        .forEach((c) =>
          c.send(
            JSON.stringify({
              text,
              sender: connection.userId,
              recipient,
              file: file ? filename : null,
              _id: messageDoc._id,
            })
          )
        )
    }
  })

  // notify everyone about online people (when someone connects)
  notifyAboutOnlinePeople()
})
