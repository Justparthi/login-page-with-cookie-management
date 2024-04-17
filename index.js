import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";

const app = express();
const port = 5000;
const saltRounds = 10


app.use(session({
    secret: "TOPSECRET",
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
    }
}))

app.use(passport.initialize());
app.use(passport.session())

const db = new pg.Client({
    user : "postgres",
    host : "localhost",
    database : "login",
    password : "Parthi",
    port : 5432
})


db.connect();




app.use(bodyParser.urlencoded({ extended: true}))
app.use(express.static("public"))


app.get("/signup", (req,res) =>{

    try {
        res.render("signup.ejs")
    } catch (err) {
        console.log(err)
    }

    
})

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets.ejs")
    } else {
        res.redirect("/")
    } 
})


app.get("/", (req, res) =>{
    res.render("login.ejs")
})

app.post("/signup", async (req,res) =>{


    const mailid = req.body.username
    const pass = req.body.password
    
    try {
        const result = await db.query('SELECT username FROM userinfo WHERE username = $1', [mailid])

    if (result.rows.length > 0) {
        res.send("Username or email Already taken !!!")
    }  else {
        bcrypt.hash(pass, saltRounds, async (err, hash) => {
            if (err){
                console.log(`Error hashing password ${err}`)
            } else {
                const result = await db.query("INSERT INTO userinfo (username, password) VALUES ($1, $2) RETURNING *", [mailid, hash])
        // console.log(result)
        const user = result.rows[0]
        req.login(user, (err) =>{
            console.log(err)
            res.redirect("/secrets")
        })
            }
        })
        
    }

    } catch (err) {
        console.log(err)
        res.render("secrets")
        console.log("user details dosnt exists")
        res.send("User details already exist")

        
    } 
    
    
})

app.post('/', passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/"
}));


passport.use(new Strategy(async function verify(username, password, cb) {
    console.log(username)
    try {
        const data = await db.query("SELECT * FROM userinfo WHERE (username) = $1", [username])
        
        
        if (data.rows.length > 0) {

        const user = data.rows[0]
        const saltedPassword = user.password

        bcrypt.compare(password, saltedPassword, (err, result) =>{
        if (err) {
            return cb(err)
        }
        else {
            if (result) {
                return cb(null, user)
            } else {
                return cb(null, false)
            }
        }
        
        })

            
        } else {
            return cb("Something went wrong please check the password")
            
        }

    } catch (err) {
        return cb(err)
        
    }
}))


passport.serializeUser((user, cb) => {
    cb(null, user);
})

passport.deserializeUser((user, cb) => {
    cb(null, user);
})



app.listen(port, () =>{
    console.log(`The Server is running on port ${port}`)
})





