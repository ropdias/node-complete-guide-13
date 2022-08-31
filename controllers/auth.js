const crypto = require("crypto");

const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

const User = require("../models/user");

const transporter = nodemailer.createTransport({
  host: "smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: process.env.MAILTRAP_USER,
    pass: process.env.MAILTRAP_PASS,
  },
});

exports.getLogin = (req, res, next) => {
  let message = req.flash("error"); // What I stored in 'error' will be retrivied here, and after we get it, it will be removed from the session
  // We need the validation below because flash() returns an array and we need to check if it has something, otherwise set it to null
  // So we can use in the views: <% if (errorMessage) { %> ...
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message,
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash("error"); // What I stored in 'error' will be retrivied here, and after we get it, it will be removed from the session
  // We need the validation below because flash() returns an array and we need to check if it has something, otherwise set it to null
  // So we can use in the views: <% if (errorMessage) { %> ...
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message,
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  // The session object is added by the session middleware with app.use(session())
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        req.flash("error", "Invalid email or password."); // We use both (email and password) here so people don't know which part was wrong
        return res.redirect("/login");
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          // We enter here independent if the password match or not (doMatch is true if it's equal, otherwise its false)
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user; // This will remain a full mongoose model ONLY for this request
            req.session.save((err) => {
              if (err) console.log(err);
              res.redirect("/");
            });
          } else {
            req.flash("error", "Invalid email or password."); // We use both (email and password) here so people don't know which part was wrong
            req.session.isLoggedIn = false;
            req.session.user = null;
            req.session.save((err) => {
              if (err) console.log(err);
              res.redirect("/login");
            });
          }
        })
        .catch((err) => {
          // We enter here if something goes wrong with the compare function (not regarding if the password match or not)
          console.log(err);
          res.redirect("/login");
        });
    })
    .catch((err) => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  // We will validate user input (like checking if it's the same password) in a later section
  // So will just ignore validation for now

  User.findOne({ email: email })
    .then((userDoc) => {
      if (userDoc) {
        req.flash(
          "error",
          "E-mail exists already, please pick a different one."
        );
        return res.redirect("/signup");
      }
      return bcrypt
        .hash(password, 12)
        .then((hashedPassword) => {
          const user = new User({
            email: email,
            password: hashedPassword,
            cart: { items: [] },
          });
          return user.save();
        })
        .then((result) => {
          res.redirect("/login");
          return transporter.sendMail({
            to: email,
            from: process.env.MAILTRAP_FROM,
            subject: "Signup succeeded!",
            html: "<h1>You successfully signed up!</h1>",
          });
        })
        .catch((err) => {
          console.log(err);
        });
    })
    .catch((err) => {
      console.log(err);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message,
  });
};

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect("/reset");
    }
    const token = buffer.toString("hex");
    User.findOne({ email: req.body.email })
      .then((user) => {
        if (!user) {
          req.flash("error", "No account with that email found.");
          return res.redirect("/reset");
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000; // 1 hour = 3600000 ms (needs to be ms here)
        return user
          .save()
          .then((result) => {
            res.redirect("/");
            return transporter.sendMail({
              to: req.body.email,
              from: process.env.MAILTRAP_FROM,
              subject: "Password reset",
              html: `
                <p>You requested a password reset</p>
                <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
              `,
            });
          })
          .catch((err) => {
            console.log(err);
          });
      })
      .catch((err) => {
        console.log(err);
      });
  });
};

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
    .then((user) => {
      if (!user) {
        req.flash("error", "Reset Token invalid or expired.");
        return res.redirect("/login");
      }
      let message = req.flash("error");
      if (message.length > 0) {
        message = message[0];
      } else {
        message = null;
      }
      res.render("auth/new-password", {
        path: "/new-password",
        pageTitle: "New Password",
        errorMessage: message,
        // We will include a userId in the render from the get request because
        // we need it in the post request to update the password
        userId: user._id.toString(), // toString() to convert from a an objectID to a real string
        // We will also need the token so we can make sure we can pass the same token to the post request:
        passwordToken: token,
      });
    })
    .catch((err) => {
      console.log(err);
    });
};

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken: passwordToken,
    resetTokenExpiration: { $gt: Date.now() },
    _id: userId,
  })
    .then((user) => {
      if (!user) {
        req.flash(
          "error",
          "Error when trying to update. Reset Token invalid or expired."
        );
        return res.redirect("/login");
      }
      // If we find a user, we will save it in a local variable to get it in the next then() after we encrypt the password again
      resetUser = user;
      return bcrypt
        .hash(newPassword, 12)
        .then((hashedPassword) => {
          resetUser.password = hashedPassword;
          resetUser.resetToken = undefined; // Field is not required, so we can set to undefined to not store any values in the database
          resetUser.resetTokenExpiration = undefined; // Field is not required, so we can set to undefined to not store any values in the database
          return resetUser.save();
        })
        .then((result) => {
          res.redirect("/login");
        })
        .catch((err) => {
          console.log(err);
        });
    })
    .catch((err) => {
      console.log(err);
    });
};
