// We are creating a middleware here to add before every route that needs protection against a user not logged in:
module.exports = (req, res, next) => {
  if (!req.session.isLoggedIn) {
    return res.redirect("/login");
  }
  next();
}