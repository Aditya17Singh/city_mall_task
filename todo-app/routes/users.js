var express = require("express");
var router = express.Router();
var User = require("../models/User");

/* REGISTER users */
router.post("/", async (req, res, next) => {
  try {
    var user = await User.create(req.body);
    let token = await user.signToken();
    res.json({ user: await user.userJSON(token) });
  } catch (error) {
    next(error);
  }
});

// LOGIN users
router.post("/login", async (req, res, next) => {
  var { email, password } = req.body;
  if (!email || !password){
    return res.status(400).json({ error: "Email/Password required!" });
  }
  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Email is not registered" });
    }
    let result = await user.verifyPassword(password);
    if (!result) {
      return res.status(400).json({ error: "Password is invalid" });
    }
    let token = await user.signToken();
    res.json({ user: await user.userJSON(token) });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
