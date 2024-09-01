const jwt = require("jsonwebtoken");
require("dotenv").config();
const config = process.env;
const express = require("express");

const tokenVerification = (req, res, next) => {
  let token; 
  if (req.body && req.body.token) {
    token = req.body.token;
  } else if (req.query && req.query.token) {
    token = req.query.token;
  } else if (req.headers && req.headers["x-access-token"]) {
    token = req.headers["x-access-token"];
  } else if (req?.signedCookies?.user?.token) {
  token = req.signedCookies.user.token;
  } else {
    token = null; 
    console.log("null value for token")
  }
  //let token = req.body?.token ?? req.query?.token ?? req.headers["x-access-token"] ?? req?.signedCookies?.user?.token ?? null;

  if (!token) {
    return res.status(403).send({
      auth: false,
      message: "Token is not provided.",
      status: 403
    });
  }
  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    req.user = decoded;
  } catch (err) {
    console.log("Failed to authenticate token.");
    return res.status(401).send({
      auth: false,
      message: "Failed to authenticate token.",
      status: 401
    });
  }
  return next();
};

module.exports = tokenVerification;
