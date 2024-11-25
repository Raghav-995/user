const jwt = require('jsonwebtoken');
const db = require('../config/db')

exports.authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({warning:"Access Denied"});

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({error:"Invalid token"});
    req.user = user;
    next();
  });
};

exports.verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({error:"Access Denied"});

  // Check if the token is blacklisted
  db.query("SELECT * FROM token_blacklist WHERE token = ?", [token], (err, result) => {
    if (result.length > 0) return res.status(401).json({error:"Token is blacklisted"});

    // Verify token validity
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(401).json({error:"Invalid token"});
      req.user = user;
      next();
    });
  });
};

exports.authenticateUser = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded.id; // Attach the user data to the request object
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

exports.authenticateSuperAdmin = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  try {
    // Decode and verify the JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded JWT:", decoded); // Add logging to verify decoded token

    req.user = decoded; // Attach user data from the token to the request

    const userId = decoded.id; // Extract user_id from the decoded token
    console.log("Fetching user with user_id:", userId); // Add logging

    // Fetch the user's role from the database
    const [user] = await db.promise().query(
      "SELECT role_f_id, user_id FROM user WHERE user_id = ?",
      [userId]
    );

    if (!user.length) {
      console.log("User not found with user_id:", userId); // Add logging
      return res.status(404).json({ error: "User not found" });
    }

    req.user.role = user[0].role_f_id; // Attach role to the request
    req.user.id = user[0].user_id; // Attach user_id to the request

    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    console.error("Authentication error:", err);
    return res.status(401).json({ error: "Unauthorized: Invalid token" });
  }
};

