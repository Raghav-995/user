const db = require('../config/db');

exports.logUserActivity = (userId, action, description, req) => {
    const ip_address = req.ip; // Get the user's IP address
    const user_agent = req.headers['user-agent']; // Get the user's browser details
    
    const query = `
      INSERT INTO user_activity_log (user_f_id, ip_address, action, description, user_agent)
      VALUES (?, ?, ?, ?, ?)
    `;
  
    db.query(query, [userId, ip_address, action, description, user_agent], (err) => {
      if (err) {
        console.error("Error logging user activity:", err);
      }
    });
  }
  