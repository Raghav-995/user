const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Joi = require('joi');
const cron = require('node-cron');
const db = require('../config/db');
const { sendResetEmail } = require('../utils/emailService');
const { loginSchema, signupSchema, emailSchema, otpSchema } = require('../validators/authValidation');
const { sendVerificationEmail, sendApprovalEmail, sendApprovedEmail, sendRejectionEmail } = require('../utils/emailService');
const { logUserActivity } = require('../utils/userActivity');
require('dotenv').config();


exports.signup = async (req, res) => {
  const { error } = signupSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { firstName, lastName, email, password, phoneNumber, role_id, organization_id } = req.body;

  try {
    // Check if the role_id exists in the roles table
    const [roleRecord] = await db.promise().query(
      "SELECT role_id, role_name FROM roles WHERE role_id = ?",
      [role_id]
    );

    if (roleRecord.length === 0) {
      return res.status(400).json({ error: "Invalid role_id specified" });
    }

    const role_name = roleRecord[0].role_name;
        // If the role is SUPER_ADMIN, check the `super_admin_organizations` table
        if (role_name === "SUPER_ADMIN") {

                // Check if the super_admin_organizations table has records
      const [superAdminOrgs] = await db.promise().query(
        "SELECT organization_id FROM super_admin_organizations"
      );

      if (superAdminOrgs.length === 0) {
        return res.status(400).json({ error: "No organizations exist for SUPER_ADMIN." });
      }

          const [organization] = await db.promise().query(
            "SELECT organization_id FROM super_admin_organizations WHERE organization_id = ?",
            [organization_id]
          );
    
          if (organization.length === 0) {
            return res.status(400).json({ error: "Invalid organization ID for SUPER_ADMIN." });
          }
        } else {

          
          // Check if the organization exists for other roles
          const [organization] = await db.promise().query(
            "SELECT organization_id FROM organization WHERE organization_id = ?",
            [organization_id]
          );
    
          if (organization.length === 0) {
            return res.status(400).json({ error: "Invalid organization ID." });
          }
        }
    const [existingUser] = await db.promise().query(
      "SELECT * FROM user WHERE user_email = ?",
      [email]
    );

    if (existingUser.length > 0) {
      // Handle already existing email with unverified status
      if (!existingUser[0].status) {
        return res
          .status(200)
          .json({ success: "OTP already sent. Please verify or request a new one." });
      }
          // Handle already existing email with unverified status
          const user = existingUser[0];
          if (user.signup_otpcount >= 3) {
            return res.status(400).json({ error: "Your account is locked for 30 minutes due to too many OTP requests." });
          }
          if (user.signup_otpcount >= 3) {
            // Lock the account for 30 minutes
            await db.promise().query(
              "UPDATE users SET otpLockTime = ? WHERE email = ?",
              [new Date(Date.now() + 30 * 60 * 1000), email]  // Set lock time to 30 minutes from now
            );
            return res.status(400).json({ error: "Your account is locked for 30 minutes due to too many OTP requests." });
          }
      return res.status(400).json({ error: "User already exists" });
    }

    // Generate OTP and hash the password
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    await db.promise().query(
      `INSERT INTO user (
        user_first_name, user_last_name, user_email, user_password, user_phone_number, role_f_id, organization_f_id,
        signup_otp, signup_otpcount, status, created_timestamp, updated_timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, FALSE, NOW(), NOW())`,
      [firstName, lastName, email, hashedPassword, phoneNumber, role_id, organization_id, otp]
    );

    // Send verification email
    sendVerificationEmail(email, otp);
    const [user] = await db.promise().query(
      "SELECT * FROM user WHERE user_email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const existingUser1 = user[0];

    
    logUserActivity(existingUser1.user_id, "Register_Account", "User Registered Successfully", req);


    res.json({
      success: "Registration successful. Please check your email to verify your account."
    });
  } catch (err) {
    console.error("Error during signup:", err);
    res.status(500).json({ error: "Error creating user" });
  }
};


exports.resendVerificationEmail = async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
  });
  const { error } = schema.validate(req.body);
  if (error) return res.status(400).json({error:error.details[0].message});

  const { email } = req.body;

  try {
    // Fetch the user record
    const [user] = await db.promise().query(
      "SELECT * FROM user WHERE user_email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const existingUser = user[0];

    if(existingUser.status == 1){
      return res.status(400).json({error: "User verified account already!"});
    }

    // Check if the account is locked (OTP count exceeds 3 and lock time is within 30 minutes)
    const lastUpdated = new Date(existingUser.updated_timestamp);
    const currentTime = new Date();
    const timeDiff = currentTime - lastUpdated;

    if (existingUser.signup_otpcount >= 3 && timeDiff < 30 * 60 * 1000) {
      return res.status(400).json({ error: "Your account is locked for 30 minutes due to too many OTP requests." });
    }

    // Retrieve the same OTP as the first time
    const otp = existingUser.signup_otp;

    // Increment the OTP count
    await db.promise().query(
      "UPDATE user SET signup_otpcount = signup_otpcount + 1, updated_timestamp = NOW() WHERE user_email = ?",
      [email]
    );

    // Send the same OTP via email
    sendVerificationEmail(email, otp);
    logUserActivity(existingUser.user_id, "Verification_Email", "OTP Sent Successfully", req);


    res.json({
      success: "Verification email resent successfully. Please verify your email."
    });
  } catch (err) {
    console.error("Error resending OTP:", err);
    res.status(500).json({ error: "Error resending OTP" });
  }
};

// // Check for unverified users and delete them if they have not verified their email within 1 hour
// const cleanupUnverifiedUsers = () => {
//   const expirationTime = new Date(Date.now() - 16 * 60 * 1000); // 15 minutes ago

//   db.query(
//     "DELETE FROM user WHERE isVerified = 0 AND otpExpires < ?",
//     [expirationTime],
//     (err, result) => {
//       if (err) {
//         console.error("Error deleting unverified users:", err);
//         return;
//       }
//       console.log(`Deleted ${result.affectedRows} unverified users.`);
//     }
//   );
// };

// // Run cleanup every 30 minutes
// cron.schedule('*/30 * * * *', () => {
//   cleanupUnverifiedUsers();
//   console.log('running a task every 15 minute');

// });

// Verify OTP function
exports.verifyEmail = async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    otp: Joi.number().required(),
  });
  const { error } = schema.validate(req.body);
  if (error) return res.status(400).json({error:error.details[0].message});

  const { email, otp } = req.body;

  try {
        // Check if the email exists
        const [emailCheck] = await db.promise().query(
          "SELECT * FROM user WHERE user_email = ?",
          [email]
        );
    
        if (emailCheck.length === 0) {
          return res.status(404).json({ error: "User email not found" });
        }
            // Check if the user is already verified
    if (emailCheck[0].status) {
      return res.status(400).json({ error: "Email is already verified" });
    }
    // Check if the user exists and if the OTP is valid
    const [user] = await db.promise().query(
      "SELECT * FROM user WHERE user_email = ? AND signup_otp = ?",
      [email, otp, new Date()]
    );

    if (user.length === 0) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // Mark user as verified
    await db.promise().query(
      "UPDATE user SET status = TRUE, signup_otp = NULL, signup_otpcount = NULL WHERE user_id = ?",
      [user[0].user_id]
    );
    logUserActivity(user[0].user_id, "Verify_Email", "Email Verified Successfully", req);

    res.status(200).json({ success: "Email verified successfully" });
  } catch (err) {
    console.error("Error verifying OTP:", err);
    res.status(500).json({ error: "Error verifying OTP" });
  }
};

exports.login = async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { email, password } = req.body;

  try {
    // Fetch user from database
    const [result] = await db.promise().query("SELECT * FROM user WHERE user_email = ?", [email]);

    if (result.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result[0];

    // Check if the account is verified
    if (user.status !== 1) {
      return res.status(403).json({ error: "Account not verified. Please check your email to verify your account." });
    }

    // Check login attempts and timestamp
    if (user.login_attempts >= 3) {
      const currentTime = new Date();
      const lastAttemptTime = new Date(user.updated_timestamp);
      const timeDifference = (currentTime - lastAttemptTime) / 1000 / 60; // Difference in minutes

      if (timeDifference < 30) {
        return res.status(403).json({
          error: "Too many failed login attempts. Please try again after 30 minutes.",
        });
      } else {
        // Reset login attempts after 30 minutes
        await db.promise().query("UPDATE user SET login_attempts = 0 WHERE user_email = ?", [email]);
      }
    }

    // Validate password
    const validPassword = await bcrypt.compare(password, user.user_password);

    if (!validPassword) {
      // Increment login attempts on wrong password
      await db.promise().query("UPDATE user SET login_attempts = login_attempts + 1, updated_timestamp = NOW() WHERE user_email = ?", [email]);

      return res.status(401).json({ error: "Invalid email or password." });
    }

    // Reset login attempts on successful login
    await db.promise().query("UPDATE user SET login_attempts = 0 WHERE user_email = ?", [email]);

    const [userPin] = await db.promise().query("SELECT pin, isPinSet FROM user_pins WHERE user_f_id = ?", user.user_id);
    console.log(userPin[0])

    var currentHashedPin = 1;

    if (userPin.length === 0) {
       currentHashedPin = 0;
    }
    else{
      currentHashedPin = userPin[0].isPinSet;
      console.log(currentHashedPin)
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.user_id }, process.env.JWT_SECRET, { expiresIn: "24h" });

    // Log user activity
    logUserActivity(user.user_id, "Login", "User Logged In Successfully", req);

    res.json({ success: "Logged in Successfully", token, "isPinSet": currentHashedPin, role_id: user.role_f_id });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// Set PIN API
exports.setPin = async (req, res) => {
  const { pin } = req.body;
  const userId = req.user; // Extracted from token by the middleware

  // Validate PIN: It should be a 6-digit integer
  if (!/^\d{6}$/.test(pin)) {
      return res.status(400).json({ error: "PIN must be a 6-digit number." });
  }

  try {
      // Check if the PIN has already been set
      const [existingPin] = await db.promise().query("SELECT isPinSet FROM user_pins WHERE user_f_id = ?", [userId]);
      
      if (existingPin.length > 0 && existingPin[0].isPinSet) {
          return res.status(400).json({ error: "PIN has already been set." });
      }

      // Hash the PIN
      const hashedPin = await bcrypt.hash(pin, 10);

      // Insert or update the PIN in the user_pins table
      await db.promise().query(
          "INSERT INTO user_pins (user_f_id, pin, isPinSet) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE pin = VALUES(pin), isPinSet = VALUES(isPinSet)",
          [userId, hashedPin, true]
      );

      // Update isPinSet in users table
      // await db.promise().query("UPDATE user SET isPinSet = ? WHERE user_id = ?", [true, userId]);
      logUserActivity(userId, "Set_Pin", "User Set Pin Successfully", req);

      res.json({ success: "PIN set successfully." });
  } catch (err) {
      console.error("Error setting PIN:", err);
      res.status(500).json({ error: "Error setting PIN" });
  }
};

// Verify PIN API
exports.verifyPin = async (req, res) => {
const schema = Joi.object({ pin: Joi.string().min(6).required()
  .messages({
    'string.min': 'Pin must be 6 characters long',
    'any.required': 'Pin is required',
  }),
 });
const { error } = schema.validate(req.body);
if (error) return res.status(400).json({ error: error.details[0].message });

const { pin } = req.body;
const userId = req.user; // Extracted from token by the middleware

try {
    // Retrieve the stored hashed PIN for the user
    const [userPin] = await db.promise().query("SELECT pin FROM user_pins WHERE user_f_id = ?", [userId]);

    if (userPin.length === 0) {
        return res.status(400).json({ error: "PIN not set. Please set your PIN first." });
    }

    // Compare the provided PIN with the stored hashed PIN
    const isMatch = await bcrypt.compare(pin, userPin[0].pin);

    if (!isMatch) {
        return res.status(400).json({ error: "Invalid PIN." });
    }
    logUserActivity(userId, "Verify_Pin", "User Verified Pin Successfully", req);
    res.json({ success: "PIN verified successfully." });
} catch (err) {
    console.error("Error verifying PIN:", err);
    res.status(500).json({ error: "Error verifying PIN" });
}
};

// Reset PIN API
exports.resetPin = async (req, res) => {
const schema = Joi.object({ newPin: Joi.string().min(6).required()
  .messages({
    'string.min': 'newPin must be 6 characters long',
    'any.required': 'newPin is required',
  }),
 });
const { error } = schema.validate(req.body);
if (error) return res.status(400).json({ error: error.details[0].message });

const { newPin } = req.body;
const userId = req.user; // Extracted from token by the middleware

// Validate new PIN: It should be a 6-digit integer
if (!/^\d{6}$/.test(newPin)) {
    return res.status(400).json({ error: "PIN must be a 6-digit number." });
}

try {
        // Retrieve the stored hashed PIN for the user
    const [userPin] = await db.promise().query("SELECT pin FROM user_pins WHERE user_f_id = ?", [userId]);

    if (userPin.length === 0) {
        return res.status(400).json({ error: "PIN not set. Please set your PIN first." });
    }
    const currentHashedPin = userPin[0].pin;

    // Check if the new PIN matches the existing PIN
    const isSameAsOldPin = await bcrypt.compare(newPin, currentHashedPin);
    if (isSameAsOldPin) {
        return res.status(400).json({ error: "New PIN cannot be the same as the old PIN." });
    }

    // Hash the new PIN
    const hashedPin = await bcrypt.hash(newPin, 10);

    // Update the PIN in the user_pins table
    await db.promise().query(
        "UPDATE user_pins SET pin = ?, updatedAt = CURRENT_TIMESTAMP WHERE user_f_id = ?",
        [hashedPin, userId]
    );

    logUserActivity(userId, "Update_Pin", "User Updated Pin Successfully", req);
    res.json({ success: "PIN reset successfully." });

} catch (err) {
    console.error("Error resetting PIN:", err);
    res.status(500).json({ error: "Error resetting PIN" });
}
};

exports.forgotPassword = async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { email } = req.body;

  try {
    // Fetch user by email
    const [user] = await db.promise().query(
      "SELECT user_id FROM user WHERE user_email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const userId = user[0].user_id;

    // Fetch the latest OTP request for this user
    const [forgotPasswordRequest] = await db.promise().query(
      "SELECT * FROM forgot_password WHERE user_id = ? ORDER BY updated_timestamp DESC LIMIT 1",
      [userId]
    );

    if (forgotPasswordRequest.length > 0) {
      const existingRequest = forgotPasswordRequest[0];

      // Check if the user has exceeded the OTP request limit (3 attempts)
      if (existingRequest.forgot_otp_count >= 3) {
        // Check if the last OTP request was made less than 30 minutes ago
        const currentTime = new Date();
        const otpTimestamp = new Date(existingRequest.updated_timestamp);
        const timeDifference = (currentTime - otpTimestamp) / 1000 / 60; // Difference in minutes

        if (timeDifference < 30) {
          return res.status(400).json({
            error: "You have reached the OTP resend limit. Please try again after 30 minutes.",
          });
        }
      }
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP

    // Update or insert OTP in the forgot_password table
    await db.promise().query(
      `INSERT INTO forgot_password (user_id, forgot_otp, forgot_otp_count, updated_timestamp) 
       VALUES (?, ?, 1, NOW()) 
       ON DUPLICATE KEY UPDATE forgot_otp_count = forgot_otp_count + 1, updated_timestamp = NOW()`,
      [userId, otp]
    );

    // Send OTP email to the user
    sendResetEmail(email, otp);

    // Log the user activity
    logUserActivity(userId, "Forgot_Password_OTP", "Requested OTP Successfully", req);

    res.json({ success: "Password reset otp sent successfully. Please check your email" });
  } catch (err) {
    console.error("Error during forgot password request:", err);
    res.status(500).json({ error: "Error processing the forgot password request" });
  }
};


exports.verifyOtp = async (req, res) => {
  const { error } = otpSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { email, otp } = req.body;

  try {
    // Fetch user by email
    const [user] = await db.promise().query(
      "SELECT user_id FROM user WHERE user_email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const userId = user[0].user_id;

    // Fetch the latest OTP request for the user
    const [forgotPasswordRequest] = await db.promise().query(
      "SELECT * FROM forgot_password WHERE user_id = ? ORDER BY updated_timestamp DESC LIMIT 1",
      [userId]
    );

    if (forgotPasswordRequest.length === 0) {
      return res.status(400).json({ error: "No OTP request found for this email" });
    }

    const existingRequest = forgotPasswordRequest[0];
      console.log(existingRequest.status)

            // Check if the OTP has already been verified
            if (existingRequest.status === 1) {
              return res.status(400).json({ error: "OTP has already been verified." });
            }
        

    // Validate timestamp and OTP
    const currentTime = new Date();
    const otpTimestamp = new Date(existingRequest.updated_timestamp);

    const timeDifference = (currentTime - otpTimestamp) / 1000 / 60; // Difference in minutes
    console.log("Current Time:", currentTime);
    console.log("OTP Timestamp:", otpTimestamp);
    console.log("Time Difference (minutes):", timeDifference);

    if (timeDifference > 15) {
      return res.status(400).json({ error: "OTP has expired. Please request a new one." });
    }
    const dbOtp = existingRequest.forgot_otp.toString().trim();
    const inputOtp = otp.toString().trim();
    
    console.log("Normalized OTP from DB:", dbOtp);
    console.log("Normalized OTP from User:", inputOtp);
    
    if (dbOtp !== inputOtp) {
      return res.status(400).json({ error: "Invalid OTP." });
    }
    

    // Mark ONLY the latest OTP as verified
    await db.promise().query(
      "UPDATE forgot_password SET status = true WHERE user_id = ? AND forgot_otp = ? ",
      [userId, otp]
    );

    logUserActivity(userId, "Verify_OTP", "OTP Verified Successfully", req);

    res.json({ success: "OTP verified successfully. You can now reset your password." });
  } catch (err) {
    console.error("Error verifying OTP:", err);
    res.status(500).json({ error: "Error verifying OTP" });
  }
};



exports.resendOtp = async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { email } = req.body;

  try {
    // Fetch user by email
    const [user] = await db.promise().query(
      "SELECT user_id FROM user WHERE user_email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const userId = user[0].user_id;

    // Fetch the latest OTP details from the forgot_password table
    const [forgotPasswordRequest] = await db.promise().query(
      "SELECT * FROM forgot_password WHERE user_id = ? ORDER BY updated_timestamp DESC LIMIT 1",
      [userId]
    );

    if (forgotPasswordRequest.length === 0) {
      return res.status(400).json({ error: "No OTP request found for this email" });
    }

    const existingRequest = forgotPasswordRequest[0];
        // Check if the OTP has already been verified
        if (existingRequest.status === 1) {
          return res.status(400).json({ error: "OTP has already been verified." });
        }
    

    const lastUpdated = new Date(existingRequest.updated_timestamp);
    const currentTime = new Date();
    const timeDiff = currentTime - lastUpdated;

    // Check if the OTP count has exceeded the limit
    if (existingRequest.forgot_otp_count >= 3 && timeDiff < 30 * 60 * 1000) {
      return res.status(400).json({
        error: "Your account is locked for 30 minutes due to too many OTP requests.",
      });
    }

    // Retrieve the same OTP as the latest one
    const otp = existingRequest.forgot_otp;

    // Increment the OTP count and update the timestamp
    await db.promise().query(
      "UPDATE forgot_password SET forgot_otp_count = forgot_otp_count + 1, updated_timestamp = NOW() WHERE user_id = ? AND forgot_otp = ?",
      [userId, otp]
    );

    // Check if the OTP is still valid (less than 15 minutes old)
    const otpAgeInMinutes = (currentTime - lastUpdated) / 1000 / 60; // Difference in minutes
    if (otpAgeInMinutes > 15) {
      return res.status(400).json({ error: "OTP has expired. Please request a new one." });
    }

    // Send the same OTP again
    sendResetEmail(email, otp);

    // Log user activity
    logUserActivity(
      userId,
      "Forgot_Password_Resend_OTP",
      "Forgot-Password OTP Sent Successfully",
      req
    );

    res.json({ success: "OTP resent to your email." });
  } catch (err) {
    console.error("Error during resend OTP:", err);
    res.status(500).json({ error: "Error processing resend OTP request" });
  }
};


exports.resetPassword = async (req, res) => {

  const schema = Joi.object({
    email: Joi.string().email().required(),
    newPassword: Joi.string().min(8).required().messages({
      'string.min': 'New password should be at least 8 characters long',
      'any.required': 'New password is required',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) return res.status(400).json({error:error.details[0].message});

  const { email, newPassword } = req.body;

  try {
    // Validate request body
    if (!newPassword || typeof newPassword !== "string") {
      return res.status(400).json({ error: "New password is required and must be a string." });
    }

    // Fetch user by email
    const [user] = await db.promise().query(
      "SELECT user_id, user_password, updated_timestamp FROM user WHERE user_email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const { user_id: userId, user_password: currentHashedPassword, updated_timestamp } = user[0];

    // // Check if the password was changed in the last 30 minutes using updated_timestamp
    // const currentTime = new Date();
    // const lastUpdatedTime = new Date(updated_timestamp);
    // const timeDifference = (currentTime - lastUpdatedTime) / 1000 / 60; // Difference in minutes

    // if (timeDifference < 30) {
    //   return res.status(400).json({
    //     error: "Password cannot be changed within 30 minutes of the last change. Please verify OTP again.",
    //   });
    // }

    // Compare new password with current password
    const isSamePassword = await bcrypt.compare(newPassword, currentHashedPassword);
    if (isSamePassword) {
      return res.status(400).json({ error: "New password cannot be the same as the old password." });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    await db.promise().query(
      "UPDATE user SET user_password = ?, updated_timestamp = NOW() WHERE user_id = ?",
      [hashedPassword, userId]
    );

    // Clear the OTP request from forgot_password table
    await db.promise().query(
      "UPDATE forgot_password SET status = false, forgot_otp_count = 0 WHERE user_id = ?",
      [userId]
    );
    logUserActivity(userId, "Update_Password", "New Password Updated Successfully", req);
    res.json({ success: "Password reset successfully. Please log in with your new password." });
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).json({ error: "Error resetting password" });
  }
};

exports.logout = (req, res) => {
  // Define the schema for validating the token
  const tokenSchema = Joi.object({
    token: Joi.string()
      .regex(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/) // Regex for JWT structure
      .required(),
  });

  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(400).json({error:"Token not provided"});

    // Validate the token format
    const { error } = tokenSchema.validate({ token });
    if (error) {
      return res.status(400).json({ error: "Invalid token format" });
    }
  
  // Verify token to check if it’s valid before blacklisting it
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(400).json({error:"Invalid token"});
    const userId = decoded.id; // Assuming the JWT payload contains the user ID in `id`
    // Save the token in the blacklist
    db.query("INSERT INTO token_blacklist (token) VALUES (?)", [token], (err) => {
      if (err) return res.status(500).json({error:"Error blacklisting token"});
      logUserActivity(userId, "Logout", "Logged out Successfully!", req);
      res.json({success:"Successfully logged out"});
    });
  });
};

exports.getUserActivityLog = (req, res) => {
  const userId = req.user.id; // Assuming you have user authentication and can get the user's ID

  db.query("SELECT * FROM user_activity_log WHERE user_f_id = ? ORDER BY created_at DESC", [userId], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    logUserActivity(userId, "Activity_Log", "Activity-Log Fetched Successfully", req);
    res.json({ activities: results });
  });
};
