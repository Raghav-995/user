const mysql = require('mysql2');
require('dotenv').config();

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  // database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) throw err;
    console.log("Connected to MySQL database");

    db.query(
      `CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME}`,
      (err) => {
        if (err) throw err;

      console.log(`Database ${process.env.DB_NAME} checked/created`);

        // Switch to the newly created or existing database
      db.changeUser({ database: process.env.DB_NAME }, (err) => {
          if (err) throw err;

      console.log(`Switched to database: ${process.env.DB_NAME}`);

    db.query(`
      CREATE TABLE IF NOT EXISTS roles (
        role_id INT AUTO_INCREMENT PRIMARY KEY,
        role_name VARCHAR(50) UNIQUE NOT NULL,
        role_description TEXT NOT NULL,
        status BOOLEAN NOT NULL DEFAULT TRUE,
        created_by INT NOT NULL DEFAULT 1,
        created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_by INT NOT NULL DEFAULT 1,
        updated_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      );`,
        (err) => {
          if (err) throw err;
          console.log("Role table checked/created");
        });
    db.query(`CREATE TABLE IF NOT EXISTS organization (
      organization_id INT AUTO_INCREMENT PRIMARY KEY,
      organization_name VARCHAR(255) NOT NULL,
      organization_email_1 VARCHAR(255) NOT NULL,
      organization_email_2 VARCHAR(255) NOT NULL,
      organization_phone_1 VARCHAR(15) NOT NULL,
      organization_phone_2 VARCHAR(15) NOT NULL,
      organization_address_line_1 VARCHAR(100) NOT NULL,
      organization_address_line_2 VARCHAR(100) NOT NULL,
      organization_landmark VARCHAR(100) NOT NULL,
      organization_city VARCHAR(50) NOT NULL,
      organization_district VARCHAR(50) NOT NULL,
      organization_state VARCHAR(50) NOT NULL,
      organization_country VARCHAR(50) NOT NULL,
      organization_pincode VARCHAR(8) NOT NULL,
      organization_contact_person VARCHAR(50) NOT NULL,
      organization_contact_person_designation VARCHAR(50) NOT NULL,
      organization_contact_email VARCHAR(255) NOT NULL,
      organization_contact_mobile VARCHAR(15) NOT NULL,
      organization_logo VARCHAR(255) NOT NULL,
      status BOOLEAN DEFAULT TRUE, -- Active by default
      created_by INT NOT NULL DEFAULT 1,
      created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_by INT NOT NULL DEFAULT 1,
      updated_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      );`,
        (err) => {
          if (err) throw err;
          console.log("Organization table checked/created");
        }
        );
    // Create 'users' table if it doesn't exist
    db.query(`
      CREATE TABLE IF NOT EXISTS user (
      user_id INT AUTO_INCREMENT PRIMARY KEY,
      user_first_name VARCHAR(100) NOT NULL,
      user_last_name VARCHAR(100) NOT NULL,
      user_email VARCHAR(255) UNIQUE NOT NULL,
      user_phone_number VARCHAR(15) NOT NULL,
      user_password VARCHAR(255) NOT NULL,
      signup_otp CHAR(6),
      signup_otpcount INT DEFAULT 0,
      login_attempts INT DEFAULT 0,
      role_f_id INT NOT NULL,
      organization_f_id INT NOT NULL,
      status BOOLEAN DEFAULT FALSE,
      created_by INT NOT NULL DEFAULT 1,
      created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_by INT NOT NULL DEFAULT 1,
      updated_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_user_role FOREIGN KEY (role_f_id) REFERENCES roles(role_id),
      CONSTRAINT fk_user_organization FOREIGN KEY (organization_f_id) REFERENCES organization(organization_id)
      ) AUTO_INCREMENT=101;`, 
          (err) => {
              if (err) throw err;
              console.log("User table checked/created");
            });

    db.query(`
      CREATE TABLE IF NOT EXISTS forgot_password (
      fp_id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL, -- Foreign key referencing User table
      forgot_otp CHAR(6) NOT NULL, -- 6-character OTP for password reset
      forgot_otp_count INT DEFAULT 0, -- Counter for OTP attempts
      status BOOLEAN DEFAULT FALSE, -- False until the OTP is verified
      created_by INT NOT NULL DEFAULT 1,
      created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_by INT NOT NULL DEFAULT 1,
      updated_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_forgot_password_user FOREIGN KEY (user_id) REFERENCES user(user_id)
      );`,
        (err) => {
          if (err) throw err;
          console.log("Forgot Password table checked/created");
        });
    // Create 'token_blacklist' table if it doesn't exist
    db.query(`
      CREATE TABLE IF NOT EXISTS token_blacklist (
        tb_id INT AUTO_INCREMENT PRIMARY KEY,
        token VARCHAR(500) NOT NULL,
        blacklistedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );`,
        (err) => {
          if (err) throw err;
          console.log("Token blacklist table checked/created");
        });

    db.query(`
      CREATE TABLE IF NOT EXISTS user_activity_log (
        activity_id INT AUTO_INCREMENT PRIMARY KEY,
        user_f_id INT NOT NULL,
        ip_address VARCHAR(45),
        action VARCHAR(50),
        description TEXT,
        user_agent VARCHAR(255),
        created_by INT NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_by INT NOT NULL DEFAULT 1,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_f_id) REFERENCES user(user_id) ON DELETE CASCADE
      );`,
          (err) => {
          if (err) throw err;
          console.log("User Activity log table checked/created");
        });

    db.query(`CREATE TABLE IF NOT EXISTS user_pins (
      upins_id INT PRIMARY KEY AUTO_INCREMENT,
      user_f_id INT NOT NULL,
      pin VARCHAR(255) NOT NULL,           -- Stores the hashed PIN (six digits)
      isPinSet BOOLEAN DEFAULT FALSE,     -- Indicates if the PIN has been set
      biometric BOOLEAN DEFAULT FALSE,    -- Indicates if biometric authentication is enabled
      device_lock BOOLEAN DEFAULT FALSE,  -- Indicates if device lock is enabled
      created_by INT NOT NULL DEFAULT 1,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_by INT NOT NULL DEFAULT 1,
      updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_f_id) REFERENCES user(user_id) ON DELETE CASCADE
      );`,
          (err) => {
            if (err) throw err;
            console.log("User pins table checked/created");
        });

db.query(`
  CREATE TABLE IF NOT EXISTS family_members (
  fm_id INT AUTO_INCREMENT PRIMARY KEY,
  user_f_id INT NOT NULL,
  family_member_name VARCHAR(255) NOT NULL,
  family_member_gender ENUM('Male', 'Female', 'Other') NOT NULL,
  family_member_relation VARCHAR(100) NOT NULL,
  family_member_education VARCHAR(255),
  family_member_address TEXT,
  family_member_city VARCHAR(255),
  family_member_state VARCHAR(255),
  family_member_pincode VARCHAR(10),
  family_member_photo VARCHAR(255),  -- Store photo path or URL
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_f_id) REFERENCES user(user_id) ON DELETE CASCADE
);`,
    (err) => {
      if(err) throw err;
      console.log("Family members table created/checked");
    }
);

db.query(`
  CREATE TABLE IF NOT EXISTS super_admin_organizations (
    organization_id INT PRIMARY KEY AUTO_INCREMENT,
    organization_name VARCHAR(255) NOT NULL,
    created_by INT NOT NULL, -- Links to the SUPER_ADMIN user_id
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`,
(err) => {
  if(err) throw err;
  console.log("Super_Admin table created/checked");
}
)

//     db.query(`INSERT INTO organization (
//     organization_name,
//     organization_email_1,
//     organization_email_2,
//     organization_phone_1,
//     organization_phone_2,
//     organization_address_line_1,
//     organization_address_line_2,
//     organization_landmark,
//     organization_city,
//     organization_district,
//     organization_state,
//     organization_country,
//     organization_pincode,
//     organization_contact_person,
//     organization_contact_person_designation,
//     organization_contact_email,
//     organization_contact_mobile,
//     organization_logo,
//     created_by,
//     updated_by
// ) VALUES (
//     'NextAstra Technologies',
//     'raghvendrapathak2002@example.com',
//     'email2@example.com',
//     '9959142371',
//     '9876543210',
//     'Badangpet',
//     'Lakshmi Chowk',
//     'Pimpri-Chinchawad',
//     'Hyderabad',
//     'Hyderabad',
//     'Telanagana',
//     'India',
//     '500058',
//     'Raghavendra',
//     'Full Stack Dev',
//     'raghavendrapathak0@gmail.com',
//     '9959142371',
//     'path/to/logo.jpg',
//     1,  -- Assuming you want to set the created_by and updated_by to 1
//     1
// );`, (err) => {
//   if (err) throw err;
//   console.log("Inserted checked/created");
// });

// db.query(`INSERT INTO roles(role_name, role_description, status, created_by , updated_by) 
//       VALUES ('USER', 'User can handle users', TRUE, 1, 1 );
//   ` ,(err) => {
//       if (err) throw err;
//       console.log("Inserted 1 checked/created");
//     });

// db.query(`INSERT INTO roles(role_name, role_description, status, created_by , updated_by) 
//       VALUES ('ADMIN', 'Admin can handle users', TRUE, 1, 1 );
//   ` ,(err) => {
//       if (err) throw err;
//       console.log("Inserted 1 checked/created");
//     });


// db.query(`INSERT INTO roles(role_name, role_description, status, created_by , updated_by) 
//       VALUES ('SUPER_ADMIN', 'Super_Admin can handle both admins and users', TRUE, 1, 1 );
//   ` ,(err) => {
//       if (err) throw err;
//       console.log("Inserted 1 checked/created");
//     });

      });
    }
  );
});

module.exports = db;