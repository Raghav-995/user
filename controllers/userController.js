const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const multer = require('multer');
const db = require('../config/db');
const path = require('path');
const fs = require('fs');
const {addFamilySchema, addJobsSchema} = require('../validators/userValidation');
const { loginSchema, signupSchema, emailSchema, otpSchema } = require('../validators/authValidation');

require('dotenv').config();

// Define the upload folder path
const UPLOAD_FOLDER = path.join(__dirname, 'uploads/organization_logos');

// Ensure the folder exists (if not, create it)
if (!fs.existsSync(UPLOAD_FOLDER)) {
    fs.mkdirSync(UPLOAD_FOLDER, { recursive: true }); // `recursive: true` ensures all intermediate directories are created
}

// Configure Multer storage for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, UPLOAD_FOLDER); // Folder where files will be saved
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname)); // Save file with a unique name
    }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // Limit to 5 MB
});

exports.addOrganization = async (req, res) => {
  upload.single('organizationLogo')(req, res, async function (err) {
      if (err) {
          return res.status(400).json({ error: 'File upload error' });
      }

      const schema = Joi.object({
          organizationName: Joi.string().required().messages({
              'any.required': 'Organization name is required',
          }),
          organizationEmail1: Joi.string().email().required(),
          organizationPhone1: Joi.string().required(),
          organizationCity: Joi.string().required(),
          organizationState: Joi.string().required(),
          organizationEmail2: Joi.string().required(),
          organizationPhone2: Joi.string().required(),
          organizationCountry: Joi.string().required(),
          organizationAddressLine1: Joi.string().required(),
          organizationAddressLine2: Joi.string().required(),
          organizationLandmark: Joi.string().required(),
          organizationDistrict: Joi.string().required(),
          organizationPinCode: Joi.string().required(),
          oContactPersonDesignation: Joi.string().required(),
          oContactPersonName: Joi.string().required(),
          oContactPersonMobile: Joi.string().required(),
          oContactPersonEmail: Joi.string().email().required(),
      });

      const { error } = schema.validate(req.body);
      if (error) return res.status(400).json({ error: error.details[0].message });

      try {
          const createdBy = req.user.id; // Extract authenticated user ID from middleware

                
      const [user] = await db.promise().query(
        "SELECT role_name FROM roles WHERE role_id = ?",
        [req.user.role]
      );
  
      if (!user.length) {
        return res.status(404).json({ error: "Role not found" });
      }
      // Check if the user has the Super Admin role
      if (user[0].role_name !== 'SUPER_ADMIN') {
        return res.status(403).send({ error: "Only Super Admin can add Organizations." });
      }

          const { 
              organizationName, 
              organizationEmail1,
              organizationEmail2, 
              organizationPhone1,
              organizationPhone2,
              organizationAddressLine1,
              organizationAddressLine2,
              organizationLandmark,
              organizationDistrict, 
              organizationCity, 
              organizationState, 
              organizationCountry,
              organizationPinCode,
              oContactPersonName,
              oContactPersonMobile,
              oContactPersonDesignation,
              oContactPersonEmail
          } = req.body;

          // const organizationLogo = req.file ? `/uploads/organization_logos/${req.file.filename}` : null;

          const [existingOrg] = await db.promise().query(
              'SELECT * FROM organization WHERE organization_name = ?',
              [organizationName]
          );

          if (existingOrg.length > 0) {
              return res.status(400).json({ error: 'Organization already exists' });
          }

          const query = `
              INSERT INTO organization (
                  organization_name,
                  organization_email_1,
                  organization_phone_1, 
                  organization_email_2,
                  organization_phone_2,
                  organization_address_line_1,
                  organization_address_line_2,
                  organization_landmark,
                  organization_city,
                  organization_district,
                  organization_state,
                  organization_country,
                  organization_pincode,
                  organization_contact_person,
                  organization_contact_person_designation,
                  organization_contact_email,
                  organization_contact_mobile,
                  status, created_by
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, TRUE, ?)
          `;
          const [result] = await db.promise().query(
              query, 
              [organizationName, organizationEmail1, organizationPhone1,organizationEmail2, organizationPhone2,
                organizationAddressLine1, organizationAddressLine2, organizationLandmark,
                organizationCity, organizationDistrict, organizationState, organizationCountry, organizationPinCode,
                oContactPersonName, oContactPersonDesignation, oContactPersonEmail, oContactPersonMobile, createdBy],
          );
          const organizationId = result.insertId;

          // If a file was uploaded, rename the file and update the organization record
          let organizationLogo = null;
          if (req.file) {
              const originalExtension = path.extname(req.file.originalname);
              const newFilename = `${organizationId}_${Date.now()}_${organizationName}${originalExtension}`;
              const newFilePath = path.join(UPLOAD_FOLDER, newFilename);

              // Rename the file
              fs.renameSync(req.file.path, newFilePath);

              // Save the logo filename in the database
              organizationLogo = newFilename;
              const updateQuery = `
                  UPDATE organization 
                  SET organization_logo = ? 
                  WHERE organization_id = ?
              `;
              await db.promise().query(updateQuery, [organizationLogo, organizationId]);
          }
          res.status(201).json({
            success: 'Organization added successfully',
            organizationId,
            organizationLogo: organizationLogo ? `/uploads/organization_logos/${organizationLogo}` : null
        });
      } catch (err) {
          console.error('Server error:', err);
          res.status(500).json({ error: 'Server error' });
      }
  });
};

  const BASE_URL = 'http://localhost:5000';
  
  exports.getAllOrganizations = async (req, res) => {
    try {
      // Validate that the user has permission to fetch this data (e.g., SUPER_ADMIN role)
      // const [user] = await db.promise().query(
      //   "SELECT role_name FROM roles WHERE role_id = ?",
      //   [req.user.role]
      // );
  
      // if (!user.length) {
      //   return res.status(404).json({ error: "Role not found" });
      // }
  
      // if (user[0].role_name !== 'SUPER_ADMIN') {
      //   return res.status(403).json({ error: "Only Super Admin can view all organizations." });
      // }
  
      // Query to fetch all organizations and their details
      const query = `
        SELECT 
          o.organization_id,
          o.organization_name,
          o.organization_email_1 AS organizationEmail1,
          o.organization_email_2 AS organizationEmail2,
          o.organization_phone_1 AS organizationPhone1,
          o.organization_phone_2 AS organizationPhone2,
          o.organization_address_line_1 AS organizationAddressLine1,
          o.organization_address_line_2 AS organizationAddressLine2,
          o.organization_landmark AS organizationLandmark,
          o.organization_city AS organizationCity,
          o.organization_district AS organizationDistrict,
          o.organization_state AS organizationState,
          o.organization_country AS organizationCountry,
          o.organization_pincode AS organizationPinCode,
          o.organization_contact_person AS oContactPersonName,
          o.organization_contact_person_designation AS oContactPersonDesignation,
          o.organization_contact_email AS oContactPersonEmail,
          o.organization_contact_mobile AS oContactPersonMobile,
          o.organization_logo AS organizationLogo,
          o.status,
          o.created_by AS createdBy,
          u.user_first_name AS createdByUserName, -- Assuming a 'users' table for the user info
          r.role_name AS userRole -- Assuming a 'roles' table for role details
        FROM organization o
        LEFT JOIN user u ON o.created_by = u.user_id
        LEFT JOIN roles r ON u.role_f_id = r.role_id
        ORDER BY o.organization_name
      `;
  
      const [organizations] = await db.promise().query(query);
  
      // Check if organizations exist
      if (!organizations.length) {
        return res.status(404).json({ error: "No organizations found." });
      }
  
      // Append the full logo URL for each organization
      const dataWithLogoURL = organizations.map(org => ({
        ...org,
        organizationLogo: org.organizationLogo
          ? `${BASE_URL}/uploads/organization_logos/${org.organizationLogo}`
          : null, // Handle cases where no logo is provided
      }));
  
      // Return all the organization details
      res.status(200).json({
        message: 'Organizations fetched successfully',
        data: dataWithLogoURL,
      });
    } catch (err) {
      console.error('Server error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  };
  
  exports.getAllUserOrganizationRoles = async (req, res) => {
    try {
      const query = `
        SELECT 
          organization_id,
          organization_name,
          organization_logo  -- Assuming your database has this column for logo
        FROM organization 
        WHERE status = True
        ORDER BY organization_name ASC;
      `;
  
      const [organizations] = await db.promise().query(query);
  
      // Check if organizations exist
      if (!organizations.length) {
        return res.status(404).json({ error: "No organizations found." });
      }
  
      // Append the full logo URL for each organization
      const dataWithLogoURL = organizations.map(org => ({
        ...org,
        organizationLogo: org.organization_logo
          ? `${BASE_URL}/uploads/organization_logos/${org.organization_logo}`
          : null,  // Handle cases where no logo is provided
      }));
  
      const query2 = `
      SELECT 
        role_id,
        role_name
      FROM roles
      WHERE status = True
      ORDER BY role_name ASC;
    `;

    const [roles] = await db.promise().query(query2);

    // Check if organizations exist
    if (!roles.length) {
      return res.status(404).json({ error: "No roles found." });
    }

          // Append the full logo URL for each organization
          const role = roles.map(org => ({
            ...org,
          }));
      // Return all the organization details
      res.status(200).json({
        success: 'Organizations fetched successfully',
        organizations: dataWithLogoURL,
        roles: role
      });
    } catch (err) {
      console.error('Server error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  };

  exports.addUser = async (req, res) => {
    const { error } = signupSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });
  
    const { firstName, lastName, email, password, phoneNumber, role_id, organization_id } = req.body;
  
    try {
      const adminId = req.user.role;
      const [roleName] = await db.promise().query(
        "SELECT role_id, role_name FROM roles WHERE role_id = ?",
        [adminId]
      );
  
      if (roleName.length === 0) {
        return res.status(400).json({ error: "Invalid role_id specified" });
      }
  
      const role_name = roleName[0].role_name;

      console.log(role_name)

      if (role_name === "SUPER_ADMIN" || "ADMIN") {

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
          signup_otp, signup_otpcount, status, created_by, updated_by, created_timestamp, updated_timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, FALSE, ?, ?, NOW(), NOW())`,
        [firstName, lastName, email, hashedPassword, phoneNumber, role_id, organization_id, otp, adminId, adminId]
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
  
      
      logUserActivity(adminId, "Adding User", "User Added Successfully", req);
  
  
      res.json({
        success: "User added successfully! The OTP is send to email to verify the account."
      });
    } 
    else{
      return res.status(400).json({ error: "Users can be added only by Admin and Super_admin." });
    } 
  }catch (err) {
      console.error("Error during signup:", err);
      res.status(500).json({ error: "Error creating user" });
    }
  };
  

  exports.addFamily = async (req, res) => {
    const { error } = addFamilySchema.validate(req.body);
  
    if (error) {
      return res.status(400).json({ error: error.details[0].message }); // Ensure early return
    }
  
    try {
      const {
        familyPhoto,
        familyName,
        familyRelation,
        familyEducation,
        familyAddress,
        familyCity,
        familyState,
        familyPinCode,
        familyGender,
      } = req.body;
  
      // Validate required fields
      if (!familyName || !familyGender || !familyRelation) {
        return res.status(400).json({
          error: "Name, gender, and relation are required.",
        }); // Early return
      }
  
      const userId = req.user;
  
      // Query to insert family member data
      const query = `
        INSERT INTO family_members 
        (user_f_id, family_member_name, family_member_gender, family_member_relation, family_member_education, family_member_address, family_member_city, family_member_state, family_member_pincode, family_member_photo) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
  
      const values = [
        userId,
        familyName,
        familyGender,
        familyRelation,
        familyEducation,
        familyAddress,
        familyCity,
        familyState,
        familyPinCode,
        familyPhoto,
      ];
  
      // Execute the query
      const [result] = await db.promise().query(query, values);
  
      // Send success response
      return res.status(201).json({
        success: "Family member added successfully.",
        fm_id: result.insertId, // Return the inserted family member's ID
      });
    } catch (err) {
      // Log error for debugging
      console.error("Error adding family member:", err);
  
      // Send error response only once
      return res.status(500).json({
        error: "An error occurred while adding the family member.",
      });
    }
  };
  
  exports.downloadFile = (req, res) => {
    const { fileName } = req.params; // Pass the file name as a parameter in the request
    const filePath = path.join(__dirname, 'uploads/organization_logos', fileName);
  
    res.download(filePath, (err) => {
      if (err) {
        console.error('Error in downloading file:', err);
        res.status(500).json({ error: 'Error in downloading file' });
      }
    });
  };
  
exports.addJobs = (req,res) => {
    const {error} = addJobsSchema.validate(req.body);

    if(error) res.status(400).json({error: error.details[0].message});
}