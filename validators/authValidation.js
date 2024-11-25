const Joi = require('joi');

const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.email': 'Invalid email format',
    'any.required': 'Email is required',
  }),
  password: Joi.string().min(8).required().messages({
    'string.min': 'Password should be at least 8 characters long',
    'any.required': 'Password is required',
  })
});

const signupSchema = Joi.object({
  firstName: Joi.string().min(3).max(30).required().messages({
    'string.min': 'Username should be at least 3 characters long',
    'string.max': 'Username should be at most 30 characters long',
    'any.required': 'firstname is required',
  }),
  lastName: Joi.string().min(3).max(30).required().messages({
    'string.min': 'Username should be at least 3 characters long',
    'string.max': 'Username should be at most 30 characters long',
    'any.required': 'lastname is required',
  }),
  phoneNumber: Joi.string().pattern(/^[0-9]+$/).min(10).required().messages({
    'string.min': 'Phone number should be 10 characters long',
    'any.required': 'Phone number is required',
  }),
  email: Joi.string().email().required().messages({
    'string.email': 'Invalid email format',
    'any.required': 'Email is required',
  }),
  password: Joi.string().min(8).required().messages({
    'string.min': 'Password should be at least 8 characters long',
    'any.required': 'Password is required',
  }),
  role_id: Joi.number().required().messages({
    'any.required': 'role_id value is required'
  }),
  organization_id: Joi.number().required().messages({
    'any.required': 'organization_id value is required'
  }),
});

const emailSchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.email': 'Invalid email format',
    'any.required': 'Email is required',
  })
});

const otpSchema = Joi.object({
  email: Joi.string().email().required(),
  otp: Joi.string().length(6).required().messages({
    'string.length': 'OTP must be 6 digits long',
    'any.required': 'OTP is required'
  })
});

module.exports = {
  loginSchema,
  signupSchema,
  emailSchema,
  otpSchema
};

// const signupSchema = Joi.object({
//   firstName: Joi.string().min(3).max(30).required().messages({
//     'string.min': 'Username should be at least 3 characters long',
//     'string.max': 'Username should be at most 30 characters long',
//     'any.required': 'firstname is required',
//   }),
//   lastName: Joi.string().min(3).max(30).required().messages({
//     'string.min': 'Username should be at least 3 characters long',
//     'string.max': 'Username should be at most 30 characters long',
//     'any.required': 'lastname is required',
//   }),
//   phoneNumber: Joi.string().pattern(/^[0-9]+$/).min(10).required().messages({
//     'string.min': 'Phone number should be 10 characters long',
//     'any.required': 'Phone number is required',
//   }),
//   email: Joi.string().email().required().messages({
//     'string.email': 'Invalid email format',
//     'any.required': 'Email is required',
//   }),
//   password: Joi.string().min(8).required().messages({
//     'string.min': 'Password should be at least 8 characters long',
//     'any.required': 'Password is required',
//   }),
//   role: Joi.string().valid('user', 'admin', 'super_admin').required().messages({
//     'any.required': 'Role value is required',
//     'string.min': 'Role must be more than 3 characters'
//   }),
//   communityId: Joi.string().when('role', {
//     is: Joi.not('super_admin'),  // Exclude communityId for super-admin
//     then: Joi.required(),         // Only require communityId if the role is not super-admin
//     otherwise: Joi.forbidden()    // Make it forbidden if the role is super-admin
//   }).messages({
//     'any.required': 'CommunityId value is required',
//   }),
// });