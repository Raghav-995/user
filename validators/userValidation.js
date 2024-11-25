const Joi = require('joi');

const addFamilySchema = Joi.object({
  familyPhoto: Joi.string().trim().messages({
  }),
  familyName: Joi.string().min(3).trim().required().messages({
    'string.min': 'Family member name should be at least 3 characters long',
    'any.required': 'Family member name is required',
  }),
  familyRelation: Joi.string().min(3).trim().required().messages({
    'string.min': 'Family member realtion should be at least 3 characters long',
    'any.required': 'Family member relation is required',
  }),
  familyEducation: Joi.string().min(3).trim().required().messages({
    'string.min': 'Family member education should be at least 3 characters long',
    'any.required': 'Family member education is required',
  }),
  familyAddress: Joi.string().min(3).trim().required().messages({
    'string.min': 'Family member address should be at least 3 characters long',
    'any.required': 'Family member address is required',
  }),
  familyCity: Joi.string().min(3).trim().required().messages({
    'string.min': 'Family member city should be at least 3 characters long',
    'any.required': 'Family member city is required',
  }),
  familyState: Joi.string().min(3).trim().required().messages({
    'string.min': 'Family member state should be at least 3 characters long',
    'any.required': 'Family member state is required',
  }),
  familyGender: Joi.string().min(3).required().messages({
    'string.min': 'Family member gender should be at least 3 characters long',
    'any.required': 'Family member gender is required',
  }),
  familyPinCode: Joi.string().length(6).trim().required().messages({
    'string.length': 'Pin code must be exactly 6 characters long',
    'any.required': 'Pin code is required',
  })
  
});

const addJobsSchema = Joi.object({
  jobRole: Joi.string().min(3).required().messages({
    'string.min': 'Job role should be at least 3 characters long',
    'any.required': 'Job role name is required',
  }),
  jobSalary: Joi.string().min(3).required().messages({
    'string.min': 'Salary should be at least 3 characters long',
    'any.required': 'Salary is required',
  }),
  jobDescription: Joi.string().min(3).required().messages({
    'string.min': 'Job description should be at least 3 characters long',
    'any.required': 'Job description is required',
  }),
  jobHrName: Joi.string().min(3).required().messages({
    'string.min': 'HR name should be at least 3 characters long',
    'any.required': 'HR name is required',
  }),
  jobTeamSize: Joi.string().required().messages({
    'any.required': 'Team size is required',
  }),
  jobEmail: Joi.string().email().required().messages({
    'string.min': 'Family member state should be at least 3 characters long',
    'any.required': 'Family member state is required',
  }),
  jobAbout: Joi.string().min(3).required().messages({
    'string.min': 'About organization should be at least 3 characters long',
    'any.required': 'About organization is required',
  }),
  jobDate: Joi.date().required().messages({
    'any.requiredd': 'Date is required',
  }),
  
})

module.exports = { addFamilySchema, addJobsSchema };