const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateUser, authenticateSuperAdmin } = require('../midddlewares/authMiddleware');
const userController = require('../controllers/userController');

//Routes for User Controller

router.get('/get-organization', authenticateSuperAdmin,userController.getAllOrganizations);
router.get('/get-user-organization',userController.getAllUserOrganizationRoles);
router.get('/download/:fileName', userController.downloadFile);

router.post("/add-organization", authenticateSuperAdmin, userController.addOrganization);
router.post("/add-user", authenticateSuperAdmin, userController.addUser);

router.post('/add-family-member', authenticateUser ,userController.addFamily);
router.post('/add-job', userController.addJobs);

module.exports = router;