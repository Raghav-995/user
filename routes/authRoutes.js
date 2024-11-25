const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateUser, authenticateSuperAdmin } = require('../midddlewares/authMiddleware');
const userController = require('../controllers/userController');


// router.post('/signup', authController.signup);
// router.post('/resend-verify-otp', authController.resendVerificationEmail);
// router.post("/verify-email", authController.verifyEmail);
// router.post('/login', authController.login);
// router.post('/set-pin', authenticateUser, authController.setPin);
// router.post('/verify-pin', authenticateUser, authController.verifyPin);
// router.post('/reset-pin', authenticateUser, authController.resetPin);
// router.post('/forgot-password', authController.forgotPassword);
// router.post('/verify-otp', authController.verifyOtp);
// router.post('/reset-password', authController.resetPassword);
// router.post('/logout', authController.logout);
// router.get("/activity-log", authenticateUser, authController.getUserActivityLog);

// router.get('/get-community', authController.getCommunities);

// router.post("/community/add", authenticateSuperAdmin, authController.addCommunity);

// router.get("/pending-requests", authenticateSuperAdmin, authController.getPendingRequests);

// router.post("/request/status", authenticateSuperAdmin, authController.updateRequestStatus);
// router.delete('/delete',authController.deleteUser);

router.post('/signup', authController.signup);
router.post('/resend-verify-otp', authController.resendVerificationEmail);
router.post("/verify-email", authController.verifyEmail);

router.post('/login', authController.login);
router.post('/set-pin', authenticateUser, authController.setPin);
router.post('/verify-pin', authenticateUser, authController.verifyPin);
router.post('/reset-pin', authenticateUser, authController.resetPin);

router.post('/forgot-password', authController.forgotPassword);
router.post('/verify-otp', authController.verifyOtp);
router.post('/resend-forgot-otp', authController.resendOtp);
router.post('/reset-password', authController.resetPassword);

router.post('/logout', authController.logout);
router.get("/activity-log", authenticateUser, authController.getUserActivityLog);

module.exports = router;