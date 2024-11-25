const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'Gmail', // or another service
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.sendResetEmail = (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Password Reset Request',
    text: `Your OTP for password reset is: ${otp}. It is valid for 15 minutes.`,
    html: `<p
              style="
                margin: 0;
                margin-top: 17px;
                font-weight: 500;
                letter-spacing: 0.56px;
              "
            >
              <p>OTP is
              valid for
              <span style="font-weight: 600; color: #1f1f1f;">15 minutes</span>.</p> 
              Do not share this code with others, including X
              employees.
            </p>
            <p
              style="
                margin: 0;
                margin-top: 40px;
                font-size: 35px;
                font-weight: 600;
                letter-spacing: 25px;
                color: #ADD8E6;
              "
            >
              ${otp}
            </p>
            `,
  };

  return transporter.sendMail(mailOptions,(error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      return res.status(500).json({ message: "Error sending email" });
    }
    res.json({ message: "Password reset link sent to your email." });
  });
};

// Send verification email
exports.sendVerificationEmail = async (email, otp) => {

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Email Verification",
    text: `Thank you for SignUp with X. Below is the 6 digits OTP. It is valid for only 15 mintues. Please verify your email by entering the OTP ${otp}.`,
    html: `<p
              style="
                margin: 0;
                margin-top: 17px;
                font-weight: 500;
                letter-spacing: 0.56px;
              "
            >
              <p>Thank you for SignUp with X account. Below is the 6 digit One Time Password OTP.</p>
              <p>Please verify your email. OTP is
              valid for only
              <span style="font-weight: 600; color: #1f1f1f;">15 minutes</span>.</p> 
              Do not share this code with others.
            </p>
            <p
              style="
                margin: 0;
                margin-top: 35px;
                font-size: 35px;
                font-weight: 600;
                letter-spacing: 25px;
                color: #ADD8E6;
              "
            >
              ${otp}
            </p>
            `,
  };

  await transporter.sendMail(mailOptions);
};

exports.sendApprovalEmail = async (email, message) => {

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Approval Request",
    text: `${message}`,
    html: `<p
              style="
                margin: 0;
                margin-top: 17px;
                font-weight: 500;
                letter-spacing: 0.56px;
              "
            >
             ${message}
            </p>
            `,
  };

  await transporter.sendMail(mailOptions);
};


exports.sendApprovedEmail = (to, message) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: 'Your Request has been Approved',
    text: message
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending approval email:', error);
    } else {
      console.log('Approval email sent:', info.response);
    }
  });
};

exports.sendRejectionEmail = (to, message) => {

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: 'Your Request has been Rejected',
    text: message
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending rejection email:', error);
    } else {
      console.log('Rejection email sent:', info.response);
    }
  });
};
