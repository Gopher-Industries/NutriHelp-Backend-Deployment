const addContactUsMsg = require('../model/addContactUsMsg.js');
const { sendContactUsConfirmationEmail } = require('../utils/emailService');
const logger = require('../utils/logger');

const contactus = async (req, res) => {
  const { name, email, subject, message } = req.body;

  try {
    await addContactUsMsg(name, email, subject, message);

    try {
      await sendContactUsConfirmationEmail(email, { name, subject, message });
    } catch (emailError) {
      logger.error('Contact us confirmation email failed', { error: emailError.message, email });
    }

    return res.status(200).json({
      success: true,
      message: "Message received. A confirmation has been sent to your email."
    });
  } catch (error) {
    logger.error('Error saving contact us message', { error: error.message, email });
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
};

module.exports = { contactus };
