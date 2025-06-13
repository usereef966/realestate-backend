const axios = require('axios');

const instance_id = 'instance124299';
const token = 'hk7g25xetv3t58r5';

async function sendWhatsAppMessage(to, message) {
  try {
    const response = await axios.post(`https://api.ultramsg.com/${instance_id}/messages/chat`, {
      token: token,
      to: to,
      body: message
    });

    console.log('✅ WhatsApp sent:', response.data);
    return response.data;
  } catch (error) {
    console.error('❌ WhatsApp sending error:', error);
    throw error;
  }
}

module.exports = sendWhatsAppMessage; // 👈 تصدير الدالة
