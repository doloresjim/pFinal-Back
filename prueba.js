const axios = require("axios");
const chalk = require("chalk").default; // Asegura que se usa la versión correcta

const API_URL = "http://localhost:5000/api/registro";
const TOTAL_REQUESTS = 110;

const testRequests = async () => {
  for (let i = 1; i <= TOTAL_REQUESTS; i++) {
    try {
      const response = await axios.post(API_URL, {
        username: `user${i}`,
        email: `user${i}@example.com`,
        password: "test1234",
      }, { withCredentials: true });
      
      console.log(chalk.green(`[✅ ÉXITO] Solicitud ${i}:`, response.data));
    } catch (error) {
      if (error.response) {
        console.log(chalk.red(`[❌ ERROR] Solicitud ${i}:`, error.response.data));
      } else {
        console.log(chalk.yellow(`[⚠️ OTRO ERROR] Solicitud ${i}:`, error.message));
      }
    }
  }
};

testRequests();