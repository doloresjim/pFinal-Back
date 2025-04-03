const { faker } = require('@faker-js/faker'); 
const axios = require('axios');

const API_URL = 'http://localhost:5001/api/register'; // Cambia el puerto si es diferente

// Generar datos aleatorios
const generateRandomUser = () => ({
  email: faker.internet.email(),
  username: faker.internet.username(),
  nombre: faker.person.firstName(),
  app: faker.person.lastName(),
  apm: faker.person.lastName(),
  grupo: faker.helpers.arrayElement(['A', 'B', 'C']),
  password: faker.internet.password({ length: 12, memorable: true }),
});

// Enviar múltiples peticiones
const testRateLimiter = async (numRequests) => {
  let successCount = 0;
  let errorCount = 0;
  let rateLimitCount = 0;

  for (let i = 0; i < numRequests; i++) {
    const user = generateRandomUser();

    try {
      const response = await axios.post(API_URL, user, {
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.status === 201) {
        console.log(`[✅ ${i + 1}] Usuario ${user.username} registrado correctamente.`);
        successCount++;
      }
    } catch (error) {
      if (error.response?.status === 429) {
        console.log(`[🚨 ${i + 1}] Bloqueado por rate limiter (429 Too Many Requests).`);
        rateLimitCount++;
      } else {
        console.log(`[⚠️ ${i + 1}] Error al registrar usuario ${user.username}:`, error.response?.data || error.message);
        errorCount++;
      }
    }
  }

  console.log(`\n✅ Exitosos: ${successCount}, 🚨 Bloqueados: ${rateLimitCount}, ⚠️ Otros errores: ${errorCount}`);
};

// 🔥 Ejecutar la prueba con 120 peticiones
testRateLimiter(120);
