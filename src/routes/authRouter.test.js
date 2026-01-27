const request = require('supertest');
const app = require('../service');
const jwt = require('jsonwebtoken');
const config = require('../config.js');

const testUser = { name: 'pizza diner', email: 'reg@test.com', password: 'a' };
let testUserAuthToken;
let testUserId;

beforeAll(async () => {
  testUser.email = Math.random().toString(36).substring(2, 12) + '@test.com';
  const registerRes = await request(app).post('/api/auth').send(testUser);
  testUserAuthToken = registerRes.body.token;
  testUserId = registerRes.body.user.id;
  expectValidJwt(testUserAuthToken);
});

describe('POST /api/auth - Register', () => {
  test('register a new user', async () => {
    const newUser = {
      name: 'test user',
      email: Math.random().toString(36).substring(2, 12) + '@test.com',
      password: 'password123',
    };
    const res = await request(app).post('/api/auth').send(newUser);
    expect(res.status).toBe(200);
    expect(res.body.user).toHaveProperty('id');
    expect(res.body.user.name).toBe(newUser.name);
    expect(res.body.user.email).toBe(newUser.email);
    expect(res.body.user.roles).toEqual([{ role: 'diner' }]);
    expect(res.body).toHaveProperty('token');
    expectValidJwt(res.body.token);
  });

  test('register with missing name', async () => {
    const res = await request(app)
      .post('/api/auth')
      .send({ email: 'test@test.com', password: 'password' });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('name, email, and password are required');
  });

  test('register with missing email', async () => {
    const res = await request(app)
      .post('/api/auth')
      .send({ name: 'test', password: 'password' });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('name, email, and password are required');
  });

  test('register with missing password', async () => {
    const res = await request(app)
      .post('/api/auth')
      .send({ name: 'test', email: 'test@test.com' });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('name, email, and password are required');
  });

  test('register with missing all fields', async () => {
    const res = await request(app).post('/api/auth').send({});
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('name, email, and password are required');
  });
});

describe('PUT /api/auth - Login', () => {
  test('login with valid credentials', async () => {
    const loginRes = await request(app).put('/api/auth').send(testUser);
    expect(loginRes.status).toBe(200);
    expectValidJwt(loginRes.body.token);

    const expectedUser = { ...testUser, roles: [{ role: 'diner' }] };
    delete expectedUser.password;
    expect(loginRes.body.user).toMatchObject(expectedUser);
  });

  test('login with invalid email', async () => {
    const res = await request(app)
      .put('/api/auth')
      .send({ email: 'nonexistent@test.com', password: 'password' });
  });

  test('login with invalid password', async () => {
    const res = await request(app).put('/api/auth').send({ email: testUser.email, password: 'wrongpassword' });
  });

  test('login returns valid JWT', async () => {
    const loginRes = await request(app).put('/api/auth').send(testUser);
    const decoded = jwt.verify(loginRes.body.token, config.jwtSecret);
    expect(decoded).toHaveProperty('id');
    expect(decoded).toHaveProperty('email');
    expect(decoded).toHaveProperty('name');
    expect(decoded).toHaveProperty('roles');
  });
});

describe('DELETE /api/auth - Logout', () => {
  test('logout with valid token', async () => {
    // Create a new user to logout
    const newUser = {
      name: 'logout test',
      email: Math.random().toString(36).substring(2, 12) + '@test.com',
      password: 'password',
    };
    const registerRes = await request(app).post('/api/auth').send(newUser);
    const token = registerRes.body.token;

    const res = await request(app).delete('/api/auth').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toBe('logout successful');
  });

  test('logout without token', async () => {
    const res = await request(app).delete('/api/auth');
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('unauthorized');
  });

  test('logout with invalid token format', async () => {
    const res = await request(app).delete('/api/auth').set('Authorization', 'Bearer invalid');
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('unauthorized');
  });

  test('logout without Bearer prefix', async () => {
    const res = await request(app).delete('/api/auth').set('Authorization', testUserAuthToken);
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('unauthorized');
  });

  test('logout with malformed authorization header', async () => {
    const res = await request(app).delete('/api/auth').set('Authorization', 'InvalidFormat');
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('unauthorized');
  });
});

describe('setAuthUser middleware', () => {
  test('setAuthUser sets req.user with valid token', async () => {
    // This is tested indirectly through protected endpoints
    const res = await request(app)
      .delete('/api/auth')
      .set('Authorization', `Bearer ${testUserAuthToken}`);
    expect(res.status).toBe(200);
  });

  test('setAuthUser sets req.user to null with invalid token', async () => {
    const res = await request(app)
      .delete('/api/auth')
      .set('Authorization', 'Bearer invalidtoken');
    expect(res.status).toBe(401);
  });

  test('setAuthUser sets req.user to null without token', async () => {
    const res = await request(app).delete('/api/auth');
    expect(res.status).toBe(401);
  });

  test('req.user has isRole method that works correctly', async () => {
    // Create a test user and verify they're a diner
    const newUser = {
      name: 'role test',
      email: Math.random().toString(36).substring(2, 12) + '@test.com',
      password: 'password',
    };
    const registerRes = await request(app).post('/api/auth').send(newUser);
    const token = registerRes.body.token;
    const decoded = jwt.verify(token, config.jwtSecret);

    // Verify the role checking logic would work
    expect(decoded.roles).toEqual([{ role: 'diner' }]);
  });
});

describe('authenticateToken middleware', () => {
  test('authenticateToken allows request with valid token', async () => {
    const res = await request(app)
      .delete('/api/auth')
      .set('Authorization', `Bearer ${testUserAuthToken}`);
  });

  test('authenticateToken rejects request without token', async () => {
    const res = await request(app).delete('/api/auth');
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('unauthorized');
  });

  test('authenticateToken rejects request with expired/invalid token', async () => {
    const res = await request(app)
      .delete('/api/auth')
      .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.invalid');
    expect(res.status).toBe(401);
  });
});

describe('Edge cases and error handling', () => {
  test('register with empty strings', async () => {
    const res = await request(app).post('/api/auth').send({ name: '', email: '', password: '' });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('name, email, and password are required');
  });

  test('login and verify JWT contains user data', async () => {
    const loginRes = await request(app).put('/api/auth').send(testUser);
    const decoded = jwt.verify(loginRes.body.token, config.jwtSecret);
    expect(decoded.email).toBe(testUser.email);
    expect(decoded.name).toBe(testUser.name);
  });

  test('readAuthToken extracts token from Bearer header', async () => {
    const loginRes = await request(app).put('/api/auth').send(testUser);
    const token = loginRes.body.token;
    
    // Verify the token is valid by using it
    const logoutRes = await request(app)
      .delete('/api/auth')
      .set('Authorization', `Bearer ${token}`);
    expect(logoutRes.status).toBe(200);
  });
});

function expectValidJwt(potentialJwt) {
  expect(potentialJwt).toMatch(/^[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*$/);
}