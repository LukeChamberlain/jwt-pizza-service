const request = require("supertest");
const app = require("../service");
const { Role, DB } = require("../database/database");

if (process.env.VSCODE_INSPECTOR_OPTIONS) {
  jest.setTimeout(60 * 1000 * 5);
}

function randomName() {
  return Math.random().toString(36).substring(2, 12);
}

async function createAdminUser() {
  let user = { password: "toomanysecrets", roles: [{ role: Role.Admin }] };
  user.name = randomName();
  user.email = user.name + "@admin.com";
  user = await DB.addUser(user);
  return { ...user, password: "toomanysecrets" };
}

function expectValidJwt(potentialJwt) {
  expect(potentialJwt).toMatch(
    /^[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*$/
  );
}

const testUser = { name: "pizza diner", email: "reg@test.com", password: "a" };
let testUserAuthToken;

beforeAll(async () => {
  testUser.email = randomName() + "@test.com";
  const registerRes = await request(app).post("/api/auth").send(testUser);
  testUserAuthToken = registerRes.body.token;
  expectValidJwt(testUserAuthToken);
});

describe("auth", () => {
  test("login", async () => {
    const loginRes = await request(app).put("/api/auth").send(testUser);
    expect(loginRes.status).toBe(200);
    expectValidJwt(loginRes.body.token);

    const expectedUser = { ...testUser, roles: [{ role: "diner" }] };
    delete expectedUser.password;
    expect(loginRes.body.user).toMatchObject(expectedUser);
  });

  test("register", async () => {
    const newUser = {
      name: randomName(),
      email: randomName() + "@test.com",
      password: "password123",
    };
    const registerRes = await request(app).post("/api/auth").send(newUser);
    expect(registerRes.status).toBe(200);
    expectValidJwt(registerRes.body.token);
    expect(registerRes.body.user.name).toBe(newUser.name);
    expect(registerRes.body.user.roles).toEqual([{ role: "diner" }]);
  });

  test("register fails with missing name", async () => {
    const res = await request(app)
      .post("/api/auth")
      .send({
        email: randomName() + "@test.com",
        password: "password",
      });
    expect(res.status).toBe(400);
    expect(res.body.message).toBeDefined();
  });

  test("register fails with missing email", async () => {
    const res = await request(app).post("/api/auth").send({
      name: randomName(),
      password: "password",
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toBeDefined();
  });

  test("register fails with missing password", async () => {
    const res = await request(app)
      .post("/api/auth")
      .send({
        name: randomName(),
        email: randomName() + "@test.com",
      });
    expect(res.status).toBe(400);
    expect(res.body.message).toBeDefined();
  });

  test("logout succeeds with valid token", async () => {
    const logoutRes = await request(app)
      .delete("/api/auth")
      .set("Authorization", `Bearer ${testUserAuthToken}`);
    expect(logoutRes.status).toBe(200);
    expect(logoutRes.body.message).toBe("logout successful");
  });

  test("logout fails without token", async () => {
    const logoutRes = await request(app).delete("/api/auth");
    expect(logoutRes.status).toBe(401);
    expect(logoutRes.body.message).toBe("unauthorized");
  });
});

describe("user", () => {
  let userToken;

  beforeAll(async () => {
    const user = {
      name: randomName(),
      email: randomName() + "@test.com",
      password: "password123",
    };
    const res = await request(app).post("/api/auth").send(user);
    userToken = res.body.token;
  });

  test("list users unauthorized", async () => {
    const listUsersRes = await request(app).get("/api/user");
    expect(listUsersRes.status).toBe(401);
  });




  function randomName() {
    return Math.random().toString(36).substring(2, 12);
  }

  test("get /me returns authenticated user", async () => {
    const res = await request(app)
      .get("/api/user/me")
      .set("Authorization", `Bearer ${userToken}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBeDefined();
    expect(res.body.name).toBeDefined();
  });

  test("get /me fails without token", async () => {
    const res = await request(app).get("/api/user/me");
    expect(res.status).toBe(401);
  });

  test("put /:userId updates user", async () => {
    // Get user ID first
    const getRes = await request(app)
      .get("/api/user/me")
      .set("Authorization", `Bearer ${userToken}`);
    const userId = getRes.body.id;

    const newName = randomName();
    const res = await request(app)
      .put(`/api/user/${userId}`)
      .set("Authorization", `Bearer ${userToken}`)
      .send({
        name: newName,
        email: getRes.body.email,
        password: "password123",
      });

    expect(res.status).toBe(200);
    expect(res.body.user.name).toBe(newName);
    expectValidJwt(res.body.token);
  });

  test("put /:userId fails without token", async () => {
    const res = await request(app).put("/api/user/1").send({ name: "newname" });
    expect(res.status).toBe(401);
  });

  test("put /:userId fails if updating another users profile", async () => {
    // Create another user
    const otherUser = {
      name: randomName(),
      email: randomName() + "@test.com",
      password: "password123",
    };
    const otherRes = await request(app).post("/api/auth").send(otherUser);
    const otherUserId = otherRes.body.user.id;

    // Try to update other user with first user's token
    const res = await request(app)
      .put(`/api/user/${otherUserId}`)
      .set("Authorization", `Bearer ${userToken}`)
      .send({
        name: "hacked",
        email: otherUser.email,
        password: "password123",
      });

    expect(res.status).toBe(403);
    expect(res.body.message).toBe("unauthorized");
  });

  test("delete /:userId returns not implemented", async () => {
    const res = await request(app)
      .delete("/api/user/1")
      .set("Authorization", `Bearer ${userToken}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("not implemented");
  });

  test("get / returns not implemented", async () => {
    const res = await request(app)
      .get("/api/user")
      .set("Authorization", `Bearer ${userToken}`);
    expect(res.status).toBe(200);
  });

  test("admin can update other users", async () => {
    const adminUser = await createAdminUser();
    const adminLoginRes = await request(app)
      .put("/api/auth")
      .send({ email: adminUser.email, password: adminUser.password });
    const adminToken = adminLoginRes.body.token;

    // Get the user ID first
    const getRes = await request(app)
      .get("/api/user/me")
      .set("Authorization", `Bearer ${userToken}`);
    const userId = getRes.body.id;

    const res = await request(app)
      .put(`/api/user/${userId}`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        name: "updated by admin",
        email: getRes.body.email,
        password: "newpassword",
      });

    expect(res.status).toBe(200);
  });
});

describe("order", () => {
  let userToken;
  let userId;
  let adminToken;
  let franchiseId;
  let storeId;

  beforeAll(async () => {
    // Create regular user
    const user = {
      name: randomName(),
      email: randomName() + "@test.com",
      password: "password123",
    };
    const userRes = await request(app).post("/api/auth").send(user);
    userToken = userRes.body.token;
    userId = userRes.body.user.id;

    // Create admin user
    const adminUser = await createAdminUser();
    const adminRes = await request(app)
      .put("/api/auth")
      .send({ email: adminUser.email, password: adminUser.password });
    adminToken = adminRes.body.token;

    // Create franchise
    const franchiseRes = await request(app)
      .post("/api/franchise")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        name: randomName(),
        admins: [{ email: adminUser.email }],
      });
    franchiseId = franchiseRes.body.id;

    // Create a store in the franchise
    const storeRes = await request(app)
      .post(`/api/franchise/${franchiseId}/store`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ name: randomName() });
    storeId = storeRes.body.id;
  });

  test("get /menu returns menu", async () => {
    const res = await request(app).get("/api/order/menu");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test("get / requires auth", async () => {
    const res = await request(app).get("/api/order");
    expect(res.status).toBe(401);
  });

  test("get / returns orders for authenticated user", async () => {
    const res = await request(app)
      .get("/api/order")
      .set("Authorization", `Bearer ${userToken}`);
    expect(res.status).toBe(200);
    expect(res.body.dinerId).toBe(userId);
    expect(Array.isArray(res.body.orders)).toBe(true);
  });

  test("post / requires auth", async () => {
    const res = await request(app)
      .post("/api/order")
      .send({
        franchiseId,
        storeId,
        items: [{ menuId: 1, description: "Item", price: 10 }],
      });
    expect(res.status).toBe(401);
  });

  test("put /menu requires admin", async () => {
    const res = await request(app)
      .put("/api/order/menu")
      .set("Authorization", `Bearer ${userToken}`)
      .send([{ title: "Pizza", price: 10 }]);
    expect(res.status).toBe(403);
  });

  test("put /menu requires auth", async () => {
    const res = await request(app)
      .put("/api/order/menu")
      .send([{ title: "Pizza", price: 10 }]);
    expect(res.status).toBe(401);
  });
});

describe("franchise", () => {
  let userToken;
  let adminToken;
  let adminId;
  let franchiseId;

  beforeAll(async () => {
    // Create regular user
    const user = {
      name: randomName(),
      email: randomName() + "@test.com",
      password: "password123",
    };
    const userRes = await request(app).post("/api/auth").send(user);
    userToken = userRes.body.token;

    // Create admin user
    const adminUser = await createAdminUser();
    const adminRes = await request(app)
      .put("/api/auth")
      .send({ email: adminUser.email, password: adminUser.password });
    adminToken = adminRes.body.token;
    adminId = adminRes.body.user.id;
  });

  test("get / returns franchises", async () => {
    const res = await request(app).get("/api/franchise");
    expect(res.status).toBe(200);
    expect(res.body.franchises).toBeDefined();
    expect(res.body.more).toBeDefined();
  });

  test("get /:userId requires auth", async () => {
    const res = await request(app).get("/api/franchise/1");
    expect(res.status).toBe(401);
  });

  test("get /:userId returns franchises for user", async () => {
    const res = await request(app)
      .get(`/api/franchise/${adminId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test("get /:userId returns empty for non-existent user franchises", async () => {
    const res = await request(app)
      .get("/api/franchise/99999")
      .set("Authorization", `Bearer ${userToken}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  test("post / requires admin role", async () => {
    const res = await request(app)
      .post("/api/franchise")
      .set("Authorization", `Bearer ${userToken}`)
      .send({
        name: randomName(),
        admins: [{ email: "test@test.com" }],
      });
    expect(res.status).toBe(403);
  });

  test("post / requires auth", async () => {
    const res = await request(app)
      .post("/api/franchise")
      .send({
        name: randomName(),
        admins: [{ email: "test@test.com" }],
      });
    expect(res.status).toBe(401);
  });

  test("delete /:franchiseId succeeds", async () => {
    const res = await request(app)
      .delete(`/api/franchise/${franchiseId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("franchise deleted");
  });

  test("post /:franchiseId/store requires auth", async () => {
    // Create franchise first
    const franchiseRes = await request(app)
      .post("/api/franchise")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        name: randomName(),
        admins: [{ email: randomName() + "@test.com" }],
      });
    const fId = franchiseRes.body.id;

    const res = await request(app)
      .post(`/api/franchise/${fId}/store`)
      .send({ name: randomName() });
    expect(res.status).toBe(401);
  });

  test("post /:franchiseId/store requires franchise admin", async () => {
    // Create franchise
    const franchiseRes = await request(app)
      .post("/api/franchise")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        name: randomName(),
        admins: [{ email: "admin" + randomName() + "@test.com" }],
      });
    const fId = franchiseRes.body.id;

    const res = await request(app)
      .post(`/api/franchise/${fId}/store`)
      .set("Authorization", `Bearer ${userToken}`)
      .send({ name: randomName() });
    expect(res.status).toBe(403);
  });

  test("delete /:franchiseId/store/:storeId requires franchise admin", async () => {
    const franchiseRes = await request(app)
      .post("/api/franchise")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        name: randomName(),
        admins: [{ email: randomName() + "@test.com" }],
      });
    const fId = franchiseRes.body.id;

    const res = await request(app)
      .delete(`/api/franchise/${fId}/store/1`)
      .set("Authorization", `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });

  test("delete /:franchiseId/store/:storeId succeeds", async () => {
    const franchiseRes = await request(app)
      .post("/api/franchise")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        name: randomName(),
        admins: [{ email: randomName() + "@test.com" }],
      });
    const fId = franchiseRes.body.id;

    const storeRes = await request(app)
      .post(`/api/franchise/${fId}/store`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ name: randomName() });
    const storeId = storeRes.body.id;

    const res = await request(app)
      .delete(`/api/franchise/${fId}/store/${storeId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("store deleted");
  });
});
