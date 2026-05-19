require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { PrismaClient } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();

const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET;

if (process.env.NODE_ENV === "production" && !JWT_SECRET) {
  throw new Error("JWT_SECRET must be set in production");
}

const rawCorsOrigins = String(process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || "");
const defaultCorsOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "http://localhost:8080",
  "https://smsfrontend-hlja.onrender.com",
];
const allowedOrigins = rawCorsOrigins
  ? rawCorsOrigins
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
  : defaultCorsOrigins;

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json({ limit: "6mb" }));

const sendOk = (res, message, data) => res.json({ status: "ok", message, data });
const sendError = (res, status, message) => res.status(status).json({ status: "error", message });

const hashPassword = async (value) => bcrypt.hash(String(value || ""), 10);
const verifyPassword = async (value, hash) => bcrypt.compare(String(value || ""), hash);

const createToken = (user) =>
  jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });

const requireAuth = async (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) {
    return sendError(res, 401, "Missing authorization token");
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({ where: { id: payload.sub } });
    if (!user) {
      return sendError(res, 401, "Invalid user");
    }
    req.user = user;
    return next();
  } catch (_err) {
    return sendError(res, 401, "Invalid or expired token");
  }
};

const requireRole = (...roles) => (req, res, next) => {
  const userRole = req.user ? req.user.role : "";
  if (!roles.includes(userRole)) {
    return sendError(res, 403, "Insufficient permission");
  }
  return next();
};

const getStudentByUser = async (userId) =>
  prisma.student.findUnique({ where: { userId }, include: { department: true } });

const formatStudentProfile = (student) => {
  if (!student) return null;
  return {
    id: student.id,
    studentNo: student.studentNo,
    name: student.name,
    department: student.department ? student.department.name : "",
    departmentId: student.departmentId,
    level: student.level,
    status: student.status,
    createdAt: student.createdAt,
    updatedAt: student.updatedAt,
  };
};

const getSemesterCode = (semester) => {
  const normalized = String(semester || "").toLowerCase();
  if (normalized.includes("first")) return "FS";
  if (normalized.includes("second")) return "SS";
  return normalized
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part[0])
    .join("")
    .toUpperCase() || "SEM";
};

const generateRegistrationNo = async (tx, { studentNo, academicYear, semester }) => {
  const yearCode = String(academicYear || "").replace(/\D/g, "") || new Date().getFullYear();
  const studentCode = String(studentNo || "").replace(/[^a-z0-9]/gi, "").toUpperCase();
  const semesterCode = getSemesterCode(semester);
  const count = await tx.registration.count({
    where: { studentNo, academicYear, semester },
  });
  return `REG-${yearCode}-${semesterCode}-${studentCode}-${String(count + 1).padStart(3, "0")}`;
};

const toDepartmentName = (value) => {
  if (!value) return "";
  if (typeof value === "string") return value.trim();
  return String(value.name || value.department || value.departmentName || "").trim();
};

const scoreToGrade = (total) => {
  if (total >= 70) return "A";
  if (total >= 60) return "B";
  if (total >= 50) return "C";
  if (total >= 45) return "D";
  if (total >= 40) return "E";
  return "F";
};

const computeGpa = (rows) => {
  if (!rows.length) return "0.00";
  const gradePoint = (grade) => {
    if (grade === "A") return 5;
    if (grade === "B") return 4;
    if (grade === "C") return 3;
    if (grade === "D") return 2;
    if (grade === "E") return 1;
    return 0;
  };
  const totals = rows.reduce(
    (acc, row) => {
      const units = Number(row.unit) || 0;
      return {
        quality: acc.quality + gradePoint(row.grade) * units,
        units: acc.units + units,
      };
    },
    { quality: 0, units: 0 }
  );
  if (!totals.units) return "0.00";
  return (totals.quality / totals.units).toFixed(2);
};

const ensureSuperAdmin = async () => {
  const existing = await prisma.user.findFirst({ where: { role: "super_admin" } });
  if (existing) return;

  const username = String(process.env.SUPER_ADMIN_USERNAME || "").trim();
  const password = String(process.env.SUPER_ADMIN_PASSWORD || "").trim();
  const name = String(process.env.SUPER_ADMIN_NAME || "Super Admin").trim();
  const email = String(process.env.SUPER_ADMIN_EMAIL || "").trim() || null;

  if (!username || !password) {
    console.warn("SUPER_ADMIN_USERNAME/PASSWORD not set. Skipping super admin creation.");
    return;
  }

  await prisma.user.create({
    data: {
      username,
      name,
      email,
      role: "super_admin",
      status: "Active",
      passwordHash: await hashPassword(password),
    },
  });

  console.log("Super admin created:", username);
};

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  const normalized = String(username || "").trim();
  if (!normalized || !password) {
    return sendError(res, 400, "Username and password are required");
  }

  const user = await prisma.user.findUnique({ where: { username: normalized } });
  if (!user) {
    return sendError(res, 401, "Invalid credentials");
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    return sendError(res, 401, "Invalid credentials");
  }

  const token = createToken(user);
  await prisma.user.update({
    where: { id: user.id },
    data: { lastLogin: new Date() },
  });

  let studentNo = "";
  if (user.role === "student") {
    const student = await prisma.student.findUnique({ where: { userId: user.id } });
    studentNo = student ? student.studentNo : "";
  }

  return sendOk(res, "Login successful", {
    token,
    user: {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
      status: user.status,
      studentNo,
      lastLogin: user.lastLogin,
    },
  });
});

app.get("/api/admin/overview", requireAuth, requireRole("admin", "super_admin"), async (_req, res) => {
  const [departments, users, students, courses, registrations, results, submissions, tasks] =
    await Promise.all([
      prisma.department.findMany({ orderBy: { name: "asc" } }),
      prisma.user.findMany({
        where: { role: { in: ["admin", "super_admin", "lecturer", "support"] } },
        select: {
          id: true,
          username: true,
          name: true,
          role: true,
          status: true,
          email: true,
          lastLogin: true,
          createdAt: true,
        },
      }),
      prisma.student.findMany({ include: { department: true } }),
      prisma.course.findMany({ orderBy: { code: "asc" }, include: { department: true } }),
      prisma.registration.findMany({ orderBy: { createdAt: "desc" } }),
      prisma.result.findMany({ orderBy: { createdAt: "desc" } }),
      prisma.submission.findMany({ orderBy: { submittedAt: "desc" } }),
      prisma.task.findMany({ orderBy: { createdAt: "desc" } }),
    ]);

  return sendOk(res, "Overview loaded", {
    departments,
    users,
    students,
    courses,
    registrations,
    results,
    submissions,
    tasks,
  });
});

app.get("/api/admin/activity", requireAuth, requireRole("admin", "super_admin"), async (_req, res) => {
  const [latestStudent, latestUser, latestCourse, latestRegistration, latestResult, latestTask] =
    await Promise.all([
      prisma.student.findFirst({ orderBy: { id: "desc" } }),
      prisma.user.findFirst({ orderBy: { id: "desc" }, where: { role: { in: ["admin", "super_admin", "lecturer", "support"] } } }),
      prisma.course.findFirst({ orderBy: { id: "desc" } }),
      prisma.registration.findFirst({ orderBy: { createdAt: "desc" } }),
      prisma.result.findFirst({ orderBy: { createdAt: "desc" } }),
      prisma.task.findFirst({ orderBy: { createdAt: "desc" } }),
    ]);

  const items = [];
  if (latestStudent) items.push(`Student added: ${latestStudent.name} (${latestStudent.studentNo})`);
  if (latestUser) items.push(`User added: ${latestUser.name} (${latestUser.role})`);
  if (latestCourse) items.push(`Course added: ${latestCourse.code} (${latestCourse.title})`);
  if (latestRegistration) {
    const firstCourse = Array.isArray(latestRegistration.courses)
      ? latestRegistration.courses[0]
      : "No course selected";
    items.push(`New registration: ${latestRegistration.regNo} - ${firstCourse}`);
  }
  if (latestResult) items.push(`Result added: ${latestResult.course} (${latestResult.grade})`);
  if (latestTask) items.push(`Task created: ${latestTask.text}`);

  return sendOk(res, "Activity loaded", items);
});

app.get("/api/admin/dashboard", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const recentPage = Number(req.query.recent_page || 1);
  const recentLimit = Number(req.query.recent_limit || 3);
  const studentFilter = String(req.query.recent_student_no || "").trim().toLowerCase();
  const courseFilter = String(req.query.recent_course_code || "").trim().toLowerCase();

  const students = await prisma.student.findMany();
  const registrations = await prisma.registration.findMany({ orderBy: { createdAt: "desc" } });
  const results = await prisma.result.findMany();
  const tasks = await prisma.task.findMany({ orderBy: { createdAt: "desc" } });

  const filtered = registrations.filter((item) => {
    const byStudent = !studentFilter || item.studentNo.toLowerCase().includes(studentFilter);
    const courseLabels = Array.isArray(item.courses) ? item.courses : [];
    const byCourse =
      !courseFilter ||
      courseLabels.some((label) => String(label).toLowerCase().includes(courseFilter));
    return byStudent && byCourse;
  });

  const pages = Math.max(1, Math.ceil(filtered.length / recentLimit));
  const safePage = Math.min(Math.max(recentPage, 1), pages);
  const start = (safePage - 1) * recentLimit;
  const list = filtered.slice(start, start + recentLimit).map((item) => {
    const firstCourse = Array.isArray(item.courses) && item.courses.length
      ? item.courses[0]
      : "No course selected";
    return `${item.studentNo} - ${firstCourse}`;
  });

  const departmentCount = new Set(students.map((student) => student.departmentId)).size;
  const pendingResults = Math.max(0, registrations.length - results.length);
  const registrationHolds = students.filter((student) => student.status.toLowerCase() !== "active").length;

  return sendOk(res, "Dashboard loaded", {
    activeStudents: students.length,
    departments: departmentCount,
    pendingResults,
    registrationHolds,
    recentRegistrations: list,
    recentMeta: { page: safePage, pages },
    tasks,
  });
});

app.get("/api/departments", requireAuth, async (_req, res) => {
  const departments = await prisma.department.findMany({ orderBy: { name: "asc" } });
  return sendOk(res, "Departments loaded", departments);
});

app.post("/api/departments", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const name = String(req.body.name || "").trim();
  if (!name) return sendError(res, 400, "Department name is required");

  const existing = await prisma.department.findUnique({ where: { name } });
  if (existing) return sendError(res, 409, "Department already exists");

  const department = await prisma.department.create({ data: { name } });
  return sendOk(res, "Department created", department);
});

app.put("/api/departments/:id", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const name = String(req.body.name || "").trim();
  if (!name) return sendError(res, 400, "Department name is required");

  const duplicate = await prisma.department.findFirst({
    where: { name, NOT: { id: req.params.id } },
  });
  if (duplicate) return sendError(res, 409, "Another department already uses this name");

  const department = await prisma.department.update({
    where: { id: req.params.id },
    data: { name },
  });
  return sendOk(res, "Department updated", department);
});

app.delete("/api/departments/:id", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const [studentCount, courseCount] = await Promise.all([
    prisma.student.count({ where: { departmentId: req.params.id } }),
    prisma.course.count({ where: { departmentId: req.params.id } }),
  ]);
  if (studentCount) return sendError(res, 400, "Cannot delete department assigned to students");
  if (courseCount) return sendError(res, 400, "Cannot delete department assigned to courses");

  await prisma.department.delete({ where: { id: req.params.id } });
  return sendOk(res, "Department deleted", null);
});

app.get("/api/users", requireAuth, requireRole("admin", "super_admin"), async (_req, res) => {
  const users = await prisma.user.findMany({
    where: { role: { in: ["admin", "super_admin", "lecturer", "support"] } },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      username: true,
      name: true,
      role: true,
      status: true,
      email: true,
      lastLogin: true,
      createdAt: true,
    },
  });
  return sendOk(res, "Users loaded", users);
});

app.post("/api/users", requireAuth, requireRole("super_admin"), async (req, res) => {
  const name = String(req.body.name || "").trim();
  const role = String(req.body.role || "Admin").trim().toLowerCase();
  const status = String(req.body.status || "Active").trim();
  const email = String(req.body.email || "").trim() || null;
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();

  if (!name || !username || !password) {
    return sendError(res, 400, "Name, username, and password are required");
  }

  const allowed = new Set(["admin", "lecturer", "support"]);
  if (!allowed.has(role)) {
    return sendError(res, 400, "Role must be admin, lecturer, or support");
  }

  const existing = await prisma.user.findUnique({ where: { username } });
  if (existing) return sendError(res, 409, "Username already exists");

  const user = await prisma.user.create({
    data: {
      username,
      name,
      role,
      status,
      email,
      passwordHash: await hashPassword(password),
    },
  });

  return sendOk(res, "User created", user);
});

app.put("/api/users/:id", requireAuth, requireRole("super_admin"), async (req, res) => {
  const name = String(req.body.name || "").trim();
  const role = String(req.body.role || "").trim().toLowerCase();
  const status = String(req.body.status || "").trim();
  const email = String(req.body.email || "").trim() || null;
  const username = String(req.body.username || "").trim();

  if (!name || !role || !status || !username) {
    return sendError(res, 400, "Name, username, role, and status are required");
  }

  const allowed = new Set(["admin", "lecturer", "support", "super_admin"]);
  if (!allowed.has(role)) {
    return sendError(res, 400, "Invalid role" );
  }

  const duplicate = await prisma.user.findFirst({
    where: { username, NOT: { id: req.params.id } },
  });
  if (duplicate) return sendError(res, 409, "Another user already uses this username");

  const user = await prisma.user.update({
    where: { id: req.params.id },
    data: { name, role, status, email, username },
  });
  return sendOk(res, "User updated", user);
});

app.delete("/api/users/:id", requireAuth, requireRole("super_admin"), async (req, res) => {
  await prisma.user.delete({ where: { id: req.params.id } });
  return sendOk(res, "User deleted", null);
});

app.get("/api/students", requireAuth, async (req, res) => {
  const departmentName = String(req.query.department || "").trim();
  if (req.user.role === "student") {
    const student = await getStudentByUser(req.user.id);
    return sendOk(res, "Students loaded", student ? [student] : []);
  }

  const where = departmentName
    ? { department: { name: { equals: departmentName } } }
    : {};

  const students = await prisma.student.findMany({
    where,
    include: { department: true },
    orderBy: { createdAt: "desc" },
  });

  return sendOk(res, "Students loaded", students);
});

app.post("/api/students", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const studentNo = String(req.body.studentNo || "").trim();
  const name = String(req.body.name || "").trim();
  const department = String(req.body.department || "").trim();
  const level = String(req.body.level || "").trim();
  const status = String(req.body.status || "Active").trim();

  if (!studentNo || !name || !department || !level) {
    return sendError(res, 400, "Student number, name, department, and level are required");
  }

  const dept = await prisma.department.findUnique({ where: { name: department } });
  if (!dept) return sendError(res, 400, "Please select a valid department");

  const existingUser = await prisma.user.findUnique({ where: { username: studentNo } });
  if (existingUser) return sendError(res, 409, "Student number already exists" );

  const student = await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({
      data: {
        username: studentNo,
        name,
        role: "student",
        status,
        passwordHash: await hashPassword(studentNo),
      },
    });

    return tx.student.create({
      data: {
        studentNo,
        name,
        departmentId: dept.id,
        level,
        status,
        userId: user.id,
      },
      include: { department: true },
    });
  });

  return sendOk(res, "Student created", student);
});

app.put("/api/students/:id", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const studentNo = String(req.body.studentNo || "").trim();
  const name = String(req.body.name || "").trim();
  const department = String(req.body.department || "").trim();
  const level = String(req.body.level || "").trim();
  const status = String(req.body.status || "").trim();

  if (!studentNo || !name || !department || !level || !status) {
    return sendError(res, 400, "Student fields are incomplete" );
  }

  const dept = await prisma.department.findUnique({ where: { name: department } });
  if (!dept) return sendError(res, 400, "Please select a valid department");

  const target = await prisma.student.findUnique({ where: { id: req.params.id } });
  if (!target) return sendError(res, 404, "Student not found" );

  const duplicate = await prisma.student.findFirst({
    where: { studentNo, NOT: { id: req.params.id } },
  });
  if (duplicate) return sendError(res, 409, "Another student already uses this number" );

  const updated = await prisma.$transaction(async (tx) => {
    await tx.user.update({
      where: { id: target.userId },
      data: {
        username: studentNo,
        name,
        status,
        passwordHash: await hashPassword(studentNo),
      },
    });

    return tx.student.update({
      where: { id: req.params.id },
      data: {
        studentNo,
        name,
        departmentId: dept.id,
        level,
        status,
      },
      include: { department: true },
    });
  });

  return sendOk(res, "Student updated", updated);
});

app.delete("/api/students/:id", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const target = await prisma.student.findUnique({ where: { id: req.params.id } });
  if (!target) return sendError(res, 404, "Student not found" );

  await prisma.$transaction([
    prisma.result.deleteMany({ where: { studentId: target.id } }),
    prisma.registration.deleteMany({ where: { studentId: target.id } }),
    prisma.submission.deleteMany({ where: { studentId: target.id } }),
    prisma.student.delete({ where: { id: target.id } }),
    prisma.user.delete({ where: { id: target.userId } }),
  ]);

  return sendOk(res, "Student deleted", null);
});

app.get("/api/courses", requireAuth, async (_req, res) => {
  const courses = await prisma.course.findMany({
    orderBy: { code: "asc" },
    include: { department: true },
  });
  return sendOk(res, "Courses loaded", courses);
});

app.get("/api/courses/options", requireAuth, async (_req, res) => {
  const courses = await prisma.course.findMany({
    orderBy: { code: "asc" },
    include: { department: true },
  });
  const options = courses.map((course) => ({
    id: course.id,
    label: `${course.code} - ${course.title}`,
    semester: course.semester,
    department: course.department ? course.department.name : "",
  }));
  return sendOk(res, "Course options loaded", options);
});

app.post("/api/courses", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const code = String(req.body.code || "").trim();
  const title = String(req.body.title || "").trim();
  const units = Number(req.body.units || 0);
  const semester = String(req.body.semester || "").trim();
  const departmentName = String(req.body.department || "").trim();

  if (!code || !title || !units || !semester || !departmentName) {
    return sendError(res, 400, "Course code, title, units, semester, and department are required");
  }

  const dept = await prisma.department.findUnique({ where: { name: departmentName } });
  if (!dept) return sendError(res, 400, "Please select a valid department");

  const duplicate = await prisma.course.findUnique({ where: { code } });
  if (duplicate) return sendError(res, 409, "Course code already exists");

  const course = await prisma.course.create({
    data: { code, title, units, semester, departmentId: dept.id },
  });
  return sendOk(res, "Course created", course);
});

app.put("/api/courses/:id", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const code = String(req.body.code || "").trim();
  const title = String(req.body.title || "").trim();
  const units = Number(req.body.units || 0);
  const semester = String(req.body.semester || "").trim();
  const departmentName = String(req.body.department || "").trim();

  if (!code || !title || !units || !semester || !departmentName) {
    return sendError(res, 400, "Course code, title, units, semester, and department are required");
  }

  const dept = await prisma.department.findUnique({ where: { name: departmentName } });
  if (!dept) return sendError(res, 400, "Please select a valid department");

  const duplicate = await prisma.course.findFirst({
    where: { code, NOT: { id: req.params.id } },
  });
  if (duplicate) return sendError(res, 409, "Another course already uses this code");

  const course = await prisma.course.update({
    where: { id: req.params.id },
    data: { code, title, units, semester, departmentId: dept.id },
  });
  return sendOk(res, "Course updated", course);
});

app.delete("/api/courses/:id", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  await prisma.course.delete({ where: { id: req.params.id } });
  return sendOk(res, "Course deleted", null);
});

app.post("/api/registrations", requireAuth, async (req, res) => {
  const studentNo = String(req.body.studentNo || "").trim();
  const semester = String(req.body.semester || "").trim();
  const academicYear = String(req.body.academicYear || "").trim();
  const courses = Array.isArray(req.body.courses) ? req.body.courses : [];

  if (!studentNo || !semester || !academicYear) {
    return sendError(res, 400, "Registration fields are incomplete" );
  }

  const student = await prisma.student.findUnique({ where: { studentNo } });
  if (!student) return sendError(res, 404, "Student not found" );

  if (req.user.role === "student") {
    const current = await getStudentByUser(req.user.id);
    if (!current || current.studentNo !== studentNo) {
      return sendError(res, 403, "Cannot register for another student" );
    }
  }

  const registration = await prisma.$transaction(async (tx) => {
    const regNo = await generateRegistrationNo(tx, { studentNo, academicYear, semester });
    return tx.registration.create({
      data: {
        studentId: student.id,
        studentNo,
        regNo,
        semester,
        academicYear,
        courses,
      },
    });
  });

  return sendOk(res, "Registration saved", registration);
});

app.get("/api/registered-courses", requireAuth, async (req, res) => {
  const studentNo = String(req.query.studentNo || "").trim();
  const academicYear = String(req.query.academicYear || "").trim();
  const semester = String(req.query.semester || "").trim();

  if (!studentNo || !academicYear || !semester) {
    return sendOk(res, "Registered courses loaded", []);
  }

  const student = await prisma.student.findUnique({ where: { studentNo } });
  if (!student) return sendOk(res, "Registered courses loaded", []);

  const registrations = await prisma.registration.findMany({
    where: { studentId: student.id, academicYear, semester },
  });

  const labels = new Set();
  registrations.forEach((item) => {
    const list = Array.isArray(item.courses) ? item.courses : [];
    list.forEach((label) => labels.add(label));
  });

  const courses = await prisma.course.findMany();
  const mapped = Array.from(labels).map((label) => {
    const code = String(label).split(" - ")[0].trim();
    const match = courses.find((course) => course.code === code);
    return {
      code,
      label,
      unit: match ? match.units : null,
    };
  });

  return sendOk(res, "Registered courses loaded", mapped);
});

app.post("/api/results", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const studentNo = String(req.body.studentNo || "").trim();
  const academicYear = String(req.body.academicYear || "").trim();
  const semester = String(req.body.semester || "").trim();
  const course = String(req.body.course || "").trim().toUpperCase();
  const unit = Number(req.body.unit || 0);
  const ca = Number(req.body.ca || 0);
  const exam = Number(req.body.exam || 0);
  const total = Number(
    req.body.total !== undefined && req.body.total !== "" ? req.body.total : ca + exam
  );
  const grade = String(req.body.grade || scoreToGrade(total)).trim().toUpperCase();

  if (!studentNo || !academicYear || !semester || !course) {
    return sendError(res, 400, "Student report fields are incomplete" );
  }
  if (!unit || Number.isNaN(unit)) {
    return sendError(res, 400, "Course unit is required" );
  }
  if (Number.isNaN(ca) || Number.isNaN(exam) || Number.isNaN(total)) {
    return sendError(res, 400, "Scores must be valid numbers" );
  }

  const student = await prisma.student.findUnique({ where: { studentNo } });
  if (!student) return sendError(res, 404, "Student not found" );

  const duplicate = await prisma.result.findFirst({
    where: { studentId: student.id, academicYear, semester, course },
  });
  if (duplicate) {
    return sendError(res, 409, "Result already exists for this student/course/semester" );
  }

  const result = await prisma.result.create({
    data: {
      studentId: student.id,
      academicYear,
      semester,
      course,
      unit,
      ca,
      exam,
      total,
      grade,
    },
  });

  return sendOk(res, "Result saved", result);
});

app.post("/api/results/query", requireAuth, async (req, res) => {
  const page = Number(req.body.page || 1);
  const limit = Number(req.body.limit || 5);
  let studentNo = String(req.body.studentNo || "").trim();
  const academicYear = String(req.body.academicYear || "").trim();
  const semester = String(req.body.semester || "").trim();
  const minTotal = req.body.min_total !== undefined ? Number(req.body.min_total) : null;
  const maxTotal = req.body.max_total !== undefined ? Number(req.body.max_total) : null;
  const sort = req.body.sort || "course_code";
  const order = req.body.order === "desc" ? "desc" : "asc";

  if (req.user.role === "student") {
    const current = await getStudentByUser(req.user.id);
    studentNo = current ? current.studentNo : "";
  }

  let studentId = null;
  if (studentNo) {
    const student = await prisma.student.findUnique({ where: { studentNo } });
    studentId = student ? student.id : null;
  }

  let rows = await prisma.result.findMany({
    where: {
      ...(studentId ? { studentId } : {}),
      ...(academicYear ? { academicYear } : {}),
      ...(semester ? { semester } : {}),
      ...(minTotal !== null ? { total: { gte: minTotal } } : {}),
      ...(maxTotal !== null ? { total: { lte: maxTotal } } : {}),
    },
  });

  const fieldMap = {
    course_code: "course",
    course_unit: "unit",
    course_work: "ca",
    exam: "exam",
    total: "total",
  };
  const sortField = fieldMap[sort] || "course";

  rows.sort((a, b) => {
    const left = a[sortField];
    const right = b[sortField];
    if (typeof left === "number" && typeof right === "number") {
      return order === "asc" ? left - right : right - left;
    }
    return order === "asc"
      ? String(left).localeCompare(String(right))
      : String(right).localeCompare(String(left));
  });

  const pages = Math.max(1, Math.ceil(rows.length / limit));
  const safePage = Math.min(Math.max(page, 1), pages);
  const start = (safePage - 1) * limit;
  const pageRows = rows.slice(start, start + limit);

  const allStudentRows = studentId
    ? rows.filter((row) => row.studentId === studentId)
    : rows;

  return sendOk(res, "Results loaded", {
    results: pageRows,
    gpa: computeGpa(pageRows),
    cgpa: computeGpa(allStudentRows),
    meta: {
      page: safePage,
      pages,
      total: rows.length,
    },
  });
});

app.get("/api/students/me/dashboard", requireAuth, requireRole("student"), async (req, res) => {
  const student = await getStudentByUser(req.user.id);
  if (!student) return sendError(res, 404, "Student profile not found" );

  const [registrations, results, courses] = await Promise.all([
    prisma.registration.findMany({ where: { studentId: student.id }, orderBy: { createdAt: "desc" } }),
    prisma.result.findMany({ where: { studentId: student.id } }),
    prisma.course.findMany(),
  ]);

  const latestRegistration = registrations[0] || null;
  const latestResults = results.slice(-3).reverse();

  let registeredUnits = 0;
  let pendingResults = 0;
  if (latestRegistration) {
    const courseCodes = Array.isArray(latestRegistration.courses)
      ? latestRegistration.courses.map((course) => String(course).split(" - ")[0])
      : [];
    registeredUnits = courseCodes.reduce((total, code) => {
      const match = courses.find((course) => course.code === code);
      return total + (match ? match.units : 0);
    }, 0);

    const semesterResults = results.filter(
      (row) =>
        row.academicYear === latestRegistration.academicYear &&
        row.semester === latestRegistration.semester
    );
    pendingResults = Math.max(0, courseCodes.length - semesterResults.length);
  }

  return sendOk(res, "Student dashboard loaded", {
    student,
    profile: formatStudentProfile(student),
    registrations,
    results,
    latestResults,
    latestRegistration,
    registeredUnits,
    pendingResults,
    gpa: computeGpa(results),
    cgpa: computeGpa(results),
  });
});

app.post("/api/submissions", requireAuth, requireRole("student"), async (req, res) => {
  const student = await getStudentByUser(req.user.id);
  if (!student) return sendError(res, 404, "Student profile not found" );

  const fileName = String(req.body.fileName || "").trim();
  const fileType = String(req.body.fileType || "").trim();
  const fileSize = Number(req.body.fileSize || 0);
  const dataUrl = String(req.body.dataUrl || "").trim();
  const note = String(req.body.note || "").trim();

  if (!fileName || !fileType || !fileSize || !dataUrl) {
    return sendError(res, 400, "Submission fields are incomplete");
  }

  const submission = await prisma.submission.create({
    data: {
      studentId: student.id,
      fileName,
      fileType,
      fileSize,
      dataUrl,
      note,
      status: "Pending",
    },
  });

  return sendOk(res, "File submitted", submission);
});

app.get("/api/submissions", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const status = String(req.query.status || "").trim();
  const where = status ? { status: { equals: status, mode: "insensitive" } } : {};
  const submissions = await prisma.submission.findMany({
    where,
    orderBy: { submittedAt: "desc" },
    include: { student: true },
  });
  return sendOk(res, "Submissions loaded", submissions);
});

app.get("/api/submissions/me", requireAuth, requireRole("student"), async (req, res) => {
  const student = await getStudentByUser(req.user.id);
  if (!student) return sendError(res, 404, "Student profile not found" );

  const submissions = await prisma.submission.findMany({
    where: { studentId: student.id },
    orderBy: { submittedAt: "desc" },
  });

  return sendOk(res, "Submissions loaded", submissions);
});

app.put("/api/submissions/:id/review", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const status = String(req.body.status || "").trim();
  const reviewNote = String(req.body.reviewNote || "").trim();
  if (status !== "Accepted" && status !== "Rejected") {
    return sendError(res, 400, "Invalid review status" );
  }

  const submission = await prisma.submission.update({
    where: { id: req.params.id },
    data: {
      status,
      reviewer: req.user.username,
      reviewNote,
      reviewedAt: new Date(),
    },
  });

  return sendOk(res, "Submission reviewed", submission);
});

app.get("/api/tasks", requireAuth, requireRole("admin", "super_admin"), async (_req, res) => {
  const tasks = await prisma.task.findMany({ orderBy: { createdAt: "desc" } });
  return sendOk(res, "Tasks loaded", tasks);
});

app.post("/api/tasks", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const text = String(req.body.text || "").trim();
  if (!text) return sendError(res, 400, "Task text is required" );

  const task = await prisma.task.create({ data: { text } });
  return sendOk(res, "Task added", task);
});

app.put("/api/tasks/:id/toggle", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const task = await prisma.task.findUnique({ where: { id: req.params.id } });
  if (!task) return sendError(res, 404, "Task not found" );

  const updated = await prisma.task.update({
    where: { id: req.params.id },
    data: { completed: !task.completed },
  });
  return sendOk(res, "Task updated", updated);
});

app.delete("/api/tasks/:id", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  await prisma.task.delete({ where: { id: req.params.id } });
  return sendOk(res, "Task deleted", null);
});

app.post("/api/admin/export", requireAuth, requireRole("admin", "super_admin"), async (_req, res) => {
  const data = await prisma.$transaction([
    prisma.department.findMany(),
    prisma.user.findMany({
      select: {
        id: true,
        username: true,
        name: true,
        role: true,
        status: true,
        email: true,
        lastLogin: true,
        createdAt: true,
      },
    }),
    prisma.student.findMany({ include: { department: true } }),
    prisma.course.findMany({ include: { department: true } }),
    prisma.registration.findMany(),
    prisma.result.findMany({ include: { student: true } }),
    prisma.submission.findMany({ include: { student: true } }),
    prisma.task.findMany(),
  ]);

  const students = data[2].map((student) => ({
    id: student.id,
    studentNo: student.studentNo,
    name: student.name,
    department: student.department ? student.department.name : "",
    level: student.level,
    status: student.status,
    createdAt: student.createdAt,
    updatedAt: student.updatedAt,
  }));

  const courses = data[3].map((course) => ({
    id: course.id,
    code: course.code,
    title: course.title,
    units: course.units,
    semester: course.semester,
    department: course.department ? course.department.name : "",
  }));

  const results = data[5].map((result) => ({
    id: result.id,
    studentNo: result.student ? result.student.studentNo : "",
    academicYear: result.academicYear,
    semester: result.semester,
    course: result.course,
    unit: result.unit,
    ca: result.ca,
    exam: result.exam,
    total: result.total,
    grade: result.grade,
    createdAt: result.createdAt,
  }));

  const submissions = data[6].map((submission) => ({
    id: submission.id,
    studentNo: submission.student ? submission.student.studentNo : "",
    fileName: submission.fileName,
    fileType: submission.fileType,
    fileSize: submission.fileSize,
    dataUrl: submission.dataUrl,
    note: submission.note,
    status: submission.status,
    submittedAt: submission.submittedAt,
    reviewedAt: submission.reviewedAt,
    reviewer: submission.reviewer,
    reviewNote: submission.reviewNote,
  }));

  return sendOk(res, "Export ready", {
    departments: data[0],
    users: data[1],
    students,
    courses,
    registrations: data[4],
    results,
    submissions,
    tasks: data[7],
  });
});

app.post("/api/admin/reset", requireAuth, requireRole("admin", "super_admin"), async (_req, res) => {
  await prisma.$transaction([
    prisma.result.deleteMany(),
    prisma.registration.deleteMany(),
    prisma.submission.deleteMany(),
    prisma.task.deleteMany(),
    prisma.course.deleteMany(),
    prisma.student.deleteMany(),
    prisma.user.deleteMany({ where: { role: "student" } }),
    prisma.department.deleteMany(),
  ]);

  return sendOk(res, "Data reset complete", null);
});

app.post("/api/admin/import", requireAuth, requireRole("admin", "super_admin"), async (req, res) => {
  const payload = req.body || {};

  const departments = Array.isArray(payload.departments) ? payload.departments : [];
  const courses = Array.isArray(payload.courses) ? payload.courses : [];
  const students = Array.isArray(payload.students) ? payload.students : [];
  const registrations = Array.isArray(payload.registrations) ? payload.registrations : [];
  const results = Array.isArray(payload.results) ? payload.results : [];
  const submissions = Array.isArray(payload.submissions) ? payload.submissions : [];
  const tasks = Array.isArray(payload.tasks) ? payload.tasks : [];

  for (const dept of departments) {
    const name = String(dept.name || "").trim();
    if (!name) continue;
    await prisma.department.upsert({
      where: { name },
      update: {},
      create: { name },
    });
  }

  for (const course of courses) {
    if (!course.code || !course.title || !course.units) continue;
    const departmentName = toDepartmentName(course.department || course.departmentName);
    if (!departmentName) continue;

    const dept = await prisma.department.findUnique({ where: { name: departmentName } });
    if (!dept) continue;

    await prisma.course.upsert({
      where: { code: course.code },
      update: {
        title: course.title,
        units: Number(course.units || 0),
        semester: course.semester || "First Semester",
        departmentId: dept.id,
      },
      create: {
        code: course.code,
        title: course.title,
        units: Number(course.units || 0),
        semester: course.semester || "First Semester",
        departmentId: dept.id,
      },
    });
  }

  for (const student of students) {
    const studentNo = String(student.studentNo || "").trim();
    const name = String(student.name || "").trim();
    const departmentName = toDepartmentName(student.department || student.departmentName);
    const level = String(student.level || "").trim();
    const status = String(student.status || "Active").trim();
    if (!studentNo || !name || !departmentName || !level) continue;

    const dept = await prisma.department.findUnique({ where: { name: departmentName } });
    if (!dept) continue;

    const existing = await prisma.student.findUnique({ where: { studentNo } });
    if (existing) continue;

    const user = await prisma.user.create({
      data: {
        username: studentNo,
        name,
        role: "student",
        status,
        passwordHash: await hashPassword(studentNo),
      },
    });

    await prisma.student.create({
      data: {
        studentNo,
        name,
        departmentId: dept.id,
        level,
        status,
        userId: user.id,
      },
    });
  }

  for (const item of registrations) {
    const studentNo = String(item.studentNo || "").trim();
    const semester = String(item.semester || "").trim();
    const academicYear = String(item.academicYear || "").trim();
    const courses = Array.isArray(item.courses) ? item.courses : [];
    if (!studentNo || !semester || !academicYear) continue;

    const student = await prisma.student.findUnique({ where: { studentNo } });
    if (!student) continue;

    const regNo = String(item.regNo || "").trim() || await generateRegistrationNo(prisma, { studentNo, academicYear, semester });
    const existing = await prisma.registration.findFirst({
      where: { studentId: student.id, regNo, academicYear, semester },
    });
    if (existing) continue;

    await prisma.registration.create({
      data: {
        studentId: student.id,
        studentNo,
        regNo,
        semester,
        academicYear,
        courses,
      },
    });
  }

  for (const item of results) {
    const studentNo = String(item.studentNo || "").trim();
    const academicYear = String(item.academicYear || "").trim();
    const semester = String(item.semester || "").trim();
    const course = String(item.course || "").trim().toUpperCase();
    const unit = Number(item.unit || 0);
    const ca = Number(item.ca || 0);
    const exam = Number(item.exam || 0);
    const total = Number(item.total !== undefined && item.total !== "" ? item.total : ca + exam);
    if (!studentNo || !academicYear || !semester || !course || !unit) continue;

    const student = await prisma.student.findUnique({ where: { studentNo } });
    if (!student) continue;

    await prisma.result.upsert({
      where: {
        studentId_academicYear_semester_course: {
          studentId: student.id,
          academicYear,
          semester,
          course,
        },
      },
      update: {
        unit,
        ca,
        exam,
        total,
        grade: item.grade || scoreToGrade(total),
      },
      create: {
        studentId: student.id,
        academicYear,
        semester,
        course,
        unit,
        ca,
        exam,
        total,
        grade: item.grade || scoreToGrade(total),
      },
    });
  }

  for (const item of submissions) {
    const studentNo = String(item.studentNo || "").trim();
    const fileName = String(item.fileName || "").trim();
    const fileType = String(item.fileType || "").trim();
    const fileSize = Number(item.fileSize || 0);
    const dataUrl = String(item.dataUrl || "").trim();
    if (!studentNo || !fileName || !fileType || !fileSize || !dataUrl) continue;

    const student = await prisma.student.findUnique({ where: { studentNo } });
    if (!student) continue;

    const existing = item.id
      ? await prisma.submission.findUnique({ where: { id: item.id } })
      : null;
    if (existing) continue;

    await prisma.submission.create({
      data: {
        ...(item.id ? { id: item.id } : {}),
        studentId: student.id,
        fileName,
        fileType,
        fileSize,
        dataUrl,
        note: String(item.note || ""),
        status: String(item.status || "Pending"),
        reviewedAt: item.reviewedAt ? new Date(item.reviewedAt) : null,
        reviewer: item.reviewer || null,
        reviewNote: item.reviewNote || null,
      },
    });
  }

  for (const item of tasks) {
    const text = String(item.text || "").trim();
    if (!text) continue;

    await prisma.task.upsert({
      where: { id: item.id || "__missing_task_id__" },
      update: {
        text,
        completed: Boolean(item.completed),
      },
      create: {
        ...(item.id ? { id: item.id } : {}),
        text,
        completed: Boolean(item.completed),
      },
    });
  }

  return sendOk(res, "Import completed", null);
});

app.listen(PORT, async () => {
  try {
    await prisma.$connect();
    await ensureSuperAdmin();
    console.log(`SMS backend running on port ${PORT}`);
  } catch (error) {
    console.error("Startup error:", error);
  }
});
