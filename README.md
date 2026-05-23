<div align="center">

# MSU Learning Management System

**A SQL-to-NoSQL redesign of a university LMS, built on Vue 3 and Firebase Firestore.**

[![Vue 3](https://img.shields.io/badge/Vue-3.x-4FC08D?style=for-the-badge&logo=vue.js&logoColor=white)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-5.x-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.x-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Firebase](https://img.shields.io/badge/Firebase-Firestore-FFCA28?style=for-the-badge&logo=firebase&logoColor=black)](https://firebase.google.com/)
[![Status](https://img.shields.io/badge/Status-Prototype-orange?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

</div>

---

## Overview

MSU LMS is a web-based Learning Management System prototype developed as part of a database redesign study — migrating from a traditional relational (SQL) database model to a NoSQL architecture using Firebase Firestore. The system demonstrates full CRUD operations, role-based authentication, and a document-oriented data structure designed for academic environments.

This project was built to evaluate how NoSQL databases handle the real-world data requirements of a university LMS: managing users, courses, enrollments, learning modules, activities, and student submissions — all under a multi-role access model.

> **Note:** This is an academic prototype, not a production-ready system. It is intended for capstone demonstration, database architecture comparison, and portfolio purposes.

---

## Features

- **Role-Based Authentication** — Separate dashboards and permissions for Admin, Instructor, and Student roles
- **Admin-Controlled Accounts** — No public registration; all accounts are provisioned by an administrator
- **Course & Subject Management** — Full CRUD for programs, courses, and subject offerings
- **Module & Activity Delivery** — Instructors can create and publish learning modules and activities
- **Submission Tracking** — Students can submit work; instructors can review and manage submissions
- **Firestore NoSQL Backend** — Document-oriented data model replacing a traditional relational schema
- **Responsive UI** — Built with Tailwind CSS for a clean, mobile-friendly interface

---

## System Roles

| Role | Description |
|------|-------------|
| **Admin** | Manages user accounts, programs, and course offerings. Full system access. |
| **Instructor** | Creates and manages subjects, modules, activities, and student submissions within assigned courses. |
| **Student** | Accesses enrolled subjects, views modules and activities, and submits coursework. |

### Role Permissions Matrix

| Action | Admin | Instructor | Student |
|--------|:-----:|:----------:|:-------:|
| Manage Users | ✅ | ❌ | ❌ |
| Manage Programs & Courses | ✅ | ❌ | ❌ |
| Create/Edit Subjects | ✅ | ✅ | ❌ |
| Publish Modules & Activities | ❌ | ✅ | ❌ |
| View Enrolled Subjects | ❌ | ✅ | ✅ |
| Submit Activities | ❌ | ❌ | ✅ |
| View Submissions | ❌ | ✅ | ✅ (own) |

---

## CRUD Implementation

Every major collection in Firestore supports the four standard operations across the system:

| Operation | Description | Example |
|-----------|-------------|---------|
| **Create** | Adding new records to Firestore collections | Creating a user account, posting a new module |
| **Read** | Fetching documents with real-time or one-time queries | Loading a student's enrolled subjects |
| **Update** | Modifying existing document fields | Editing course details, grading a submission |
| **Delete** | Removing documents from collections | Removing a user, deleting an outdated activity |

CRUD operations are handled through Firebase's SDK (`setDoc`, `getDoc`, `getDocs`, `updateDoc`, `deleteDoc`) and are organized into composable service modules per collection. Security Rules on Firestore enforce access control at the database level, independent of the frontend logic.

---

## SQL to NoSQL Transition

This project began as a conceptual SQL schema with normalized tables (users, enrollments, courses, etc.) and relational foreign keys. The redesign involved restructuring that schema into a Firestore document model.

### Key Differences

| Aspect | SQL (Original) | NoSQL / Firestore (Redesign) |
|--------|---------------|------------------------------|
| Data Structure | Normalized tables with joins | Documents inside collections |
| Relationships | Foreign keys | Document references (`/users/{uid}`) |
| Schema Enforcement | Strict, predefined | Flexible, schema-less |
| Querying | SQL JOIN queries | Firestore queries with `where()` filters |
| Scalability | Vertical scaling | Horizontal, cloud-native |
| Real-time Support | Requires polling | Built-in `onSnapshot` listeners |

### Design Decisions

- **Enrollment** is stored as its own collection rather than a junction table, making it easier to query a student's subjects directly without joins.
- **Submissions** are scoped under activities by reference, keeping student work cleanly associated with its context.
- Some **denormalization** was applied intentionally — for example, storing a subject's name inside enrollment documents to avoid extra reads.

---

## Why Firebase Firestore

Firebase Firestore was selected over alternatives like MongoDB Atlas for the following reasons:

- **Zero backend overhead** — No separate server or database host to configure; Firestore runs fully managed in the cloud
- **Native Vue integration** — Firebase's JavaScript SDK integrates cleanly with Vue 3's Composition API and reactive patterns
- **Real-time capabilities** — `onSnapshot` allows live data updates without polling or WebSockets setup
- **Authentication + Database in one** — Firebase Auth and Firestore share the same project, keeping the auth UID consistent across the system
- **Security Rules** — Declarative, server-side access control that works independently of the frontend
- **Generous free tier** — The Spark plan is sufficient for academic prototypes and classroom-scale usage
- **Practical for CRUD demonstration** — Firestore's document model makes create, read, update, and delete operations straightforward to implement and explain

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend Framework | [Vue 3](https://vuejs.org/) | Reactive UI with Composition API |
| Build Tool | [Vite](https://vitejs.dev/) | Fast dev server and build pipeline |
| Styling | [Tailwind CSS](https://tailwindcss.com/) | Utility-first CSS framework |
| Authentication | [Firebase Auth](https://firebase.google.com/docs/auth) | Email/password login with role-based access |
| Database | [Firebase Firestore](https://firebase.google.com/docs/firestore) | NoSQL document database |
| Routing | [Vue Router](https://router.vuejs.org/) | Client-side navigation and route guards |
| State Management | [Pinia](https://pinia.vuejs.org/) | Lightweight global state for auth and user data |

---

## Database Structure

All data is stored in Firebase Firestore as collections of documents. Below is the top-level collection structure.

```
firestore/
├── users/
├── programs/
├── courses/
├── subjects/
├── enrollments/
├── modules/
├── activities/
└── submissions/
```

### Collection Schemas

#### `users/{uid}`
```json
{
  "uid": "abc123",
  "name": "Juan dela Cruz",
  "email": "juan@msu.edu.ph",
  "role": "student",
  "programId": "bsit",
  "createdAt": "2024-01-15T08:00:00Z"
}
```

#### `programs/{programId}`
```json
{
  "programId": "bsit",
  "name": "Bachelor of Science in Information Technology",
  "code": "BSIT",
  "department": "College of Information and Computing Sciences",
  "createdAt": "2024-01-01T00:00:00Z"
}
```

#### `courses/{courseId}`
```json
{
  "courseId": "ite191",
  "code": "ITE191",
  "title": "Capstone Project 1",
  "programId": "bsit",
  "units": 3
}
```

#### `subjects/{subjectId}`
```json
{
  "subjectId": "subj_001",
  "courseId": "ite191",
  "title": "Capstone Project 1 - Section A",
  "instructorId": "uid_instructor",
  "semester": "1st",
  "schoolYear": "2024-2025",
  "schedule": "MWF 10:00-11:00 AM"
}
```

#### `enrollments/{enrollmentId}`
```json
{
  "enrollmentId": "enr_001",
  "studentId": "uid_student",
  "subjectId": "subj_001",
  "subjectTitle": "Capstone Project 1 - Section A",
  "status": "active",
  "enrolledAt": "2024-06-01T00:00:00Z"
}
```

#### `modules/{moduleId}`
```json
{
  "moduleId": "mod_001",
  "subjectId": "subj_001",
  "title": "Module 1: Introduction to Capstone",
  "content": "...",
  "order": 1,
  "publishedAt": "2024-06-05T00:00:00Z"
}
```

#### `activities/{activityId}`
```json
{
  "activityId": "act_001",
  "subjectId": "subj_001",
  "moduleId": "mod_001",
  "title": "Activity 1: Project Proposal",
  "instructions": "Submit a 2-page project proposal.",
  "dueDate": "2024-06-15T23:59:00Z",
  "maxScore": 100
}
```

#### `submissions/{submissionId}`
```json
{
  "submissionId": "sub_001",
  "activityId": "act_001",
  "studentId": "uid_student",
  "fileUrl": "https://storage.googleapis.com/...",
  "submittedAt": "2024-06-14T20:30:00Z",
  "score": null,
  "feedback": null
}
```

---

## Authentication Flow

```
User visits app
      │
      ▼
Firebase Auth checks session token
      │
      ├── No session → Redirect to /login
      │
      └── Session valid
              │
              ▼
        Fetch user document from Firestore (users/{uid})
              │
              ▼
        Read role field (admin / instructor / student)
              │
              ▼
        Route guard checks role → Redirect to role dashboard
              │
        ┌─────┼─────┐
        ▼     ▼     ▼
     Admin  Instructor  Student
    Dashboard Dashboard Dashboard
```

- Authentication is handled entirely through **Firebase Authentication** using email and password.
- Upon login, the app fetches the user's Firestore document to retrieve their **role**.
- **Vue Router guards** protect all routes — unauthorized access redirects to `/unauthorized`.
- There is no public registration endpoint. All accounts are created by the Admin through the system.

---

## Screenshots

> *Screenshots will be added upon UI finalization.*

| View | Preview |
|------|---------|
| Login Page | `[screenshot]` |
| Admin Dashboard | `[screenshot]` |
| Instructor — Subject View | `[screenshot]` |
| Student — Enrolled Subjects | `[screenshot]` |
| Module Viewer | `[screenshot]` |
| Activity Submission | `[screenshot]` |

---

## Installation Guide

### Prerequisites

Make sure the following are installed on your machine:

- [Node.js](https://nodejs.org/) v18 or higher
- [npm](https://www.npmjs.com/) v9 or higher
- A [Firebase](https://firebase.google.com/) project with Firestore and Authentication enabled

### Clone the Repository

```bash
git clone https://github.com/your-username/msu-lms.git
cd msu-lms
```

### Install Dependencies

```bash
npm install
```

---

## Environment Setup

Create a `.env` file in the project root. Copy the template below and fill in your Firebase project credentials.

```env
# .env

VITE_FIREBASE_API_KEY=your_api_key_here
VITE_FIREBASE_AUTH_DOMAIN=your_project_id.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_project_id.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
VITE_FIREBASE_APP_ID=your_app_id
```

> `.env` is listed in `.gitignore` and must **never** be committed to version control.

---

## Firebase Configuration Guide

1. Go to the [Firebase Console](https://console.firebase.google.com/) and create a new project.
2. Under **Build > Authentication**, enable the **Email/Password** sign-in method.
3. Under **Build > Firestore Database**, create a database in **production mode** (you will set rules manually).
4. Under **Project Settings > General**, scroll to "Your apps" and register a **Web app**. Copy the config values into your `.env` file.
5. Set Firestore Security Rules to restrict access by role:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // Users can only read their own document
    match /users/{uid} {
      allow read: if request.auth.uid == uid;
      allow write: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }

    // Authenticated users can read subjects
    match /subjects/{subjectId} {
      allow read: if request.auth != null;
      allow write: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role in ['admin', 'instructor'];
    }

    // Students can only write their own submissions
    match /submissions/{submissionId} {
      allow read: if request.auth != null;
      allow create: if request.auth.uid == request.resource.data.studentId;
      allow update, delete: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role in ['admin', 'instructor'];
    }
  }
}
```

---

## Running the Project

Start the development server:

```bash
npm run dev
```

Build for production:

```bash
npm run build
```

Preview the production build locally:

```bash
npm run preview
```

The dev server runs at `http://localhost:5173` by default.

---

## Folder Structure

```
msu-lms/
├── public/
│   └── favicon.ico
├── src/
│   ├── assets/               # Static assets (images, icons)
│   ├── components/           # Reusable Vue components
│   │   ├── common/           # Shared UI elements (Navbar, Sidebar, Modal)
│   │   ├── admin/            # Admin-specific components
│   │   ├── instructor/       # Instructor-specific components
│   │   └── student/          # Student-specific components
│   ├── composables/          # Vue composables (useAuth, useFirestore)
│   ├── firebase/
│   │   └── config.js         # Firebase app initialization
│   ├── router/
│   │   └── index.js          # Route definitions and guards
│   ├── services/             # Firestore CRUD service functions
│   │   ├── userService.js
│   │   ├── courseService.js
│   │   ├── subjectService.js
│   │   ├── enrollmentService.js
│   │   ├── moduleService.js
│   │   ├── activityService.js
│   │   └── submissionService.js
│   ├── stores/               # Pinia stores
│   │   ├── authStore.js
│   │   └── userStore.js
│   ├── views/                # Page-level Vue components
│   │   ├── auth/
│   │   │   └── LoginView.vue
│   │   ├── admin/
│   │   ├── instructor/
│   │   └── student/
│   ├── App.vue
│   └── main.js
├── .env                      # Environment variables (not committed)
├── .gitignore
├── index.html
├── package.json
├── tailwind.config.js
└── vite.config.js
```

---

## Future Improvements

The following features are outside the current scope but are planned for a future version:

- **File Upload Support** — Integration with Firebase Storage for activity submissions
- **Grade Book** — Instructor-facing grade management and computation
- **Announcements** — Subject-level announcement posting with read receipts
- **Notifications** — Real-time alerts for new modules, activities, and grades
- **Attendance Tracking** — Session-based attendance records per subject
- **Email Invitations** — Admin sends account invites via Firebase email
- **Analytics Dashboard** — Submission rates, activity completion, and enrollment stats
- **Dark Mode** — User preference toggle for light/dark themes

---

## Security Notes

- All Firestore operations are protected by **server-side Security Rules** — the frontend alone cannot bypass access control.
- Firebase Auth tokens are managed automatically; the app does not store passwords or tokens in `localStorage`.
- The `.env` file holds sensitive credentials and is excluded from version control via `.gitignore`.
- No public registration is available. Account creation is restricted to admin users only, reducing unauthorized access risks.
- This system has **not undergone a security audit** and is not suitable for production deployment without proper hardening.

---

## Developers

<div align="center">

| Name | Role | GitHub |
|------|------|--------|
| [Developer Name] | Lead Developer / Backend | [@username](https://github.com) |
| [Developer Name] | Frontend Developer | [@username](https://github.com) |
| [Developer Name] | UI/UX & Documentation | [@username](https://github.com) |

**Course:** ITD110 — NoSQL Databases  
**Institution:** College of Information and Computing Sciences  
**University:** Mindanao State University — Main Campus  
**Academic Year:** 2024–2025

</div>

---

## License

This project is licensed under the [MIT License](LICENSE). It is intended for academic and educational use. Commercial use without permission is not allowed.

---

## Conclusion

MSU LMS demonstrates that NoSQL databases are a practical fit for academic systems that prioritize flexibility, real-time data, and rapid prototyping over strict relational constraints. By migrating from a SQL schema to Firestore's document model, the system trades join-heavy queries for a structure that maps more naturally to how LMS data is actually used — by role, by subject, by student.

This project does not claim to replace existing LMS platforms. It is a working proof-of-concept that explores database redesign in an academic context, and a portfolio piece showing full-stack development with modern web technologies.

---

<div align="center">

*Built with Vue 3 + Firebase — Mindanao State University, 2024–2025*

</div>
