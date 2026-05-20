// src/router/index.js
import { createRouter, createWebHistory } from 'vue-router'

// Layouts
import Layout from '@/layouts/Layout.vue'
import AuthLayout from '@/layouts/AuthLayout.vue'

// Auth Pages
import Login from '@/Pages/auth/Login.vue'

// Admin Pages
import AdminDashboard from '@/Pages/admin/AdminDashboard.vue'
import ManageStudents from '@/Pages/admin/ManageStudents.vue'
import ManageInstructors from '@/Pages/admin/ManageInstructors.vue'
import ManagePrograms from '@/Pages/admin/ManagePrograms.vue'
import ManageSubjects from '@/Pages/admin/ManageSubjects.vue'
import EnrollmentManager from '@/Pages/admin/EnrollmentManager.vue'

// Instructor Pages
import InstructorDashboard from '@/Pages/instructor/InstructorDashboard.vue'
import InstructorSubjects from '@/Pages/instructor/InstructorSubjects.vue'
import UploadModule from '@/Pages/instructor/UploadModule.vue'
import CreateActivity from '@/Pages/instructor/CreateActivity.vue'
import Submissions from '@/Pages/instructor/Submissions.vue'
import GradeSubmission from '@/Pages/instructor/GradeSubmission.vue'

// Student Pages
import StudentDashboard from '@/Pages/student/StudentDashboard.vue'
import StudentSubjects from '@/Pages/student/StudentSubjects.vue'
import SubjectDetails from '@/Pages/student/SubjectDetails.vue'
import MyActivities from '@/Pages/student/MyActivities.vue'
import MyGrades from '@/Pages/student/MyGrades.vue'

const routes = [
  {
    path: '/',
    component: AuthLayout,
    children: [
      {
        path: '',
        redirect: '/login',
      },
      {
        path: 'login',
        name: 'Login',
        component: Login,
      },
    ],
  },

  // STUDENT ROUTES
  {
    path: '/student',
    component: Layout,
    meta: {
      requiresAuth: true,
      role: 'student',
    },
    children: [
      {
        path: '',
        redirect: '/student/dashboard',
      },
      {
        path: 'dashboard',
        name: 'StudentDashboard',
        component: StudentDashboard,
      },
      {
        path: 'subjects',
        name: 'StudentSubjects',
        component: StudentSubjects,
      },
      {
        path: 'subjects/:id',
        name: 'SubjectDetails',
        component: SubjectDetails,
      },
      {
        path: 'activities',
        name: 'MyActivities',
        component: MyActivities,
      },
      {
        path: 'grades',
        name: 'MyGrades',
        component: MyGrades,
      },
    ],
  },

  // INSTRUCTOR ROUTES
  {
    path: '/instructor',
    component: Layout,
    meta: {
      requiresAuth: true,
      role: 'instructor',
    },
    children: [
      {
        path: '',
        redirect: '/instructor/dashboard',
      },
      {
        path: 'dashboard',
        name: 'InstructorDashboard',
        component: InstructorDashboard,
      },
      {
        path: 'subjects',
        name: 'InstructorSubjects',
        component: InstructorSubjects,
      },
      {
        path: 'upload-module',
        name: 'UploadModule',
        component: UploadModule,
      },
      {
        path: 'create-activity',
        name: 'CreateActivity',
        component: CreateActivity,
      },
      {
        path: 'submissions',
        name: 'Submissions',
        component: Submissions,
      },
      {
        path: 'grade-submission',
        name: 'GradeSubmission',
        component: GradeSubmission,
      },
    ],
  },

  // ADMIN ROUTES
  {
    path: '/admin',
    component: Layout,
    meta: {
      requiresAuth: true,
      role: 'admin',
    },
    children: [
      {
        path: '',
        redirect: '/admin/dashboard',
      },
      {
        path: 'dashboard',
        name: 'AdminDashboard',
        component: AdminDashboard,
      },
      {
        path: 'students',
        name: 'ManageStudents',
        component: ManageStudents,
      },
      {
        path: 'instructors',
        name: 'ManageInstructors',
        component: ManageInstructors,
      },
      {
        path: 'programs',
        name: 'ManagePrograms',
        component: ManagePrograms,
      },
      {
        path: 'subjects',
        name: 'ManageSubjects',
        component: ManageSubjects,
      },
      {
        path: 'enrollment',
        name: 'EnrollmentManager',
        component: EnrollmentManager,
      },
    ],
  },

  {
    path: '/:pathMatch(.*)*',
    redirect: '/login',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

function getLoggedInUser() {
  try {
    const user = localStorage.getItem('user')
    if (!user) return null
    return JSON.parse(user)
  } catch (error) {
    localStorage.removeItem('user')
    return null
  }
}

function normalizeRole(role) {
  return String(role || '').toLowerCase().trim()
}

function getDashboardByRole(role) {
  const userRole = normalizeRole(role)

  if (userRole === 'admin') return '/admin/dashboard'
  if (userRole === 'instructor') return '/instructor/dashboard'
  if (userRole === 'student') return '/student/dashboard'

  return '/login'
}

router.beforeEach((to, from, next) => {
  const loggedInUser = getLoggedInUser()
  const isAuthRequired = to.matched.some((record) => record.meta.requiresAuth)
  const targetRole = to.matched.find((record) => record.meta.role)?.meta.role

  if (isAuthRequired && !loggedInUser) {
    return next('/login')
  }

  if (to.path === '/login' && loggedInUser) {
    return next(getDashboardByRole(loggedInUser.role))
  }

  if (isAuthRequired && targetRole) {
    const userRole = normalizeRole(loggedInUser?.role)
    const requiredRole = normalizeRole(targetRole)

    if (userRole !== requiredRole) {
      alert('Access Denied: Hindi ka awtorisadong pumasok sa panel na ito.')
      return next(getDashboardByRole(userRole))
    }
  }

  next()
})

export default router