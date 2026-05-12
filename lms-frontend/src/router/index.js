import { createRouter, createWebHistory } from 'vue-router'

import AuthLayout from '../layouts/AuthLayout.vue'
import Layout from '../layouts/Layout.vue'

import Login from '../pages/auth/Login.vue'
import Register from '../pages/auth/Register.vue'

import StudentDashboard from '../pages/student/StudentDashboard.vue'
import MySubjects from '../pages/student/MySubjects.vue'
import Activities from '../pages/student/Activities.vue'
import SubmitActivity from '../pages/student/SubmitActivity.vue'
import MyGrades from '../pages/student/MyGrades.vue'

import InstructorDashboard from '../pages/instructor/InstructorDashboard.vue'
import InstructorSubjects from '../pages/instructor/InstructorSubjects.vue'
import UploadModule from '../pages/instructor/UploadModule.vue'
import CreateActivity from '../pages/instructor/CreateActivity.vue'
import Submissions from '../pages/instructor/Submissions.vue'
import GradeSubmission from '../pages/instructor/GradeSubmission.vue'

import AdminDashboard from '../pages/admin/AdminDashboard.vue'
import ManageStudents from '../pages/admin/ManageStudents.vue'
import ManageInstructors from '../pages/admin/ManageInstructors.vue'
import ManageCourses from '../pages/admin/ManageCourses.vue'
import ManageSubjects from '../pages/admin/ManageSubjects.vue'

const getDashboardByRole = (role) => {
  if (role === 'admin') return '/admin/dashboard'
  if (role === 'instructor') return '/instructor/dashboard'
  return '/student/dashboard'
}

const routes = [
  {
    path: '/',
    redirect: () => {
      const user = JSON.parse(localStorage.getItem('user') || '{}')

      if (!user.id) return '/login'

      return getDashboardByRole(user.role)
    },
  },

  {
    path: '/',
    component: AuthLayout,
    children: [
      {
        path: 'login',
        name: 'Login',
        component: Login,
      },
      {
        path: 'register',
        name: 'Register',
        component: Register,
      },
    ],
  },

  {
    path: '/',
    component: Layout,
    meta: { requiresAuth: true },
    children: [
      // Student
      {
        path: 'student/dashboard',
        name: 'StudentDashboard',
        component: StudentDashboard,
        meta: { role: 'student' },
      },
      {
        path: 'student/subjects',
        name: 'MySubjects',
        component: MySubjects,
        meta: { role: 'student' },
      },
      {
        path: 'student/modules',
        name: 'StudentModules',
        component: MySubjects,
        meta: { role: 'student' },
      },
      {
        path: 'student/activities',
        name: 'StudentActivities',
        component: Activities,
        meta: { role: 'student' },
      },
      {
        path: 'student/submit/:id',
        name: 'SubmitActivity',
        component: SubmitActivity,
        meta: { role: 'student' },
      },
      {
        path: 'student/grades',
        name: 'MyGrades',
        component: MyGrades,
        meta: { role: 'student' },
      },

      // Instructor
      {
        path: 'instructor/dashboard',
        name: 'InstructorDashboard',
        component: InstructorDashboard,
        meta: { role: 'instructor' },
      },
      {
        path: 'instructor/subjects',
        name: 'InstructorSubjects',
        component: InstructorSubjects,
        meta: { role: 'instructor' },
      },
      {
        path: 'instructor/upload-module',
        name: 'UploadModule',
        component: UploadModule,
        meta: { role: 'instructor' },
      },
      {
        path: 'instructor/create-activity',
        name: 'CreateActivity',
        component: CreateActivity,
        meta: { role: 'instructor' },
      },
      {
        path: 'instructor/submissions',
        name: 'Submissions',
        component: Submissions,
        meta: { role: 'instructor' },
      },
      {
        path: 'instructor/grade-submission',
        name: 'GradeSubmission',
        component: GradeSubmission,
        meta: { role: 'instructor' },
      },

      // Admin
      {
        path: 'admin/dashboard',
        name: 'AdminDashboard',
        component: AdminDashboard,
        meta: { role: 'admin' },
      },
      {
        path: 'admin/students',
        name: 'ManageStudents',
        component: ManageStudents,
        meta: { role: 'admin' },
      },
      {
        path: 'admin/instructors',
        name: 'ManageInstructors',
        component: ManageInstructors,
        meta: { role: 'admin' },
      },
      {
        path: 'admin/courses',
        name: 'ManageCourses',
        component: ManageCourses,
        meta: { role: 'admin' },
      },
      {
        path: 'admin/subjects',
        name: 'ManageSubjects',
        component: ManageSubjects,
        meta: { role: 'admin' },
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

router.beforeEach((to, from, next) => {
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const isLoggedIn = !!user.id

  if (to.meta.requiresAuth && !isLoggedIn) {
    return next('/login')
  }

  if (to.path === '/login' && isLoggedIn) {
    return next(getDashboardByRole(user.role))
  }

  if (to.meta.role && user.role !== to.meta.role) {
    return next(getDashboardByRole(user.role))
  }

  next()
})

export default router