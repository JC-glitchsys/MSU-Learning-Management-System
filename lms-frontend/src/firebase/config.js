import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyCg4mjYS-nYZuItlqo4bxvAi4r9oR7QNsE",
  authDomain: "msu-lms-64321.firebaseapp.com",
  projectId: "msu-lms-64321",
  storageBucket: "msu-lms-64321.firebasestorage.app",
  messagingSenderId: "956226510570",
  appId: "1:956226510570:web:a340273c08ad19d684c193",
  measurementId: "G-DQVT8BFB4T",
};

const app = initializeApp(firebaseConfig);

export const db = getFirestore(app);
