// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getAnalytics } from "firebase/analytics";
import { getFirestore } from "firebase/firestore";  // <-- ADD THIS

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBqINgmDXGxLM98wfjUz2wxM-lurN_BewA",
  authDomain: "sih2025-5963e.firebaseapp.com",
  projectId: "sih2025-5963e",
  storageBucket: "sih2025-5963e.firebasestorage.app",
  messagingSenderId: "264755982565",
  appId: "1:264755982565:web:0f51e70226220bd85c640c",
  measurementId: "G-NETEEN6R98"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Export Firebase services
export const auth = getAuth(app);
export const db = getFirestore(app);   // ✅ Firestore instance
export const analytics = getAnalytics(app);

export default app;
