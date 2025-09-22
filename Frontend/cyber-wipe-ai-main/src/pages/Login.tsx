import React, { useState } from "react";
import { signInWithEmailAndPassword } from "firebase/auth";
import { auth } from "../firebaseConfig";
import { getFirestore, doc, getDoc } from "firebase/firestore";
import { Link, useNavigate } from "react-router-dom";

const db = getFirestore();

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      // ✅ Sign in with Firebase Auth
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      const user = userCredential.user;

      // ✅ Fetch user details from Firestore
      const docRef = doc(db, "users", user.uid);
      const docSnap = await getDoc(docRef);

      if (docSnap.exists()) {
        console.log("User data:", docSnap.data());
      } else {
        console.warn("⚠️ No extra user data found in Firestore.");
      }

      navigate("/dashboard"); // redirect after login
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-black">
      <form onSubmit={handleLogin} className="glass-card p-8 w-full max-w-md">
        <h2 className="text-2xl font-bold text-center mb-6 text-primary">Login</h2>
        {error && <p className="text-red-500 text-center mb-4">{error}</p>}

        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full p-3 mb-4 rounded bg-gray-900 text-white"
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full p-3 mb-4 rounded bg-gray-900 text-white"
        />

        <button type="submit" className="w-full bg-blue-600 py-3 rounded text-white font-bold">
          Login
        </button>

        <p className="text-center text-sm mt-4 text-gray-400">
          Don’t have an account? <Link to="/register" className="text-primary">Register</Link>
        </p>
      </form>
    </div>
  );
}
