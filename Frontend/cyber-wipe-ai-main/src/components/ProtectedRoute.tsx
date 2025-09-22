// src/components/ProtectedRoute.tsx
import { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { auth } from "@/firebaseConfig";

interface Props {
  children: ReactNode;
}

const ProtectedRoute = ({ children }: Props) => {
  const user = auth.currentUser;

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

export default ProtectedRoute;
