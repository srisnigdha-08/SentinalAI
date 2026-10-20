import { lazy, Suspense, useEffect } from "react";
import { Routes, Route, Navigate, Outlet, useLocation } from "react-router-dom";
import toast, { Toaster } from "react-hot-toast";

import { AuthProvider } from "./context/AuthContext.jsx";
import { SocketProvider } from "./context/SocketContext.jsx";
import { useAuth } from "./hooks/useAuth.js";
import ErrorBoundary from "./components/ErrorBoundary.jsx";

import "./styles/globals.css";

// Lazy-loaded pages
const Landing = lazy(() => import("./pages/Landing.jsx"));
const About = lazy(() => import("./pages/About.jsx"));
const Features = lazy(() => import("./pages/Features.jsx"));
const Login = lazy(() => import("./pages/Login.jsx"));
const Register = lazy(() => import("./pages/Register.jsx"));
const ChangePassword = lazy(() => import("./pages/ChangePassword.jsx"));

const Dashboard = lazy(() => import("./pages/Dashboard.jsx"));
const ThreatLogs = lazy(() => import("./pages/ThreatLogs.jsx"));
const HoneypotAnalytics = lazy(() => import("./pages/HoneypotAnalytics.jsx"));
const Campaigns = lazy(() => import("./pages/Campaigns.jsx"));
const AIAnalytics = lazy(() => import("./pages/AIAnalytics.jsx"));
const UserManagement = lazy(() => import("./pages/UserManagement.jsx"));
const Settings = lazy(() => import("./pages/Settings.jsx"));

/* ---------------- Protected Route ---------------- */

function ProtectedRoute() {
  const { user } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (user.mustChangePassword) {
    return <Navigate to="/change-password" replace state={{ from: location }} />;
  }

  return <Outlet />;
}

/* ---------------- Public Route ---------------- */

function PublicRoute() {
  const { user } = useAuth();

  if (user) {
    return user.mustChangePassword ? (
      <Navigate to="/change-password" replace />
    ) : (
      <Navigate to="/dashboard" replace />
    );
  }

  return <Outlet />;
}

/* ---------------- Change Password Route ---------------- */

function ChangePasswordRoute() {
  const { user } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (!user.mustChangePassword) {
    return <Navigate to="/dashboard" replace />;
  }

  return <Outlet />;
}

/* ---------------- Admin Route Guard ---------------- */

export function AdminRoute({ children, redirectTo = "/dashboard" }) {
  const { user } = useAuth();
  const location = useLocation();

  useEffect(() => {
    if (user && user.role !== "admin") {
      toast.error("Access denied: Insufficient permissions (Admin only)", {
        id: "admin-route-denied",
        duration: 6000,
      });
    }
  }, [user]);

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (user.role !== "admin") {
    return <Navigate to={redirectTo} replace state={{ from: location }} />;
  }

  return children ? children : <Outlet />;
}

/* ---------------- App Routes ---------------- */

function AppRoutes() {
  return (
    <>
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: "#081f35",
            color: "#c8e6f5",
            border: "1px solid #0d3352",
            borderRadius: "4px",
            fontFamily: "'Share Tech Mono', monospace",
            fontSize: "12px",
          },
          success: {
            iconTheme: {
              primary: "#00ff88",
              secondary: "#020b18",
            },
          },
          error: {
            iconTheme: {
              primary: "#ff2d55",
              secondary: "#020b18",
            },
          },
        }}
      />

      <ErrorBoundary>
        <Suspense
          fallback={
            <div
              style={{
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                height: "100vh",
                background: "#020b18",
                color: "#00ff88",
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: "18px",
              }}
            >
              Loading...
            </div>
          }
        >
          <Routes>
            {/* Public Pages */}
            <Route path="/" element={<Landing />} />
            <Route path="/about" element={<About />} />
            <Route path="/features" element={<Features />} />

            {/* Login/Register */}
            <Route element={<PublicRoute />}>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
            </Route>

            {/* Password Change Route */}
            <Route element={<ChangePasswordRoute />}>
              <Route path="/change-password" element={<ChangePassword />} />
            </Route>

            {/* Protected Pages */}
            <Route element={<ProtectedRoute />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/dashboard/threats" element={<ThreatLogs />} />
              <Route path="/dashboard/honeypot" element={<HoneypotAnalytics />} />
              <Route path="/dashboard/campaigns" element={<Campaigns />} />
              <Route path="/dashboard/ai" element={<AIAnalytics />} />

              {/* Admin-only Protected Pages */}
              <Route element={<AdminRoute />}>
                <Route path="/dashboard/users" element={<UserManagement />} />
                <Route path="/settings" element={<Settings />} />
              </Route>
            </Route>

            {/* 404 */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </ErrorBoundary>
    </>
  );
}

/* ---------------- Root App ---------------- */

export default function App() {
  return (
    <AuthProvider>
      <SocketProvider><AppRoutes /></SocketProvider>
    </AuthProvider>
  );
}
