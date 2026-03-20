import axios from "axios";

// In production (built by Vite), requests go to /api/v1 (same origin, Nginx proxies them).
// In dev (vite dev server), the vite proxy forwards /api → localhost:8080.
const baseURL = import.meta.env.PROD
  ? "/api/v1"
  : "http://localhost:8080/api/v1";

export const api = axios.create({
  baseURL,
  withCredentials: true,
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401 && !window.location.pathname.includes("/login")) {
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);
