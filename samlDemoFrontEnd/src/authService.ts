// src/authService.ts
import axios from 'axios';

const backendURL = 'http://localhost:5011';

export const checkAuthentication = async (): Promise<boolean> => {
  try {
    const token = localStorage.getItem("jwtToken");
    if (token) {
      // Attempt to access a protected resource with the JWT token
      const response = await axios.get(`${backendURL}/auth/check-session`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.status === 200;
    }
    // No token found, redirect to login
    window.location.href = `${backendURL}/auth/login`;
    return false;
  } catch (error) {
    window.location.href = `${backendURL}/auth/login`;
    return false;
  }
};

export const login = async (): Promise<void> => {
  const response = await axios.get(`${backendURL}/auth/login`, { withCredentials: true });
  const token = response.data.token;
  localStorage.setItem("jwtToken", token);
};
