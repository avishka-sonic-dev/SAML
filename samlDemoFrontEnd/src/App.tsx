// src/App.tsx
import React, { useEffect, useState } from 'react';
import { checkAuthentication, login } from './authService';

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);

  useEffect(() => {
    const authenticate = async () => {
      const authenticated = await checkAuthentication();
      setIsAuthenticated(authenticated);
      if (!authenticated) {
        await login();
      }
    };
    authenticate();
  }, []);

  if (!isAuthenticated) {
    return <div>Redirecting to RM Unify login...</div>;
  }

  return (
    <div className="App">
      <h1>Welcome to CC5 Dev App</h1>
      {/* Main content of your app */}
    </div>
  );
};

export default App;
