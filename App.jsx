
import { useState } from "react";

export default function App() {
  const [password, setPassword] = useState("");

  const score =
    (password.length >= 12 ? 25 : 0) +
    (/[A-Z]/.test(password) ? 25 : 0) +
    (/[a-z]/.test(password) ? 15 : 0) +
    (/\d/.test(password) ? 15 : 0) +
    (/[^A-Za-z0-9]/.test(password) ? 20 : 0);

  const level =
    score < 40 ? "Weak" : score < 70 ? "Medium" : "Strong";

  return (
    <div style={{maxWidth:600,margin:"40px auto",fontFamily:"Arial"}}>
      <h1>Password Strength Analyzer</h1>
      <input
        type="password"
        value={password}
        onChange={(e)=>setPassword(e.target.value)}
        placeholder="Enter password"
        style={{width:"100%",padding:"12px"}}
      />
      <h2>Strength: {level}</h2>
      <p>Score: {score}/100</p>
    </div>
  );
}
