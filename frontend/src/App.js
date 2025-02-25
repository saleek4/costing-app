import React, { useState } from "react";
import axios from "axios";
import "bootstrap/dist/css/bootstrap.min.css";

function App() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");
    const [token, setToken] = useState("");
    const [costingData, setCostingData] = useState([]);

    const handleLogin = async () => {
        try {
            const response = await axios.post("http://127.0.0.1:5000/login", {
                username,
                password
            });

            setMessage("Login Successful!");
            setToken(response.data.token);
        } catch (error) {
            setMessage("Login Failed! Check username and password.");
        }
    };

    const fetchCostingData = async () => {
        try {
            const response = await axios.get("http://127.0.0.1:5000/get_costing", {
                headers: { Authorization: `Bearer ${token}` }
            });
            setCostingData(response.data);
        } catch (error) {
            setMessage("Failed to load costing data.");
        }
    };

    return (
        <div className="container text-center mt-5">
            <h2>Login</h2>
            <div className="mb-3">
                <input type="text" className="form-control" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="mb-3">
                <input type="password" className="form-control" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <button className="btn btn-primary" onClick={handleLogin}>Login</button>
            <p className="mt-3">{message}</p>

            {token && (
                <>
                    <h2>Costing Sheet</h2>
                    <button className="btn btn-success" onClick={fetchCostingData}>Load Costing Data</button>
                    <button className="btn btn-warning ms-3" onClick={() => window.location.href = "http://127.0.0.1:5000/download_result"}>
                        Download Costing Sheet
                    </button>
                    <table className="table table-bordered table-striped mt-3">
                        <thead className="table-dark">
                            <tr>
                                <th>Field</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {costingData.map((item, index) => (
                                <tr key={index}>
                                    <td>{Object.keys(item)[0]}</td>
                                    <td>{Object.values(item)[0]}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </>
            )}
        </div>
    );
}

export default App;
