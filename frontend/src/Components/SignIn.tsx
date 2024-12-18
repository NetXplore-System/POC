import { Dispatch, SetStateAction, useState } from "react"
import { IUser } from "./Layout"
import { NavLink, useNavigate } from "react-router";
import axios from "axios";

interface ISignIn {
    setUser: Dispatch<SetStateAction<IUser>>;
}
function SignIn({ setUser }: ISignIn) {
    const [credentials, setCredentials] = useState({
        password: '',
        email: ''
    });
    const navigate = useNavigate();


    const handleSignIn = async (e: React.FormEvent) => {
        e.preventDefault();
        const user = JSON.stringify({ password: credentials.password, email: credentials.email });
        try {
            const res = await axios.post("http://localhost:8000/researchers/signin", user, {
                headers: {
                    "Accept": "*/*",
                    "Content-Type": "application/json"
                }
            });
            console.log(res.data)
            setUser(res.data);
            navigate('/profile');
            alert('Sign In Successful!');
        } catch (error) {
            console.log(error)

        }

    };
    return (
        <div className="container mt-5">
            <div className="row justify-content-center">
                <div className="col-md-6">
                    <div className="card">
                        <div className="card-header">Sign In</div>
                        <div className="card-body">
                            <form onSubmit={handleSignIn}>
                                <div className="mb-3">
                                    <label htmlFor="email" className="form-label">Email</label>
                                    <input
                                        type="email"
                                        className="form-control"
                                        id="email"
                                        value={credentials.email}
                                        onChange={(e) => setCredentials({ ...credentials, email: e.target.value })}
                                        required
                                    />
                                </div>
                                <div className="mb-3">
                                    <label htmlFor="password" className="form-label">Password</label>
                                    <input
                                        type="password"
                                        className="form-control"
                                        id="password"
                                        value={credentials.password}
                                        onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
                                        required
                                    />
                                </div>
                                <button type="submit" className="btn btn-success">Sign In</button>
                            </form>
                            <NavLink to={"/SignUp"}>Do not have account? SignUp here</NavLink>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default SignIn