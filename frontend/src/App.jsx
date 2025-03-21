import { useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./App.css";
import Home from "./pages/Home.jsx";
import SignIn from "./pages/SignIn.jsx";
import SignUp from "./pages/SignUp.jsx";
import Profile from "./pages/Profile.jsx";
import EditProfile from "./pages/EditProfile.jsx";
import PrivateRoute from './components/PrivateRoute';
import Header from "./components/Header.jsx";
// import Menu from "./components/Menu/Menu.jsx";

function App() {
  const [count, setCount] = useState(0);
  const user = localStorage.getItem("user");
  return (
    <>
      <BrowserRouter>
        {/* <Menu /> */}
        {/* {user && <Header />}*/}
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/sign-in" element={<SignIn />} />
          <Route path="/sign-up" element={<SignUp />} />
          {/* Private Routes */}
          <Route element={<PrivateRoute />}>
            <Route path="/profile" element={<Profile />} />
            <Route path="/edit-profile" element={<EditProfile />} />
          </Route>
        </Routes>
      </BrowserRouter>

    </>
  );
}

export default App;
