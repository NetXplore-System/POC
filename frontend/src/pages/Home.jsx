import React from "react";
import UploadWhatsAppFile from "./Form";
import Menu from "../components/Menu/Menu.jsx"; // Adjust the path if needed

const Home = () => {
  return (
    <div className="upload-section">
            {/* <Menu /> Menu is now displayed only on the Home page */}
      <UploadWhatsAppFile />
    </div>
  );
};

export default Home;
