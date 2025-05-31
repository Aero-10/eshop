import { createBrowserRouter } from "react-router-dom";
import App from "../App.jsx";
import Home from "../pages/home.jsx";


const router= createBrowserRouter([
    {
        path :"/",
        element : <App/>,
        children:[
            {
                path:"",
                element: <Home/>
            }
        ]
    }
])
export default router