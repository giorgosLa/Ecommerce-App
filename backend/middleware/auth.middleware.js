import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

export const protectRoute = async (req, res, next) => {
  try {
    const accessToken = req.cookies.accessToken;

    if (!accessToken)
      return res.status(401).json({ message: "Unauthorized - No accessToken" });

    try {
      const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);

      const user = await User.findById(decoded.userId).select("-password");

      if (!user) return res.status(401).json({ message: "User not Found!" });

      req.user = user;

      next();
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ message: "Unauthorized - Access Token expired" });
      }
      throw error;
    }
  } catch (error) {
    console.log("Error in ProtectRoute middleWare", error.message);
    res.status(401).json({ message: "Unauthorized - Invalid access Token" });
  }
};

export const adminRoute = (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    return res.status(403).json({ message: "Unauthorized - Admin only" });
  }
};
