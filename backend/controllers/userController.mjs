import User from "../models/userModel.mjs";
import asyncHandler from "../middlewares/asyncHandler.mjs";
import createToken from "../utils/createToken.mjs";
import bcrypt from "bcrypt";

const createUser = asyncHandler(async (req, res) => {
  const { username, password, profileImage, rootSeed, salt, address } = req.body;
  if (!username || !password || !profileImage || !rootSeed || !address) {
    throw new Error("Fill the all inputs");
  }
  const userExists = await User.findOne({ username });
  if (userExists) return res.status(400).json({ message: "Username already exists" });

  const newUser = new User({ username, password, profileImage, rootSeed, salt, address });
  try {
    await newUser.save();
    createToken(res, newUser._id);

    return res.status(201).json({
      _id: newUser._id,
      username: newUser.username,
      profileImage: newUser.profileImage,
      rootSeed: newUser.rootSeed,
      salt: newUser.salt,
      address: newUser.address
    });
  } catch (error) {
    res.status(400).json({ message: "Invalid data" });
  }
});

const loginUser = asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  const existingUser = await User.findOne({ username });

  if (existingUser) {
    const isPasswordValid = await bcrypt.compare(
      password,
      existingUser.password
    );

    if (isPasswordValid) {
      createToken(res, existingUser._id);

      return res.status(200).json({
        _id: existingUser._id,
        username: existingUser.username,
        profileImage: existingUser.profileImage,
        rootSeed: existingUser.rootSeed,
        salt: existingUser.salt,
        address: existingUser.address
      });
    } else {
      return res.status(401).json({ message: "Invalid password" });
    }
  } else {
    return res.status(401).json({ message: "Invalid username" });
  }
});

const logoutCurrentUser = asyncHandler(async (req, res) => {
  res.cookie("jwt", "", {
    httyOnly: true,
    expires: new Date(0)
  });

  return res.status(200).json({ message: "Log out successful" });
});

const checkExistUser = asyncHandler(async (req, res) => {
  const { username } = req.body;
  const userExists = await User.findOne({ username });
  if (userExists) {
    return res.status(200).json({ existUser: true });
  } else {
    return res.status(200).json({ existUser: false });
  }
});

const getAddressFromUsername = asyncHandler(async (req, res) => {
  const { username } = req.body;
  const user = await User.findOne({ username });
  if (user) {
    return res.status(200).json({ address: user.address, profileImage: user.profileImage });
  } else {
    return res.status(401).json({ message: "Invalid username" });
  }
});

export {
  createUser,
  loginUser,
  logoutCurrentUser,
  checkExistUser,
  getAddressFromUsername
};
