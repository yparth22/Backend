import prisma from "../config/prismaClient.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import validatePhoneNumber from "../utils/validation.js";


const getEmployeeBySAPID = async (sapId) => {
  try {
    // Query the user_master table using Prisma to get the employee information
    const employee = await prisma.user_master.findUnique({
      where: {
        sap_id: sapId,  // Search by sap_id
      },
      select: {
        sap_id: true,
        phone_number: true,
        date_of_birth: true,
        email: true,
        designation: true, 
        office_location : true,
        is_digilocker_verified : true // Select only the required fields
      },
    });

    if (!employee) {
      return null;  // Return null if no employee is found
    }

    return employee;  // Return the employee data

  } catch (err) {
    console.error('Error fetching employee information:', err);
    throw err;
  }
};

export const verifyOtp = async (req, res) => {
  const { phone_number, otp } = req.body;

  if (!phone_number || !otp) {
    return res.status(400).json({
      success: false,
      status: 400,
      message: 'Phone number and OTP are required.',
    });
  }

  if (!validatePhoneNumber(phone_number)) {
    return res.status(400).json({
      success: false,
      status: 400,
      message: 'Phone number must be in the format +91 followed by exactly 10 digits.',
    });
  }

  try {
    const user = await prisma.user_master.findUnique({
      where: { phone_number },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        status: 404,
        message: 'User not registered.',
      });
    }

    // Validate OTP here
    console.log(user.otp);
    console.log(otp);
    if (otp !== "12345") {
      return res.status(400).json({
        success: false,
        status: 400,
        message: 'Invalid OTP.',
      });
    }
    const payload = {
      user_id: user.id, // Include the user ID (or any other info)
      phone_number: user.phone_number,
    };

    // Replace 'your_secret_key' with your actual secret key for signing the token
    const access_token = jwt.sign(payload, 'your_secret_key', { expiresIn: '1h' });
    await prisma.user_master.update({
      where: { phone_number },
      data: { verified_status: true },
    });

    res.status(200).json({
      success: true,
      status: 200,
      message: 'OTP verified successfully.',
      data: {
        access_token: access_token,
        //name: user.first_name + ' ' + user.last_name,
        name : user.name,
        phone_number: user.phone_number,
        email: user.email,
        designation: user.designation,
        is_digilocker_verified : user.is_digilocker_verified,
        office_location : user.office_location
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      status: 500,
      message: 'Error verifying OTP.',
    });
  }
};

export const signup = async (req, res) => {
  const { sap_id } = req.body;

  if (!sap_id) {
    return res.status(400).json({
      success: false,
      status: 400,
      message: 'SAP ID is required.',
    });
  }

  try {
    const employee = await getEmployeeBySAPID(sap_id);

    if (!employee) {
      return res.status(404).json({
        success: false,
        status: 404,
        message: 'Employee not found with the provided SAP ID.',
      });
    }

    res.status(200).json({
      success: true,
      message: 'Success',
      data: employee,
    });
  } catch (err) {
    console.error('Error during API request:', err);
    res.status(500).json({
      success: false,
      message: 'Error retrieving employee information.',
    });
  }
};

/**
 * create user
 * @auth required
 * @route {POST} /api/v1/user/register
 * @returns created user
 */
export const registerUser = async (req, res) => {
  const { name, email, password } = req.body;
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (user) {
    return res.status(400).json("user already exists");
  }

  const createdUser = await prisma.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
    },
  });

  res.status(201).json({ user: createdUser });
};

/**
 * login
 * @auth not required
 * @route {POST} /api/v1/user/login
 * @returns token
 */
export const loginUser = async (req, res) => {
  //    get the user from req.body
  const { email, password } = req.body;
  //   check if the user exists
  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (user) {
    // check if the password matches to the one in the db
    const comparePassword = bcrypt.compareSync(password, user.password);
    if (comparePassword) {
      // sign the token
      const payload = {
        userId: user.id,
      };
      jwt.sign(
        payload,
        process.env.JWTSECRET,
        {
          expiresIn: "30d",
        },
        (err, token) => {
          if (err || !token) {
            return res.status(401).json("token was not found");
          }
          return res.status(200).json({
            token: token,
          });
        }
      );
    }
  }
};

/**
 * get single user
 * @auth required
 * @route {GET} /api/v1/user/
 * @returns requested  user
 */
export const getuser = async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.userId },
  });

  if (!user) {
    return res.status(404).json({ error: "user not found" });
  }

  res.json({ user });
};

/**
 * delete single
 * @auth required
 * @route {DELETE} /api/v1/user/delete/{{id}}
 * @returns removed  user
 */
export const deleteuser = async (req, res) => {
  const { id } = req.params;

  const user = await prisma.user.findUnique({
    where: { id: parseInt(id) },
  });

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  // Check that the authenticated user is the same as the user being deleted
  if (user.id !== req.userId) {
    return res
      .status(403)
      .json({ error: "You do not have permission to delete this user" });
  }

  await prisma.user.delete({
    where: { id: parseInt(id) },
  });

  res.json({ message: "User deleted successfully" });
};

/**
 * update single
 * @auth required
 * @route {PUT} /api/v1/user/update/{{id}}
 * @returns updated  user
 */
export const updateuser = async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;

  const user = await prisma.user.findUnique({
    where: { id: parseInt(id) },
  });

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  // Check that the authenticated user is the same as the user being updated
  if (user.id !== req.userId) {
    return res
      .status(403)
      .json({ error: "You do not have permission to update this user" });
  }

  const updatedUser = await prisma.user.update({
    where: { id: parseInt(id) },
    data: {
      name,
      email,
    },
  });

  res.json({ user: updatedUser });
};

/**
 *  get all users
 * @auth required
 * @route {GET} /api/v1/user/users/all
 * @returns all users
 */
export const getAllusers = async (req, res) => {
  const users = await prisma.user.findMany({
    include: {
      articles: true,
    },
  });

  return res.status(200).json({
    users,
  });
};
