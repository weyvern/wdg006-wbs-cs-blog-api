import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import ErrorResponse from '../utils/ErrorResponse.js';

export const registerUser = async (req, res, next) => {
  /*  
    Validate the input => maybe use a middleware with Joi [x]
    Check if user already exists => User.find(by email) [x]
      if exists say no => throw ErrorResponse [x]
      if no exists create 
        Hash (and salt) the password [x] https://www.npmjs.com/package/bcrypt?activeTab=readme
        Create user [x]
        Create token jsonwebtoken https://www.npmjs.com/package/jsonwebtoken [x]
        Send token => res.json() res.set() res.cookie() [x]
  */
  try {
    const {
      body: { email, password, ...rest }
    } = req;
    const found = await User.findOne({ email });
    if (found) throw new ErrorResponse('User already exists', 403);
    const hash = await bcrypt.hash(password, 5);
    const { _id } = await User.create({ ...rest, email, password: hash });
    const token = jwt.sign({ _id }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (error) {
    next(error);
  }
};

export const loginUser = (req, res, next) => {
  /*  
Validate the input => maybe use a middleware with Joi [x] - Already implemented as a middleware in the route
Check if user already exists => User.find(by email) []
  if no exists say no => throw ErrorResponse []
  if exists 
    verify the password [] https://www.npmjs.com/package/bcrypt?activeTab=readme
    if password not a match => throw ErrorResponse []
    if password match
      Create token jsonwebtoken https://www.npmjs.com/package/jsonwebtoken []
      Send token => res.json() res.set() res.cookie() []
*/
  const token = jwt.sign({ _id: 'Sarah' }, '12345');
  res.json({ token });
};

export const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    res.json(user);
  } catch (error) {
    next(error);
  }
};
