import { Instructor } from '../models/Instructor.js';
import Joi from 'joi';
import mongoSanitize from 'express-mongo-sanitize';
import bcrypt from 'bcryptjs';
const instructorLoginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required()
}).unknown(false).required();
const instructorSearchSchema = Joi.object({
  name: Joi.string().trim().allow('')
}).unknown(false);
function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { error, value } = instructorLoginSchema.validate(req.body, {
      convert: false
    });

    if (error || mongoSanitize.has(req.body)) {
      return res.status(400).json({
        message: 'Invalid login request'
      });
    }

    const { username, password } = value;
    const instructor = await Instructor.findOne({ username });

    if (!instructor || !(await bcrypt.compare(password, instructor.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    const { error, value } = instructorSearchSchema.validate(req.query);

    if (error || mongoSanitize.has(req.query)) {
      return res.json({ count: 0, instructors: [] });
    }

    const filter = value.name ? { name: value.name } : {};
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .lean();

    return res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
