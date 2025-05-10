import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {
  createUser,
  findUserByEmail,
  findUserById,
  updatePassword,
  updatePassengerByIdUtilisateur,
} from '../models/user.model.js';
// Register
export const registerUser = async (req, res) => {
  const { email, password, role = 'passanger',nom,prenom } = req.body;
  try {
    const user = await findUserByEmail(email);
    if(!user){
    const hashed = await bcrypt.hash(password, 10);
    await createUser(email, hashed, role,nom,prenom);
     return res.status(201).redirect('/login?message=registration_success')
    }
    return res.redirect('/login?message=already_registered')
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Login
export const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.motDePasse))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.idUtilisateur, role: user.role }, process.env.JWT_SECRET);
    return res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Get Profile
export const getProfile = async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Change Profile
export const updateProfile = async (req, res) => {
  const {nom, prenom,email } = req.body;
  const idUtilisateur = req.user.id
  console.log(nom,prenom,email,idUtilisateur);
  

  if (!idUtilisateur  || !nom || !prenom || !email) {
    return res.status(400).json({ message: 'Missing fields' });
  }
  try {
    const result = await updatePassengerByIdUtilisateur(idUtilisateur, nom, prenom, email);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Passenger not found' });
    }

    res.status(200).json({ message: 'Passenger updated successfully' });
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};
// Change Password
export const changePassword = async (req, res) => {
  const { newPassword } = req.body;
  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    await updatePassword(req.user.id, hashed);
    res.json({ message: 'Password updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
