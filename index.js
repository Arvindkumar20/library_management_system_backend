// Import dependencies
import express from 'express'; // Express framework for building APIs
import mongoose from 'mongoose'; // Mongoose for MongoDB interaction
import dotenv from 'dotenv'; // dotenv for loading environment variables
import cors from 'cors'; // CORS middleware for handling cross-origin requests
import bcrypt from 'bcryptjs'; // bcrypt for hashing passwords
import jwt from 'jsonwebtoken'; // JWT for authentication
import multer from 'multer'; // Multer for handling file uploads
import path from 'path'; // Path module for working with file paths
import { type } from 'os';

// Load environment variables
dotenv.config();

const app = express();
app.use(express.json()); // Middleware to parse JSON bodies
app.use(cors()); // Enable CORS for cross-origin requests

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {

}).then(() => console.log("MongoDB Connected"))
    .catch(err => console.log(err));

// Token blacklist (temporary, should use Redis for production)
const tokenBlacklist = new Set(); // Store invalidated tokens

// Middleware for authentication
const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization'); // Get token from headers
    if (!token) return res.status(401).json({ message: 'Access Denied' });

    if (tokenBlacklist.has(token)) return res.status(401).json({ message: 'Token has been invalidated' }); // Check if token is blacklisted

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET); // Verify token
        req.user = verified; // Attach user data to request
        next(); // Proceed to next middleware
    } catch (err) {
        res.status(400).json({ message: 'Invalid Token' }); // Handle invalid token
    }
};

// Multer configuration for image uploads
const storage = multer.diskStorage({
    destination: './uploads/', // Set upload directory
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname)); // Generate unique filename
    }
});
const upload = multer({ storage }); // Initialize multer with storage settings

// User Model
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true }, // Name field (required)
    email: { type: String, required: true, unique: true }, // Email field (unique & required)
    password: { type: String, required: true, minlength: 6 }, // Password field with min length
    borrowedBooks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Book' }], // Added borrowedBooks field
    feedBacks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'FeedBack' }] // Added feedBacks field
}, { timestamps: true });


// Hash password before saving user
UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next(); // Skip if password is unchanged
    this.password = await bcrypt.hash(this.password, 10); // Hash password
    next();
});

const User = mongoose.model('User', UserSchema); // Create User model


// feed back model 
const feedBackSchema = new mongoose.Schema({
    title: {
        type: String,
        require: true
    },
    description: {
        type: String,
        require: true
    },
    userFeedBacked: {
        type: mongoose.Types.ObjectId, ref: "User"
    }
});
const FeedBack = mongoose.model("feedBack", feedBackSchema);



// ✅ Create Feedback (Only Authenticated Users)
app.post('/feedback', authMiddleware, async (req, res) => {
    try {
        const { title, description } = req.body;
        if (!title || !description) return res.status(400).json({ message: "Title and Description are required" });

        const feedback = new FeedBack({
            title,
            description,
            userFeedBacked: req.user.id // Only logged-in user can post feedback
        });

        await feedback.save();
        res.status(201).json({ message: "Feedback submitted successfully", feedback });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ✅ Get All Feedback
app.get('/feedback', async (req, res) => {
    try {
        const feedbacks = await FeedBack.find().populate('userFeedBacked', 'name email');
        res.json(feedbacks);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ✅ Get Feedback of Logged-in User
app.get('/feedback/me', authMiddleware, async (req, res) => {
    try {
        const feedbacks = await FeedBack.find({ userFeedBacked: req.user.id });
        res.json(feedbacks);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ✅ Delete Feedback (Only the user who created it can delete it)
app.delete('/feedback/:id', authMiddleware, async (req, res) => {
    try {
        const feedback = await FeedBack.findById(req.params.id);
        if (!feedback) return res.status(404).json({ message: "Feedback not found" });

        if (feedback.userFeedBacked.toString() !== req.user.id) {
            return res.status(403).json({ message: "Unauthorized to delete this feedback" });
        }

        await feedback.deleteOne();
        res.json({ message: "Feedback deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});



// Teacher Model
const TeacherSchema = new mongoose.Schema({
    name: { type: String, required: true },
    subject: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, minlength: 6 } // Added password field for teacher
}, { timestamps: true });

TeacherSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10); // Hash teacher password
    next();
});

const Teacher = mongoose.model('Teacher', TeacherSchema);

// Book Model
const BookSchema = new mongoose.Schema({
    title: { type: String, required: true }, // Book title
    author: { type: String, required: true }, // Book author
    image: { type: String } // Optional book cover image
}, { timestamps: true });

const Book = mongoose.model('Book', BookSchema);

// Routes

// Register a new user
app.post('/register', async (req, res) => {
    try {
        const user = new User(req.body);
        await user.save(); // Save user to database
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' }); // Generate token
        res.status(201).json({ message: 'User created successfully', token });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// User login
app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email }); // Find user by email
        if (!user) return res.status(400).json({ message: 'User not found' });
        const isMatch = await bcrypt.compare(req.body.password, user.password); // Compare passwords
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' }); // Generate token
        res.json({ message: 'Login successful', token });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Teacher signup
app.post('/teacher/register', async (req, res) => {
    try {
        const teacher = new Teacher(req.body);
        await teacher.save(); // Save teacher to database
        const token = jwt.sign({ id: teacher._id }, process.env.JWT_SECRET, { expiresIn: '1h' }); // Generate token
        res.status(201).json({ message: 'Teacher registered successfully', token });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Teacher login
app.post('/teacher/login', async (req, res) => {
    try {
        const teacher = await Teacher.findOne({ email: req.body.email }); // Find teacher by email
        if (!teacher) return res.status(400).json({ message: 'Teacher not found' });
        const isMatch = await bcrypt.compare(req.body.password, teacher.password); // Compare passwords
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: teacher._id }, process.env.JWT_SECRET, { expiresIn: '1h' }); // Generate token
        res.json({ message: 'Teacher login successful', token });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Add a new book
app.post('/books', authMiddleware, upload.single('image'), async (req, res) => {
    try {
        const book = new Book({
            title: req.body.title,
            author: req.body.author,
            image: req.file ? req.file.filename : null // Store image filename if uploaded
        });
        await book.save();
        res.status(201).json({ message: 'Book added successfully' });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Borrow a book and add to user's borrowedBooks array
app.post('/borrow/:bookId', authMiddleware, async (req, res) => {
    try {
        const book = await Book.findById(req.params.bookId);
        if (!book) return res.status(404).json({ message: 'Book not found' });

        const user = await User.findById(req.user.id);

        // Check if the user has already borrowed the book
        if (user.borrowedBooks.includes(book._id)) {
            return res.status(400).json({ message: 'You have already borrowed this book' });
        }

        // Add book to user's borrowedBooks array
        user.borrowedBooks.push(book._id);
        await user.save();  // Save the updated user

        res.json({ message: 'Book borrowed successfully', borrowedBooks: user.borrowedBooks });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Return a book and remove from user's borrowedBooks array
app.post('/return/:bookId', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const bookIndex = user.borrowedBooks.indexOf(req.params.bookId);

        if (bookIndex === -1) {
            return res.status(404).json({ message: 'This book is not in your borrowed list' });
        }

        // Remove book from user's borrowedBooks array
        user.borrowedBooks.splice(bookIndex, 1);
        await user.save();

        res.json({ message: 'Book returned successfully', borrowedBooks: user.borrowedBooks });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
