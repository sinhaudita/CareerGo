const express = require('express');
const ejs = require('ejs');
const bcrypt = require("bcrypt");
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require('path');
const app = express();
const PORT = 9002;

const Applicant = require('./models/Applicants');



app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs')
    // Secret key for JWT
const jwtsk = 'pehli_baar_hai_errors_aayenge_hi_tum_koshish_karte_rehna';

app.get('/', (req, res) => {
    res.render('home');
});
app.get('/signup', async(req, res) => {
    res.render('signup');

});
app.get('/login', (req, res) => {
    const token = req.cookies.token;

    if (token) {
        // If the user already has a token, verify it and redirect based on their role
        jwt.verify(token, jwtsk, async(error, decodedToken) => {
            if (error) {
                if (error.name === "TokenExpiredError") {
                    // If the token has expired, clear the cookie and prompt for re-login
                    res.clearCookie('token');
                    return res.redirect('/login');
                } else {
                    return res.status(403).send("Token not valid");
                }
            }

            // Find the user based on the token's email
            const user = await User.findOne({ email: decodedToken.email });

            if (!user) {
                return res.status(404).send("User not found");
            }

            // Redirect to the appropriate dashboard based on the user's role
            if (user.role === 'recruiter') {
                return res.redirect('/recruiterdash');
            } else {
                return res.redirect('/dashboard');
            }
        });
    } else {
        // If no token is present, render the login page
        res.render('login');
    }
});
app.get('/recruiterdash', async(req, res) => {
    const token = req.cookies.token;

    if (!token) {
        // Redirect to login if no token is found
        return res.redirect('/login');
    }

    jwt.verify(token, jwtsk, async(error, decodedToken) => {
        if (error) {
            // Handle token verification errors
            console.error("Token verification failed:", error);
            return res.redirect('/login'); // Redirect to login on token error
        }

        try {
            const email = decodedToken.email;
            console.log("Decoded email from token:", email);

            const user = await User.findOne({ email: email });

            if (!user) {
                // Handle case where user is not found
                console.error("User not found for email:", email);
                return res.status(404).send('User not found');
            }

            if (user.role !== 'recruiter') {
                // If user is not a recruiter, redirect to the appropriate page
                return res.redirect('/dashboard');
            }

            // Render the recruiter dashboard with the user's information
            res.render('recruiterdash', { username: user.name });
        } catch (err) {
            // Handle any errors that occur while fetching the user
            console.error("Error fetching user:", err);
            res.status(500).send('Failed to load recruiter dashboard');
        }
    });
});


app.post('/recruiterdash', async(req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login');
    }

    jwt.verify(token, jwtsk, async(error, decodedToken) => {
        if (error) {
            console.error("Token verification failed:", error);
            return res.redirect('/login'); // Redirect to login on token error
        }

        try {
            const email = decodedToken.email;
            const user = await User.findOne({ email: email });

            if (!user) {
                return res.status(404).send('User not found');
            }

            if (user.role !== 'recruiter') {
                return res.redirect('/dashboard'); // Redirect to dashboard if not a recruiter
            }

            // Process any data sent in the POST request here
            // For example, handle form data or other inputs

            // Redirect to the recruiter dashboard after processing
            res.redirect('/recruiterdash');
        } catch (err) {
            console.error("Error fetching user:", err);
            res.status(500).send('Failed to process request');
        }
    });
});




app.get('/dashboard', (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login');
    }

    jwt.verify(token, jwtsk, async(error, decodedToken) => {
        if (error) {
            if (error.name === "TokenExpiredError") {
                return res.redirect('/login'); // Redirect to login if token has expired
            }
            return res.status(403).send("Token not valid");
        }

        const user = await User.findOne({ email: decodedToken.email });
        const userDetails = await Details.findOne({ email: decodedToken.email });

        if (!user) {
            return res.status(404).send("User not found");
        }

        if (user.role === 'recruiter') {
            return res.redirect('/recruiterdash');
        } else {
            return res.render("dashboard", { username: user.name, details: userDetails });
        }
    });
});

app.get('/logout', (req, res) => {
    res.clearCookie("token");
    res.redirect('/login')
});


const mongoURI = 'mongodb://localhost:27017/jobPo';

// Connect to MongoDB
mongoose.connect(mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    }).then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('Failed to connect to MongoDB', err));

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, index: true },
    password: String,
    role: { type: String, enum: ['recruiter', 'seeker'], default: 'seeker' }, // Added role field
    appliedJobs: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Job', default: [] }] // Added appliedJobs field
});


const User = mongoose.model('User', userSchema);


app.post('/signup', async(req, res) => {
    const { name, email, password, role } = req.body;

    // Check if the email is already in use
    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.send('Email already in use. Please use a different email.');
    }

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the new user with hashed password
    const newUser = new User({ name, email, password: hashedPassword, role });
    await newUser.save();
    res.redirect('/choose-role?email=' + encodeURIComponent(email));
    // Redirect to the role selection page
    //res.redirect('/choose-role');
});

app.post('/login', async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return res.send('Invalid email or password');
    }

    // Compare the password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
        const token = jwt.sign({ email: email, userId: user._id }, jwtsk, {
            expiresIn: "1h",
        });
        res.cookie('token', token, { httpOnly: true });

        // Redirect based on role
        if (user.role === 'recruiter') {
            res.redirect('/recruiterdash');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        res.send('Invalid email or password');
    }
});

app.get('/details', (req, res) => {
    res.render('details');
});
const Schema = mongoose.Schema;

// Create a schema and model for job seekers' details
const detailsSchema = new Schema({
    fullName: String,
    email: String,
    phone: String,
    location: String,
    education: {
        school: String,
        degree: String,
        fieldOfStudy: String,
        startDate: Date,
        endDate: Date,
        activities: String,
        achievements: String
    },
    experience: String,
    skills: [String],
});


// Handle form submission
const Details = mongoose.model('Details', detailsSchema);

app.post('/details', async(req, res) => {
    try {
        const {
            fullName,
            email,
            phone,
            location,
            school,
            degree,
            fieldOfStudy,
            startDate,
            endDate,
            activities,
            achievements,
            experience,
            skills
        } = req.body;

        // Create a new details document
        const skillsArray = skills ? skills.split(',').map(skill => skill.trim()) : [];
        const newDetails = new Details({
            fullName,
            email,
            phone,
            location,
            education: {
                school,
                degree,
                fieldOfStudy,
                startDate,
                endDate,
                activities,
                achievements
            },
            experience,
            skills:skillsArray
        });

        await newDetails.save();

        // Find the user to pass the data to the dashboard
        const user = await User.findOne({ email });
        

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Redirect to the dashboard with user and details
        res.render('dashboard', {
            username: user.name,
            details: newDetails
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Failed to submit details');
    }
});





// Post a new job
app.get('/post-job', (req, res) => {
    res.render('postjob');
});

// Post a new job
// Post a new job
const Job = require('./models/jobs');

app.post('/jobs', async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(400).send("Token not found");
    }

    jwt.verify(token, jwtsk, async (error, decodedToken) => {
        if (error) {
            return res.status(403).send("Failed to authenticate token.");
        }

        try {
            const user = await User.findOne({ email: decodedToken.email });

            if (!user || user.role !== 'recruiter') {
                return res.status(403).send("Access denied");
            }

            const { title, description, company, location, salary, skills, deadline } = req.body;
            const newJob = new Job({
                title,
                description,
                company,
                location,
                salary,
                skills,
                deadline,
                postedBy: user._id, // Set the recruiter as the poster
                recruiterId: user._id // Assuming recruiterId is the same as postedBy
            });

            await newJob.save();
            res.status(201).redirect('/view-jobs');
        } catch (err) {
            console.error(err);
            res.status(500).send('Failed to post job');
        }
    });
});

// View all jobs
app.get('/jobs', async(req, res) => {
    try {
        const jobs = await Job.find();
        res.status(200).json(jobs);
    } catch (err) {
        console.error(err);
        res.status(500).send('Failed to fetch jobs');
    }
});



app.get('/view-jobs', async(req, res) => {
    try {
        const jobs = await Job.find();
        res.render('viewjobs', { jobs });
    } catch (err) {
        console.error(err);
        res.status(500).send('Failed to fetch jobs');
    }
});

app.get('/choose-role', (req, res) => {
    const { email } = req.query;
    res.render('chooserole', { email });
});
app.post('/choose-role', async(req, res) => {
    const { email, role } = req.body;
    console.log('Received email:', email);
    console.log('Received role:', role);


    if (!email || !role) {
        return res.status(400).send('Email and role are required');
    }

    try {
        // Validate role value
        if (!['recruiter', 'seeker'].includes(role)) {
            return res.status(400).send('Invalid role selected');
        }

        // Find the user by email and update their role
        const user = await User.findOneAndUpdate({ email }, { role }, { new: true });

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Redirect based on the role
        if (role === 'recruiter') {
            res.redirect('/recruiterdash');
        } else if (role === 'seeker') {
            res.redirect('/details');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});



// for my applied jobs
// Route to view applied jobs
// server.js (Add route for viewing applied jobs)
app.get('/applied-jobs', async(req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(400).send("Token not found");
    }

    jwt.verify(token, jwtsk, async(error, decodedToken) => {
        if (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).send("Token has expired. Please log in again.");
            }
            return res.status(403).send("Failed to authenticate token.");
        }
        const email = decodedToken.email;
        const user = await User.findOne({ email: email }).populate('appliedJobs');
        if (!user) {
            return res.status(404).send("User not found");
        }

        res.render('myappliedjobs', { appliedJobs: user.appliedJobs });
    });
});



app.post('/apply-jobs/:jobId', async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(400).send("Token not found");
    }

    jwt.verify(token, jwtsk, async (error, decodedToken) => {
        if (error) {
            return res.status(403).send("Failed to authenticate token.");
        }

        try {
            const user = await User.findOne({ email: decodedToken.email });
            if (!user || user.role !== 'seeker') {
                return res.status(403).send("Access denied");
            }

            const job = await Job.findById(req.params.jobId);
            if (!job) {
                return res.status(404).send('Job not found');
            }

            // Add user ID to job's applicants array if not already present
            if (!job.applicants.includes(user._id)) {
                job.applicants.push(user._id);
                await job.save();
            }

            // Add job ID to user's appliedJobs array if not already present
            if (!user.appliedJobs.includes(job._id)) {
                user.appliedJobs.push(job._id);
                await user.save();
            }

            
            res.redirect('/dashboard');
        } catch (err) {
            res.status(500).send('Failed to apply for job');
        }
    });
});




//recruiter job posted
app.get('/recruiter-jobs', async(req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login');
    }

    jwt.verify(token, jwtsk, async(error, decodedToken) => {
        if (error) {
            return res.redirect('/login');
        }

        try {
            const email = decodedToken.email;
            const user = await User.findOne({ email: email });

            if (!user || user.role !== 'recruiter') {
                return res.status(403).send("Access denied");
            }

            const jobs = await Job.find({ postedBy: user._id });

            // Pass the username along with the jobs
            res.render('recruiterjobs', { jobs, username: user.name });
        } catch (err) {
            console.error("Error fetching jobs:", err);
            res.status(500).send('Failed to load jobs');
        }
    });
});

// view applicants
// Middleware to verify token
function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    jwt.verify(token, jwtsk, async(err, user) => {
        if (err) return res.sendStatus(403);
        // const user = await User.findOne({ email: decodedToken.email });
        req.user = user;
        next();
    });
}
app.get('/view-applicants/:_id', authenticateToken, async (req, res) => {
    try {
        const jobId = req.params._id;
        console.log("JOB ID:",jobId)
        const job = await Job.findById(jobId).populate('applicants').exec();
        console.log("JOB:",job)
        console.log("APPLICANT: ",job.applicants.length)
        if (!job) return res.status(404).send('Job not found');

        // Check if the logged-in user is the recruiter who posted the job
        if (job.postedBy.toString() !== req.user.userId.toString()) {
            return res.status(403).send('You are not authorized to view the applicants for this job.');
        }

        // Fetch Details for each applicant
        const applicantsWithDetails = await Promise.all(job.applicants.map(async (user) => {
            const details = await Details.findOne({ email: user.email });
            return { 
                name: user.name, 
                email: user.email, 
                education: details ? details.education : null, 
                skills: details && Array.isArray(details.skills) 
                ? details.skills.map(skill => skill.trim()) 
                : []
            };
        }));

        // Render a view to display the applicants
        res.render('viewapplicants', { job: job, applicants: applicantsWithDetails });
        

    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});



app.listen(PORT, () => {
    console.log(`server is running on ${PORT}`)
});