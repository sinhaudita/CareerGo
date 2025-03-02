// models/Job.js
const mongoose = require('mongoose');

const jobSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    company: {
        type: String,
        required: true,
    },
    location: {
        type: String,
        required: true,
    },
    salary: {
        type: Number,
        required: false,
    },
    skills:{
        type: [String],
        required: true,
    },
    deadline: {
        type: Date,
        required:true,
    },
    postedBy: { 
        type: mongoose.Schema.Types.ObjectId,
         ref: 'User'
     },
     applicants: [{ 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User' 
      }],
    recruiterId: {
        type:mongoose.Schema.Types.ObjectId,
        ref: 'User' 
    }
});

const Job = mongoose.model('Job', jobSchema);

module.exports = Job;