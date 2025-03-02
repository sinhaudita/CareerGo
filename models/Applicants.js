const mongoose = require('mongoose');

const applicantSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    // unique: true
  },

  appliedAt: {
    type: Date,
    default: Date.now
  },
  skills:{
    type: [String],
    required: true,
},
  // applicantId: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User'}],
  // postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  // jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'Job' },
  appliedJobs: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Job'
}],
postedJobs: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Job'
}]
});

module.exports = mongoose.model('Applicant', applicantSchema);
