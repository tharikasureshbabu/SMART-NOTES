const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
    required: [true, 'Please provide a title'],
    trim: true,
  },
  content: {
    type: String,
    required: [true, 'Please provide content'],
  },
  category: {
    type: String,
    default: 'General',
    enum: ['General', 'Math', 'Science', 'History', 'Literature', 'Programming', 'Languages', 'Other'],
  },
  source: {
    type: String,
    default: 'text',
    enum: ['text', 'voice', 'video', 'screen'],
  },
  tags: [{
    type: String,
  }],
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

// Update the updatedAt timestamp before saving
noteSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Note', noteSchema);