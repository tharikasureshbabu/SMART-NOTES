const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fetch = require('node-fetch');
const ffmpeg = require('fluent-ffmpeg');

// Load environment variables
dotenv.config();

const app = express();

// ==================== STOP WORDS FOR SUMMARY ====================
const STOP_WORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
  'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been',
  'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
  'should', 'could', 'may', 'might', 'must', 'can', 'this', 'that',
  'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'them',
  'their', 'what', 'which', 'who', 'when', 'where', 'why', 'how', 'all',
  'each', 'every', 'both', 'few', 'more', 'most', 'other', 'some', 'such',
  'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very',
  'just', 'about', 'into', 'through', 'during', 'before', 'after', 'above',
  'below', 'between', 'under', 'again', 'further', 'then', 'once'
]);

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== FILE UPLOAD SETUP ====================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
});

// ==================== DATABASE MODELS ====================

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  lastLogin: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model('User', userSchema);

// Note Schema
const noteSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
    required: true,
    trim: true,
  },
  content: {
    type: String,
    required: true,
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
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const Note = mongoose.model('Note', noteSchema);

// ==================== AUTH MIDDLEWARE ====================
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const token = authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : authHeader;

    if (!token) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    
    res.status(500).json({ message: 'Server error in authentication' });
  }
};

// ==================== DATABASE CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/smart-notes';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch((err) => console.error('❌ MongoDB connection error:', err));

// ==================== AUTHENTICATION ROUTES ====================

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Please provide all required fields' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
    });

    await user.save();

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password' });
    }

    // Check if user exists
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// ==================== NOTES ROUTES (PROTECTED) ====================

// @route   GET /api/notes
// @desc    Get all notes for authenticated user
// @access  Private
app.get('/api/notes', authMiddleware, async (req, res) => {
  try {
    const { category, search } = req.query;
    
    // Build query
    let query = { user: req.userId };
    
    if (category && category !== 'All') {
      query.category = category;
    }
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { content: { $regex: search, $options: 'i' } },
      ];
    }
    
    const notes = await Note.find(query).sort({ updatedAt: -1 });
    res.json(notes);
  } catch (error) {
    console.error('Get notes error:', error);
    res.status(500).json({ message: 'Error fetching notes' });
  }
});

// @route   GET /api/notes/:id
// @desc    Get single note
// @access  Private
app.get('/api/notes/:id', authMiddleware, async (req, res) => {
  try {
    const note = await Note.findOne({ 
      _id: req.params.id, 
      user: req.userId 
    });
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    res.json(note);
  } catch (error) {
    console.error('Get note error:', error);
    res.status(500).json({ message: 'Error fetching note' });
  }
});

// @route   POST /api/notes
// @desc    Create note
// @access  Private
app.post('/api/notes', authMiddleware, async (req, res) => {
  try {
    const { title, content, category, source } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ message: 'Title and content are required' });
    }
    
    const note = new Note({
      user: req.userId,
      title,
      content,
      category: category || 'General',
      source: source || 'text',
    });
    
    await note.save();
    res.status(201).json(note);
  } catch (error) {
    console.error('Create note error:', error);
    res.status(500).json({ message: 'Error creating note' });
  }
});

// @route   PUT /api/notes/:id
// @desc    Update note
// @access  Private
app.put('/api/notes/:id', authMiddleware, async (req, res) => {
  try {
    const { title, content, category, source } = req.body;
    
    const note = await Note.findOne({ 
      _id: req.params.id, 
      user: req.userId 
    });
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    note.title = title || note.title;
    note.content = content || note.content;
    note.category = category || note.category;
    note.source = source || note.source;
    note.updatedAt = Date.now();
    
    await note.save();
    res.json(note);
  } catch (error) {
    console.error('Update note error:', error);
    res.status(500).json({ message: 'Error updating note' });
  }
});

// @route   DELETE /api/notes/:id
// @desc    Delete note
// @access  Private
app.delete('/api/notes/:id', authMiddleware, async (req, res) => {
  try {
    const note = await Note.findOneAndDelete({ 
      _id: req.params.id, 
      user: req.userId 
    });
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    res.json({ message: 'Note deleted successfully' });
  } catch (error) {
    console.error('Delete note error:', error);
    res.status(500).json({ message: 'Error deleting note' });
  }
});

// ==================== VIDEO UPLOAD ====================
// @route   POST /api/upload-video
// @desc    Upload video
// @access  Private
app.post('/api/upload-video', authMiddleware, upload.single('video'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No video file uploaded' });
    }
    
    res.json({ 
      message: 'Video uploaded successfully',
      filename: req.file.filename,
      path: req.file.path,
    });
  } catch (error) {
    console.error('Video upload error:', error);
    res.status(500).json({ message: 'Error uploading video' });
  }
});

// ==================== AI FEATURES ====================

// @route   POST /api/generate-summary
// @desc    Generate structured smart summary with headings and bullet points
// @access  Private
const Anthropic = require('@anthropic-ai/sdk');

// @route   POST /api/generate-summary
// @desc    Generate smart summary using Claude AI
// @access  Private
app.post('/api/generate-summary', authMiddleware, async (req, res) => {
  try {
    const { content } = req.body;

    if (!content || !content.trim()) {
      return res.status(400).json({ message: 'Content is required' });
    }

    const anthropic = new Anthropic({
      apiKey: process.env.ANTHROPIC_API_KEY,
    });

    const message = await anthropic.messages.create({
      model: 'claude-haiku-4-5-20251001', // fast + cheap
      max_tokens: 1024,
      messages: [
        {
          role: 'user',
          content: `You are a smart note-taking assistant. Analyze the following transcript/content and generate a structured summary.

The content may be from a math lecture, science class, history lesson, programming tutorial, or any other topic. You MUST detect the actual topic and summarize accordingly — include formulas, examples, steps, or key facts that are actually present in the content.

Format your response EXACTLY like this (use these exact symbols):
# 📚 [Actual Topic Title Here]

## 📖 Overview
- [1-2 sentence summary of what this content is actually about]

## 🔍 Key Points
- [key point 1 from the actual content]
- [key point 2]
- [key point 3]
- [add more as needed]

## 💡 Important Details
- [formulas, examples, steps, definitions, or facts from the content]
- [another important detail]

## 🎯 Conclusion
- [main takeaway from this specific content]

## 🔑 Keywords
- [keyword1]
- [keyword2]
- [keyword3]

Here is the content to summarize:

${content.substring(0, 8000)}`
        }
      ],
    });

    const summary = message.content[0].text;

    if (!summary?.trim()) {
      return res.status(500).json({ message: 'Summary was empty. Please try again.' });
    }

    console.log('✅ Claude AI summary generated successfully');
    res.json({ summary });

  } catch (error) {
    console.error('Generate summary error:', error);

    // Fallback to basic summary if Claude API fails
    const { content } = req.body;
    const sentences = content
      .replace(/\n+/g, ' ')
      .split(/(?<=[.!?])\s+/)
      .map(s => s.trim())
      .filter(s => s.length > 8)
      .slice(0, 6);

    const fallback = `# 📚 Summary\n\n## 📖 Key Points\n${sentences.map(s => `• ${s}`).join('\n')}\n\n## ⚠️ Note\n• Claude AI unavailable — showing basic summary. Check your ANTHROPIC_API_KEY.`;

    res.json({ summary: fallback });
  }
});
// @route   POST /api/chat
// @desc    AI Chat assistant
// @access  Private
app.post('/api/chat', authMiddleware, async (req, res) => {
  try {
    const { question, allNotes } = req.body;
    
    if (!question) {
      return res.status(400).json({ message: 'Question is required' });
    }
    
    // Simple response (you can replace with AI API like OpenAI, Claude, etc.)
    let response = '';
    
    if (allNotes && allNotes.length > 0) {
      const noteCount = allNotes.length;
      const categories = [...new Set(allNotes.map(n => n.category))];
      
      response = `I can see you have ${noteCount} note(s) across ${categories.length} categor${categories.length > 1 ? 'ies' : 'y'}: ${categories.join(', ')}. `;
      
      if (question.toLowerCase().includes('how many')) {
        response += `You have ${noteCount} total notes.`;
      } else if (question.toLowerCase().includes('category') || question.toLowerCase().includes('categories')) {
        response += `Your notes are organized in: ${categories.join(', ')}.`;
      } else {
        response += `Your question was: "${question}". This is a basic response. For advanced AI features, integrate OpenAI or Anthropic Claude API.`;
      }
    } else {
      response = `You don't have any notes yet. Start by creating your first note! Your question was: "${question}"`;
    }
    
    res.json({ response });
    
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ 
      message: 'Error processing chat',
      response: 'Sorry, I encountered an error. Please try again.'
    });
  }
});

// ==================== HEALTH CHECK ====================
// ==================== TRANSLATE ====================
// @route   POST /api/translate
// @desc    Proxy translation via MyMemory API (avoids browser CORS)
// @access  Private
app.post('/api/translate', authMiddleware, async (req, res) => {
  try {
    const { text, from, to } = req.body;
    if (!text || !from || !to) return res.status(400).json({ message: 'text, from, and to are required' });

    // Split text into sentences for structured translation
    const sentences = text.trim()
      .replace(/\n+/g, ' ')
      .split(/(?<=[.!?])\s+/)
      .map(s => s.trim())
      .filter(s => s.length > 3);

    // Translate each sentence individually (max 8 sentences, 500 chars each)
    const toTranslate = sentences.slice(0, 8);
    const translated = [];

    for (const sentence of toTranslate) {
      const chunk = sentence.substring(0, 400);
      const url = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(chunk)}&langpair=${encodeURIComponent(`${from}|${to}`)}`;
      const response = await fetch(url);
      const data = await response.json();
      const result = data?.responseData?.translatedText;
      if (result && !result.toUpperCase().includes('INVALID LANGUAGE')) {
        translated.push(result.trim());
      }
    }

    if (translated.length === 0) {
      return res.status(400).json({ message: 'Translation failed. Try a different language pair.' });
    }

    // Build structured output like smart summary
    const LANG_NAMES = {
      en:'English',ta:'Tamil',hi:'Hindi',es:'Spanish',fr:'French',
      de:'German',zh:'Chinese',ar:'Arabic',ja:'Japanese',pt:'Portuguese',
      ru:'Russian',ko:'Korean',it:'Italian',te:'Telugu',ml:'Malayalam',kn:'Kannada'
    };
    const toLang = LANG_NAMES[to] || to.toUpperCase();
    const fromLang = LANG_NAMES[from] || from.toUpperCase();

    // Chunk into groups of 3 for sections
    let structured = `# 🌐 Translation (${fromLang} → ${toLang})\n\n`;

    if (translated.length <= 3) {
      structured += `## 📝 Translated Content\n`;
      translated.forEach(t => { structured += `• ${t}\n`; });
    } else {
      // Overview: first 2
      structured += `## 📖 Opening\n`;
      translated.slice(0, 2).forEach(t => { structured += `• ${t}\n`; });
      structured += '\n';

      // Middle content
      const mid = translated.slice(2, translated.length - 1);
      if (mid.length > 0) {
        structured += `## 🔍 Main Content\n`;
        mid.forEach(t => { structured += `• ${t}\n`; });
        structured += '\n';
      }

      // Last sentence as conclusion
      structured += `## 🎯 Closing\n`;
      structured += `• ${translated[translated.length - 1]}\n`;
    }

    res.json({ structured, from, to, original: text.trim() });

  } catch (error) {
    console.error('Translation error:', error.message);
    res.status(500).json({ message: 'Translation failed: ' + error.message });
  }
});

// ==================== SMART SUMMARY ENDPOINT ====================
// @route   POST /api/summarize
// @desc    Generate intelligent summary with meaningful keywords
// @access  Private (requires authentication)
app.post('/api/summarize', authMiddleware, async (req, res) => {
  try {
    const { content } = req.body;
    
    if (!content || content.trim().length < 50) {
      return res.status(400).json({ message: 'Content too short to summarize (minimum 50 characters)' });
    }

    console.log('📝 Generating smart summary...');
    console.log('   Content length:', content.length, 'characters');

    // ── STEP 1: Extract Sentences ──
    const sentences = content
      .split(/[.!?]+/)
      .map(s => s.trim())
      .filter(s => s.length > 15 && s.split(' ').length > 3);

    console.log('   Sentences found:', sentences.length);

    if (sentences.length < 3) {
      return res.status(400).json({ message: 'Content too short - need at least 3 sentences' });
    }

    // ── STEP 2: Extract Meaningful Keywords ──
    const words = content.toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 3 && !STOP_WORDS.has(w));

    // Calculate word frequency
    const freq = {};
    words.forEach(w => freq[w] = (freq[w] || 0) + 1);

    // Get top keywords (appearing multiple times OR long words)
    const keywords = Object.entries(freq)
      .filter(([word, count]) => count > 1 || word.length > 6)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([word]) => word.charAt(0).toUpperCase() + word.slice(1));

    console.log('   Keywords extracted:', keywords.length);

    // ── STEP 3: Score Sentences ──
    const scoredSentences = sentences.map((s, idx) => {
      const lower = s.toLowerCase();
      let score = 0;
      
      // +1 for each keyword mention
      keywords.forEach(k => {
        const count = (lower.match(new RegExp(k.toLowerCase(), 'g')) || []).length;
        score += count;
      });
      
      // +3 for numbers, dates, statistics (important facts)
      const numMatches = s.match(/\d+/g);
      if (numMatches) score += numMatches.length * 3;
      
      // +3 for first sentence (usually important)
      if (idx === 0) score += 3;
      
      // +2 for last sentence (conclusion)
      if (idx === sentences.length - 1) score += 2;
      
      // +1 for sentences with quotation marks
      if (/["']/.test(s)) score += 1;
      
      // -2 for very short sentences
      if (s.split(' ').length < 5) score -= 2;
      
      // +2 for important signal words
      const importantWords = ['important', 'significant', 'key', 'main', 'critical', 'essential', 'crucial'];
      if (importantWords.some(w => lower.includes(w))) score += 2;
      
      return { sentence: s, score, index: idx };
    });

    // ── STEP 4: Select Best Sentences ──
    const numSummary = Math.max(3, Math.ceil(sentences.length * 0.3)); // 30% of content
    const topSentences = scoredSentences
      .sort((a, b) => b.score - a.score)
      .slice(0, numSummary)
      .sort((a, b) => a.index - b.index) // Restore original order
      .map(s => s.sentence);

    console.log('   Top sentences selected:', topSentences.length);

    // ── STEP 5: Extract Key Facts (sentences with numbers) ──
    const factsWithNumbers = scoredSentences
      .filter(s => /\d+/.test(s.sentence) && s.score >= 3)
      .sort((a, b) => b.score - a.score)
      .slice(0, 4)
      .map(s => s.sentence);

    // ── STEP 6: Build Structured Summary ──
    const summary = `# 📋 Smart Summary

## 🔑 Key Topics
${keywords.slice(0, 6).map(k => `• ${k}`).join('\n')}

## 📌 Main Points
${topSentences.slice(0, 4).map((s, i) => `**${i + 1}.** ${s}.`).join('\n\n')}

${factsWithNumbers.length > 0 ? `## 📊 Important Facts\n${factsWithNumbers.map(s => `• ${s}.`).join('\n')}\n` : ''}
## 💡 Key Takeaway
${topSentences[topSentences.length - 1] || sentences[sentences.length - 1]}.
`;

    console.log('✅ Summary generated successfully');
    res.json({ summary });

  } catch (error) {
    console.error('❌ Summary generation error:', error);
    res.status(500).json({ message: 'Summary generation failed: ' + error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Server is running',
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '⏳ Connecting...'}`);
});

module.exports = app;

// @route   POST /api/transcribe
// @desc    Transcribe audio/video file using AssemblyAI free API
// @access  Private
app.post('/api/transcribe', authMiddleware, upload.single('file'), async (req, res) => {
  const fs = require('fs');
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { language } = req.body;
    const filePath = path.join(__dirname, req.file.path);
    const fileSize = fs.statSync(filePath).size;

    // Map our language codes to AssemblyAI's expected format
    // AssemblyAI supports: en, es, fr, de, it, pt, nl, hi, ja, zh, fi, ko, pl, ru, tr, uk, vi, etc.
    // For unsupported languages or if unsure, use auto-detection (don't send language_code)
    const languageMap = {
      'en': 'en',
      'es': 'es', 
      'fr': 'fr',
      'de': 'de',
      'it': 'it',
      'pt': 'pt',
      'hi': 'hi',
      'ja': 'ja',
      'zh': 'zh',
      'ru': 'ru',
      'ko': 'ko',
      // Tamil, Telugu, Malayalam, Kannada - use auto-detect
      'ta': null,  // auto-detect
      'te': null,  // auto-detect
      'ml': null,  // auto-detect
      'kn': null,  // auto-detect
      'ar': null,  // auto-detect (AssemblyAI might support, but safer to auto-detect)
    };
    
    const assemblyLang = languageMap[language] || null;

    console.log('📝 Transcription request:');
    console.log('  - File:', req.file.originalname);
    console.log('  - Size:', (fileSize / 1024 / 1024).toFixed(2), 'MB');
    console.log('  - Language requested:', language || 'auto');
    console.log('  - Language sent to API:', assemblyLang || 'auto-detect');
    console.log('  - API Key present:', !!process.env.ASSEMBLYAI_API_KEY);

    // Check API key
    if (!process.env.ASSEMBLYAI_API_KEY) {
      fs.unlinkSync(filePath);
      return res.status(500).json({ 
        message: 'AssemblyAI API key not configured. Add ASSEMBLYAI_API_KEY to your .env file. See ENV_SETUP.md' 
      });
    }

    // ── AUDIO BOOSTING FOR LOW-VOLUME RECORDINGS ──
    let fileToUpload = filePath;
    const isVideoFile = req.file.mimetype.startsWith('video/') || 
                        req.file.originalname.endsWith('.webm') ||
                        req.file.originalname.endsWith('.mp4');

    if (isVideoFile) {
      console.log('🎬 Video file detected - extracting and boosting audio...');
      const audioPath = filePath.replace(path.extname(filePath), '-enhanced.wav');
      
      try {
        await new Promise((resolve, reject) => {
          ffmpeg(filePath)
            .noVideo()  // Extract audio only
            .audioFilters([
              'highpass=f=200',                    // Remove low-frequency noise (below 200Hz)
              'lowpass=f=3000',                    // Remove high-frequency noise (above 3000Hz)
              'volume=5.0',                        // Boost volume by 5x (increased from 3x)
              'loudnorm=I=-14:LRA=9:TP=-1.0',     // More aggressive loudness normalization
              'afftdn=nf=-25'                      // Denoise filter
            ])
            .audioFrequency(16000) // 16kHz is optimal for speech recognition
            .audioChannels(1)      // Mono audio
            .outputFormat('wav')
            .on('end', () => {
              console.log('✅ Audio extracted and enhanced');
              resolve();
            })
            .on('error', (err) => {
              console.error('❌ FFmpeg error:', err.message);
              reject(err);
            })
            .save(audioPath);
        });

        // Use enhanced audio file instead
        fileToUpload = audioPath;
        console.log('  - Original:', (fs.statSync(filePath).size / 1024 / 1024).toFixed(2), 'MB');
        console.log('  - Enhanced:', (fs.statSync(audioPath).size / 1024 / 1024).toFixed(2), 'MB');
      } catch (ffmpegError) {
        console.warn('⚠️ Audio enhancement failed, using original file:', ffmpegError.message);
        // Continue with original file if FFmpeg fails
      }
    }

    // Read file (original or enhanced)
    const fileData = fs.readFileSync(fileToUpload);

    // Upload to AssemblyAI
    console.log('⬆️ Uploading file to AssemblyAI...');
    const uploadRes = await fetch('https://api.assemblyai.com/v2/upload', {
      method: 'POST',
      headers: {
        'authorization': process.env.ASSEMBLYAI_API_KEY,
        'Content-Type': 'application/octet-stream',
      },
      body: fileData
    });

    if (!uploadRes.ok) {
      const errorText = await uploadRes.text();
      console.error('❌ AssemblyAI upload failed:', uploadRes.status, errorText);
      fs.unlinkSync(filePath);
      if (fileToUpload !== filePath) fs.unlinkSync(fileToUpload);  // Clean up enhanced file
      return res.status(500).json({ 
        message: `Upload failed: ${uploadRes.status} ${uploadRes.statusText}. Check your API key.` 
      });
    }

    const uploadData = await uploadRes.json();
    const upload_url = uploadData.upload_url;
    console.log('✅ File uploaded to:', upload_url);

    // Request transcription
    console.log('🎯 Requesting transcription...');
    
    const transcriptBody = { 
      audio_url: upload_url,
      speech_models: ['universal-2']  // Must be 'universal-2' or 'universal-3-pro'
    };
    
    // Only add language_code if we have a supported one (otherwise AssemblyAI auto-detects)
    if (assemblyLang) {
      transcriptBody.language_code = assemblyLang;
    }
    
    console.log('📤 Request body:', JSON.stringify(transcriptBody, null, 2));
    
    const transcriptRes = await fetch('https://api.assemblyai.com/v2/transcript', {
      method: 'POST',
      headers: {
        'authorization': process.env.ASSEMBLYAI_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(transcriptBody)
    });

    if (!transcriptRes.ok) {
      const errorText = await transcriptRes.text();
      console.error('❌ Transcription request failed:', transcriptRes.status, errorText);
      fs.unlinkSync(filePath);
      return res.status(500).json({ 
        message: `Transcription request failed: ${transcriptRes.status} - ${errorText}` 
      });
    }

    const transcriptData = await transcriptRes.json();
    const transcriptId = transcriptData.id;
    
    if (!transcriptId) {
      console.error('❌ No transcript ID returned:', transcriptData);
      fs.unlinkSync(filePath);
      return res.status(500).json({ 
        message: 'Invalid response from transcription service' 
      });
    }

    console.log('⏳ Transcription started, ID:', transcriptId);
    console.log('   Polling every 3 seconds (max 10 minutes)...');

    // Poll for completion
    let attempts = 0;
    const maxAttempts = 200; // 10 minutes

    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 3000));

      const statusRes = await fetch(`https://api.assemblyai.com/v2/transcript/${transcriptId}`, {
        headers: { 'authorization': process.env.ASSEMBLYAI_API_KEY }
      });

      const status = await statusRes.json();
      
      console.log(`   Attempt ${attempts + 1}/${maxAttempts}: ${status.status}`);

      if (status.status === 'completed') {
        fs.unlinkSync(filePath);
        // Also delete enhanced audio file if it exists
        const enhancedPath = filePath.replace(path.extname(filePath), '-enhanced.wav');
        if (fs.existsSync(enhancedPath)) {
          fs.unlinkSync(enhancedPath);
          console.log('🗑️ Cleaned up enhanced audio file');
        }
        console.log('✅ Transcription complete!');
        console.log('   Words:', status.text?.split(' ').length || 0);
        return res.json({ 
          transcript: status.text || '', 
          language: language || 'en',
          words: status.text?.split(' ').length || 0
        });
      } else if (status.status === 'error') {
        fs.unlinkSync(filePath);
        console.error('❌ AssemblyAI error:', status.error);
        return res.status(500).json({ 
          message: 'Transcription error: ' + (status.error || 'Unknown error') 
        });
      }

      attempts++;
    }

    fs.unlinkSync(filePath);
    console.error('❌ Transcription timeout after', maxAttempts * 3, 'seconds');
    res.status(500).json({ message: 'Transcription timeout. File may be too long or service is slow.' });

  } catch (error) {
    console.error('💥 Transcription error:', error.message);
    console.error('   Stack:', error.stack);
    if (req.file && fs.existsSync(path.join(__dirname, req.file.path))) {
      fs.unlinkSync(path.join(__dirname, req.file.path));
    }
    res.status(500).json({ message: 'Server error: ' + error.message });
  }
});


// @route   GET /api/tts
// @desc    Proxy Google Translate TTS to avoid CORS
// @access  Public (no auth needed for TTS)
app.get('/api/tts', async (req, res) => {
  try {
    const { text, lang } = req.query;
    if (!text || !lang) {
      return res.status(400).json({ message: 'text and lang parameters required' });
    }

    const cleanText = text.substring(0, 200); // Limit to 200 chars
    const url = `https://translate.google.com/translate_tts?ie=UTF-8&tl=${lang}&client=tw-ob&q=${encodeURIComponent(cleanText)}`;
    
    const response = await fetch(url);
    
    if (!response.ok) {
      return res.status(500).json({ message: 'TTS service unavailable' });
    }

    // Forward the audio stream
    res.setHeader('Content-Type', 'audio/mpeg');
    response.body.pipe(res);

  } catch (error) {
    console.error('TTS error:', error);
    res.status(500).json({ message: 'TTS failed: ' + error.message });
  }
});