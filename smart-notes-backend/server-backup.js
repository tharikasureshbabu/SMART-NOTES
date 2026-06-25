const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fetch = require('node-fetch');

// Load environment variables
dotenv.config();

const app = express();

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
app.post('/api/generate-summary', authMiddleware, async (req, res) => {
  try {
    const { content } = req.body;

    if (!content || !content.trim()) {
      return res.status(400).json({ message: 'Content is required' });
    }

    // ── 1. Split into clean sentences ──────────────────────────
    const rawSentences = content
      .replace(/\n+/g, ' ')
      .split(/(?<=[.!?])\s+/)
      .map(s => s.trim())
      .filter(s => s.length > 8);

    if (rawSentences.length === 0) {
      return res.json({
        summary: '# 📚 Summary\n\n## 📖 Content\n• ' + content.trim(),
        keywords: []
      });
    }

    // ── 2. Extract keywords ────────────────────────────────────
    const stopWords = new Set([
      'the','is','are','was','were','and','or','but','in','on','at','to',
      'for','of','with','a','an','this','that','it','its','they','them',
      'their','have','has','had','be','been','being','do','does','did',
      'will','would','could','should','may','might','can','from','by',
      'as','into','through','also','which','when','where','who','how',
      'what','there','these','those','than','then','so','if','about',
      'each','both','more','very','just','some','such','after','before',
      'between','during','without','over','under','again','further','once'
    ]);

    const wordFreq = {};
    content.toLowerCase()
      .replace(/[^\w\s]/g, '')
      .split(/\s+/)
      .filter(w => w.length > 3 && !stopWords.has(w))
      .forEach(w => { wordFreq[w] = (wordFreq[w] || 0) + 1; });

    const keywords = Object.entries(wordFreq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([word]) => word.charAt(0).toUpperCase() + word.slice(1));

    // ── 3. Detect main topic from first sentence ───────────────
    const firstWords = rawSentences[0].split(' ').slice(0, 7).join(' ');
    const mainHeading = firstWords.length > 4
      ? firstWords.replace(/[.!?,]$/, '')
      : 'Note Summary';

    // ── 4. Build sections ──────────────────────────────────────
    const total = rawSentences.length;
    let structured = '';

    // Main heading
    structured += `# 📚 ${mainHeading}\n\n`;

    // Overview — first 1-2 sentences
    structured += `## 📖 Overview\n`;
    rawSentences.slice(0, Math.min(2, total)).forEach(s => {
      structured += `• ${s}\n`;
    });
    structured += '\n';

    // Key Points — middle sentences
    if (total > 2) {
      const midStart = 2;
      const midEnd = Math.min(total - 1, 7);
      const midSentences = rawSentences.slice(midStart, midEnd);
      if (midSentences.length > 0) {
        structured += `## 🔍 Key Points\n`;
        midSentences.forEach(s => {
          structured += `• ${s}\n`;
        });
        structured += '\n';
      }
    }

    // Important Details — sentences with numbers or key terms
    const importantSentences = rawSentences.filter(s =>
      /\d+|first|second|third|important|key|main|primary|major|because|therefore|however|although/i.test(s)
    ).slice(0, 4);

    if (importantSentences.length > 0) {
      structured += `## 💡 Important Details\n`;
      importantSentences.forEach(s => {
        structured += `• ${s}\n`;
      });
      structured += '\n';
    }

    // Conclusion — last sentence
    if (total > 3) {
      const lastSentence = rawSentences[total - 1];
      if (lastSentence && lastSentence.trim()) {
        structured += `## 🎯 Conclusion\n`;
        structured += `• ${lastSentence}\n\n`;
      }
    }

    // Keywords section
    if (keywords.length > 0) {
      structured += `## 🔑 Keywords\n`;
      keywords.forEach(kw => {
        structured += `• ${kw}\n`;
      });
    }

    console.log('✅ Summary generated successfully');

    res.json({
      summary: structured,
      keywords: keywords
    });

  } catch (error) {
    console.error('Generate summary error:', error);
    res.status(500).json({
      message: 'Error generating summary',
      summary: '# Summary Error\n\n## ⚠️ Error\n• Could not generate summary. Please try again.',
      keywords: []
    });
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

    // Read file
    const fileData = fs.readFileSync(filePath);

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