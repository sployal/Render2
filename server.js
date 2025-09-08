require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cors = require('cors');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const cloudinary = require('cloudinary').v2;
const validator = require('validator');

// Initialize Express
const app = express();
const PORT = process.env.PORT || 5000;

// Security: Configure Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Security: Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 uploads per hour
  message: { error: 'Upload limit exceeded, please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 failed auth attempts per 15 minutes
  skipSuccessfulRequests: true,
  message: { error: 'Too many authentication attempts, please try again later.' },
});

// Apply rate limiting
app.use(generalLimiter);

// Configure Cloudinary with validation
const validateCloudinaryConfig = () => {
  const { CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET } = process.env;
  
  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
    throw new Error('Missing Cloudinary configuration');
  }
  
  cloudinary.config({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET,
    secure: true, // Force HTTPS
  });
};

// Configure Supabase with validation
const validateSupabaseConfig = () => {
  const { SUPABASE_URL, SUPABASE_ANON_KEY } = process.env;
  
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    throw new Error('Missing Supabase configuration');
  }
  
  if (!validator.isURL(SUPABASE_URL)) {
    throw new Error('Invalid Supabase URL format');
  }
  
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  });
};

let supabase;
try {
  validateCloudinaryConfig();
  supabase = validateSupabaseConfig();
  console.log('✅ Configuration validated successfully');
} catch (error) {
  console.error('❌ Configuration error:', error.message);
  process.exit(1);
}

// Security: Configure CORS properly
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.ALLOWED_ORIGINS?.split(',') || []
    : true, // Allow all origins in development
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false,
  maxAge: 86400, // 24 hours
};

app.use(cors(corsOptions));

// Security: Configure Multer with strict validation
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1, // Only one file at a time
    fieldSize: 1024 * 1024, // 1MB for text fields
  },
  fileFilter: (req, file, cb) => {
    // Strict MIME type checking
    const allowedMimeTypes = [
      'image/jpeg',
      'image/jpg', 
      'image/png',
      'image/webp'
    ];
    
    if (!allowedMimeTypes.includes(file.mimetype)) {
      return cb(new Error('Invalid file type. Only JPEG, PNG, and WebP are allowed.'), false);
    }
    
    // Additional file extension validation
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp'];
    const fileExtension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
    
    if (!allowedExtensions.includes(fileExtension)) {
      return cb(new Error('Invalid file extension.'), false);
    }
    
    cb(null, true);
  },
});

// Middleware
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security: Input validation helpers
const validatePostInput = (data) => {
  const errors = [];
  
  if (!data.caption || typeof data.caption !== 'string') {
    errors.push('Caption is required and must be a string');
  } else if (data.caption.length > 2200) {
    errors.push('Caption must be less than 2200 characters');
  }
  
  if (data.location && (typeof data.location !== 'string' || data.location.length > 100)) {
    errors.push('Location must be a string less than 100 characters');
  }
  
  if (data.tags) {
    if (!Array.isArray(data.tags)) {
      errors.push('Tags must be an array');
    } else if (data.tags.length > 10) {
      errors.push('Maximum 10 tags allowed');
    } else {
      const invalidTags = data.tags.filter(tag => 
        typeof tag !== 'string' || 
        tag.length > 50 || 
        !/^[a-zA-Z0-9_]+$/.test(tag)
      );
      if (invalidTags.length > 0) {
        errors.push('Tags must be alphanumeric strings less than 50 characters');
      }
    }
  }
  
  return errors;
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return validator.escape(input.trim());
};

// Authentication middleware with rate limiting
const authenticateUser = async (req, res, next) => {
  // Apply auth rate limiting
  authLimiter(req, res, async (err) => {
    if (err) return next(err);
    
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
          success: false,
          error: 'Access token required in Bearer format' 
        });
      }
      
      const token = authHeader.substring(7); // Remove 'Bearer ' prefix
      
      if (!token || token.length < 10) {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid token format' 
        });
      }

      const { data: { user }, error } = await supabase.auth.getUser(token);

      if (error || !user) {
        return res.status(403).json({ 
          success: false,
          error: 'Invalid or expired token' 
        });
      }

      req.user = user;
      next();
    } catch (error) {
      console.error('Auth error:', error);
      res.status(500).json({ 
        success: false,
        error: 'Authentication failed' 
      });
    }
  });
};

// Helper function to get user display info
const getUserInfo = (user) => {
  const metadata = user.user_metadata || {};
  const rawMetadata = user.raw_user_meta_data || {};
  
  return {
    username: sanitizeInput(
      metadata.username || 
      rawMetadata.username || 
      user.email?.split('@')[0] || 
      'user'
    ),
    isVerified: Boolean(metadata.is_verified || rawMetadata.is_verified),
    userType: sanitizeInput(
      metadata.user_type || 
      rawMetadata.user_type || 
      'Photography Enthusiast'
    )
  };
};

// Helper function to upload to Cloudinary with security
const uploadToCloudinary = async (buffer, options = {}) => {
  return new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: 'photography_posts',
      resource_type: 'image',
      format: 'webp', // Convert to WebP for better compression
      transformation: [
        { width: 1200, height: 1200, crop: 'limit' },
        { quality: 'auto:good' },
        { fetch_format: 'auto' }
      ],
      flags: 'sanitize', // Remove potentially harmful metadata
      ...options
    };

    cloudinary.uploader.upload_stream(
      uploadOptions,
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          reject(new Error('Image upload failed'));
        } else {
          resolve(result);
        }
      }
    ).end(buffer);
  });
};

// Helper function to format post data safely
const formatPost = (post, userInfo = null) => {
  return {
    id: post.id,
    userId: post.user_id,
    userName: userInfo?.username || 'unknown',
    imageUrl: post.image_url,
    caption: post.caption,
    location: post.location,
    likes: parseInt(post.likes) || 0,
    commentCount: parseInt(post.comment_count) || 0,
    tags: Array.isArray(post.tags) ? post.tags : [],
    createdAt: post.created_at,
    isVerified: Boolean(userInfo?.isVerified),
    userType: userInfo?.userType || 'Photography Enthusiast',
    isFeatured: Boolean(post.is_featured)
  };
};

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'OK',
    message: 'Photography API is running',
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'OK',
    message: 'Photography API is running',
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// Get all posts with enhanced validation
app.get('/api/posts', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 50); // Cap at 50
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const offset = (page - 1) * limit;
    const sort = req.query.sort === 'oldest' ? 'oldest' : 'newest';
    
    // Validate user_id if provided
    const userId = req.query.user_id;
    if (userId && !validator.isUUID(userId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid user ID format'
      });
    }

    let query = supabase
      .from('posts')
      .select(`
        *,
        post_tags (
          tags (name)
        )
      `, { count: 'exact' });

    // Filter by user if specified
    if (userId) {
      query = query.eq('user_id', userId);
    }

    // Sort order
    query = query.order('created_at', { ascending: sort === 'oldest' });
    
    // Pagination
    query = query.range(offset, offset + limit - 1);

    const { data, error, count } = await query;

    if (error) {
      console.error('Database error:', error);
      throw new Error('Failed to fetch posts from database');
    }

    // Get user info for each post with error handling
    const postsWithUserInfo = await Promise.all(
      (data || []).map(async (post) => {
        try {
          const { data: userData, error: userError } = await supabase.auth.admin.getUserById(post.user_id);
          
          if (userError) {
            console.warn(`Failed to get user info for ${post.user_id}:`, userError);
          }
          
          const userInfo = userData?.user ? getUserInfo(userData.user) : null;
          const tags = post.post_tags?.map(pt => pt.tags?.name).filter(Boolean) || [];
          
          return formatPost({ ...post, tags }, userInfo);
        } catch (err) {
          console.error('Error processing post:', err);
          return formatPost({ ...post, tags: [] });
        }
      })
    );

    res.json({
      success: true,
      posts: postsWithUserInfo,
      pagination: {
        total: count || 0,
        limit,
        page,
        totalPages: Math.ceil((count || 0) / limit)
      }
    });
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch posts' 
    });
  }
});

// Updated image upload endpoint to match your Flutter app
app.post('/api/upload-images', authenticateUser, uploadLimiter, upload.array('images', 5), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No image files provided'
      });
    }

    const uploadPromises = req.files.map(file => 
      uploadToCloudinary(file.buffer, {
        public_id: `post_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        tags: ['post', req.user.id]
      })
    );

    const results = await Promise.all(uploadPromises);
    const imageUrls = results.map(result => result.secure_url);

    res.json({
      success: true,
      imageUrls,
      message: 'Images uploaded successfully'
    });
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to upload images'
    });
  }
});

// Create new post - Updated to match your Flutter app structure
app.post('/api/posts', authenticateUser, async (req, res) => {
  try {
    const { content, images, tags, title, type } = req.body;

    // Validate input
    const validationErrors = validatePostInput({
      caption: content,
      tags: tags
    });

    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        error: validationErrors.join('; ')
      });
    }

    if (!images || !Array.isArray(images) || images.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'At least one image URL is required'
      });
    }

    // Validate image URLs
    const invalidUrls = images.filter(url => !validator.isURL(url, { protocols: ['https'] }));
    if (invalidUrls.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid image URLs provided'
      });
    }

    // Sanitize inputs
    const sanitizedContent = sanitizeInput(content);
    const sanitizedTags = (tags || []).map(tag => sanitizeInput(tag.toLowerCase()));

    // Insert post
    const { data: post, error: postError } = await supabase
      .from('posts')
      .insert({
        user_id: req.user.id,
        image_url: images[0], // Use first image as primary
        caption: sanitizedContent,
        location: null
      })
      .select('*')
      .single();

    if (postError) {
      console.error('Database insert error:', postError);
      throw new Error('Failed to create post in database');
    }

    // Handle tags
    const postTags = [];
    if (sanitizedTags.length > 0) {
      for (const tagName of sanitizedTags) {
        try {
          const { data: tag, error: tagError } = await supabase
            .from('tags')
            .upsert({ name: tagName }, { onConflict: 'name' })
            .select('id, name')
            .single();

          if (!tagError && tag) {
            await supabase
              .from('post_tags')
              .insert({ post_id: post.id, tag_id: tag.id });
            
            postTags.push(tag.name);
          }
        } catch (tagError) {
          console.warn(`Failed to process tag ${tagName}:`, tagError);
        }
      }
    }

    // Get user info for response
    const userInfo = getUserInfo(req.user);

    res.status(201).json({
      success: true,
      message: 'Post created successfully',
      post: formatPost({ ...post, tags: postTags }, userInfo)
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to create post' 
    });
  }
});

// Update post with validation
app.put('/api/posts/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!validator.isUUID(id)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid post ID format'
      });
    }

    const { content, location, tags } = req.body;

    // Validate input
    const validationErrors = validatePostInput({
      caption: content,
      location,
      tags
    });

    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        error: validationErrors.join('; ')
      });
    }

    // Check ownership
    const { data: existingPost, error: checkError } = await supabase
      .from('posts')
      .select('user_id')
      .eq('id', id)
      .single();

    if (checkError || !existingPost) {
      return res.status(404).json({
        success: false,
        error: 'Post not found'
      });
    }

    if (existingPost.user_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized to modify this post'
      });
    }

    // Update post
    const updateData = {
      updated_at: new Date().toISOString()
    };
    
    if (content !== undefined) updateData.caption = sanitizeInput(content);
    if (location !== undefined) updateData.location = location ? sanitizeInput(location) : null;

    const { data: updatedPost, error: updateError } = await supabase
      .from('posts')
      .update(updateData)
      .eq('id', id)
      .select('*')
      .single();

    if (updateError) {
      console.error('Post update error:', updateError);
      throw new Error('Failed to update post');
    }

    // Update tags if provided
    let postTags = [];
    if (tags !== undefined) {
      // Remove existing tags
      await supabase.from('post_tags').delete().eq('post_id', id);

      // Add new tags
      const sanitizedTags = tags.map(tag => sanitizeInput(tag.toLowerCase()));
      for (const tagName of sanitizedTags) {
        try {
          const { data: tag } = await supabase
            .from('tags')
            .upsert({ name: tagName }, { onConflict: 'name' })
            .select('id, name')
            .single();

          if (tag) {
            await supabase
              .from('post_tags')
              .insert({ post_id: id, tag_id: tag.id });
            
            postTags.push(tag.name);
          }
        } catch (tagError) {
          console.warn(`Failed to update tag ${tagName}:`, tagError);
        }
      }
    }

    const userInfo = getUserInfo(req.user);

    res.json({
      success: true,
      message: 'Post updated successfully',
      post: formatPost({ ...updatedPost, tags: postTags }, userInfo)
    });
  } catch (error) {
    console.error('Update post error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to update post' 
    });
  }
});

// Delete post with enhanced security
app.delete('/api/posts/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!validator.isUUID(id)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid post ID format'
      });
    }

    // Check ownership and get image URL
    const { data: post, error: checkError } = await supabase
      .from('posts')
      .select('user_id, image_url')
      .eq('id', id)
      .single();

    if (checkError || !post) {
      return res.status(404).json({
        success: false,
        error: 'Post not found'
      });
    }

    if (post.user_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized to delete this post'
      });
    }

    // Delete from database first
    const { error: deleteError } = await supabase
      .from('posts')
      .delete()
      .eq('id', id);

    if (deleteError) {
      console.error('Post deletion error:', deleteError);
      throw new Error('Failed to delete post from database');
    }

    // Try to delete from Cloudinary (non-blocking)
    if (post.image_url && post.image_url.includes('cloudinary.com')) {
      try {
        const publicIdMatch = post.image_url.match(/\/([^\/]+)\.(jpg|jpeg|png|webp)$/i);
        if (publicIdMatch) {
          const publicId = `photography_posts/${publicIdMatch[1]}`;
          await cloudinary.uploader.destroy(publicId);
        }
      } catch (cloudinaryError) {
        console.warn('Cloudinary deletion failed (non-critical):', cloudinaryError.message);
      }
    }

    res.json({
      success: true,
      message: 'Post deleted successfully'
    });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to delete post' 
    });
  }
});

// Like/Unlike post with validation
app.post('/api/posts/:id/like', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!validator.isUUID(id)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid post ID format'
      });
    }

    // Check if post exists
    const { data: postExists } = await supabase
      .from('posts')
      .select('id')
      .eq('id', id)
      .single();

    if (!postExists) {
      return res.status(404).json({
        success: false,
        error: 'Post not found'
      });
    }

    // Check if already liked
    const { data: existingLike } = await supabase
      .from('likes')
      .select('id')
      .eq('post_id', id)
      .eq('user_id', req.user.id)
      .single();

    if (existingLike) {
      // Unlike
      const { error } = await supabase
        .from('likes')
        .delete()
        .eq('post_id', id)
        .eq('user_id', req.user.id);

      if (error) throw error;

      res.json({
        success: true,
        message: 'Post unliked',
        liked: false
      });
    } else {
      // Like
      const { error } = await supabase
        .from('likes')
        .insert({
          post_id: id,
          user_id: req.user.id
        });

      if (error) {
        if (error.code === '23505') { // Unique constraint violation
          return res.json({
            success: true,
            message: 'Post already liked',
            liked: true
          });
        }
        throw error;
      }

      res.json({
        success: true,
        message: 'Post liked',
        liked: true
      });
    }
  } catch (error) {
    console.error('Like/unlike error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to process like action' 
    });
  }
});

// Enhanced error handling middleware
app.use((error, req, res, next) => {
  console.error('Global error:', error);

  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ 
      success: false,
      error: 'File too large. Maximum size is 5MB.' 
    });
  }

  if (error.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({ 
      success: false,
      error: 'Unexpected file field.' 
    });
  }

  if (error.type === 'entity.too.large') {
    return res.status(413).json({ 
      success: false,
      error: 'Request entity too large.' 
    });
  }

  // Don't expose internal errors in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : error.message;

  res.status(500).json({ 
    success: false,
    error: message 
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false,
    error: 'Route not found' 
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Photography API running on port ${PORT}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/health`);
  console.log(`🔒 Security features enabled`);
});

module.exports = app;