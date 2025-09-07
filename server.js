require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const cloudinary = require('cloudinary').v2;

// Initialize Express
const app = express();
const PORT = process.env.PORT || 5000;

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Configure Multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  },
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Validate environment variables on startup
const validateEnvironment = () => {
  const required = [
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY', 
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET'
  ];
  
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.log('❌ Missing environment variables:', missing.join(', '));
    return false;
  }
  
  return true;
};

// Validate environment before starting
validateEnvironment();

// Authentication middleware
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

// Helper function to get user display info from auth.users metadata
const getUserInfo = (user) => {
  const metadata = user.user_metadata || {};
  const rawMetadata = user.raw_user_meta_data || {};
  
  return {
    username: metadata.username || rawMetadata.username || user.email?.split('@')[0] || 'user',
    isVerified: metadata.is_verified || rawMetadata.is_verified || false,
    userType: metadata.user_type || rawMetadata.user_type || 'Photography Enthusiast'
  };
};

// Helper function to upload to Cloudinary
const uploadToCloudinary = (buffer, options = {}) => {
  return new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: 'posts',
      resource_type: 'image',
      transformation: [
        { width: 1200, height: 1200, crop: 'limit' },
        { quality: 'auto' },
        { fetch_format: 'auto' }
      ],
      ...options
    };

    cloudinary.uploader.upload_stream(
      uploadOptions,
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    ).end(buffer);
  });
};

// Helper function to format post data
const formatPost = (post, userInfo = null) => {
  return {
    id: post.id,
    userId: post.user_id,
    userName: userInfo?.username || 'unknown',
    imageUrl: post.image_url,
    caption: post.caption,
    location: post.location,
    likes: post.likes || 0,
    commentCount: post.comment_count || 0,
    tags: post.tags || [],
    createdAt: post.created_at,
    isVerified: userInfo?.isVerified || false,
    userType: userInfo?.userType || 'Photography Enthusiast',
    isFeatured: post.is_featured || false
  };
};

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Post Manager API is running',
    timestamp: new Date().toISOString()
  });
});

// Get all posts with pagination
app.get('/api/posts', async (req, res) => {
  try {
    const { limit = 10, offset = 0, sort = 'newest', user_id, tag } = req.query;

    let query = supabase
      .from('posts')
      .select(`
        *,
        post_tags (
          tags (name)
        )
      `, { count: 'exact' });

    // Filter by user if specified
    if (user_id) {
      query = query.eq('user_id', user_id);
    }

    // Sort order
    const ascending = sort === 'oldest';
    query = query.order('created_at', { ascending });

    // Pagination
    query = query.range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    const { data, error, count } = await query;

    if (error) throw error;

    // Get user info for each post
    const postsWithUserInfo = await Promise.all(
      data.map(async (post) => {
        try {
          // Get user info from auth.users
          const { data: userData } = await supabase.auth.admin.getUserById(post.user_id);
          const userInfo = userData?.user ? getUserInfo(userData.user) : null;
          
          // Format tags
          const tags = post.post_tags?.map(pt => pt.tags?.name).filter(Boolean) || [];
          
          return formatPost({ ...post, tags }, userInfo);
        } catch (err) {
          console.error('Error getting user info:', err);
          return formatPost({ ...post, tags: [] });
        }
      })
    );

    res.json({
      success: true,
      data: {
        posts: postsWithUserInfo,
        total: count,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Get post by ID
app.get('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from('posts')
      .select(`
        *,
        post_tags (
          tags (name)
        )
      `)
      .eq('id', id)
      .single();

    if (error) throw error;

    if (!data) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Get user info
    const { data: userData } = await supabase.auth.admin.getUserById(data.user_id);
    const userInfo = userData?.user ? getUserInfo(userData.user) : null;
    
    // Format tags
    const tags = data.post_tags?.map(pt => pt.tags?.name).filter(Boolean) || [];

    res.json({
      success: true,
      data: formatPost({ ...data, tags }, userInfo)
    });
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

// Create new post
app.post('/api/posts', authenticateUser, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Image file is required' });
    }

    const { caption, location, tags } = req.body;

    if (!caption) {
      return res.status(400).json({ error: 'Caption is required' });
    }

    // Upload image to Cloudinary
    const cloudinaryResult = await uploadToCloudinary(req.file.buffer, {
      public_id: `post_${Date.now()}`,
      tags: ['post', req.user.id]
    });

    // Parse tags if they're sent as string
    let parsedTags = [];
    if (tags) {
      try {
        parsedTags = typeof tags === 'string' ? JSON.parse(tags) : tags;
      } catch (e) {
        parsedTags = Array.isArray(tags) ? tags : [tags];
      }
    }

    // Insert post
    const { data: post, error: postError } = await supabase
      .from('posts')
      .insert({
        user_id: req.user.id,
        image_url: cloudinaryResult.secure_url,
        caption,
        location: location || null
      })
      .select('*')
      .single();

    if (postError) throw postError;

    // Handle tags if any
    const postTags = [];
    if (parsedTags && parsedTags.length > 0) {
      for (const tagName of parsedTags) {
        // Create tag if it doesn't exist
        const { data: tag, error: tagError } = await supabase
          .from('tags')
          .upsert({ name: tagName.toLowerCase() })
          .select('id, name')
          .single();

        if (!tagError && tag) {
          // Link tag to post
          await supabase
            .from('post_tags')
            .insert({ post_id: post.id, tag_id: tag.id });
          
          postTags.push(tag.name);
        }
      }
    }

    // Get user info for response
    const userInfo = getUserInfo(req.user);

    res.status(201).json({
      success: true,
      message: 'Post created successfully',
      data: formatPost({ ...post, tags: postTags }, userInfo)
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Update post
app.put('/api/posts/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { caption, location, tags } = req.body;

    // Check if user owns the post
    const { data: existingPost, error: checkError } = await supabase
      .from('posts')
      .select('user_id')
      .eq('id', id)
      .single();

    if (checkError || !existingPost) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (existingPost.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Update post
    const updateData = {};
    if (caption !== undefined) updateData.caption = caption;
    if (location !== undefined) updateData.location = location || null;
    updateData.updated_at = new Date().toISOString();

    const { data: updatedPost, error: updateError } = await supabase
      .from('posts')
      .update(updateData)
      .eq('id', id)
      .select('*')
      .single();

    if (updateError) throw updateError;

    // Update tags if provided
    const postTags = [];
    if (tags !== undefined) {
      // Remove existing tags
      await supabase.from('post_tags').delete().eq('post_id', id);

      // Add new tags
      const parsedTags = Array.isArray(tags) ? tags : [];
      for (const tagName of parsedTags) {
        const { data: tag } = await supabase
          .from('tags')
          .upsert({ name: tagName.toLowerCase() })
          .select('id, name')
          .single();

        if (tag) {
          await supabase
            .from('post_tags')
            .insert({ post_id: id, tag_id: tag.id });
          
          postTags.push(tag.name);
        }
      }
    } else {
      // Get existing tags
      const { data: existingTags } = await supabase
        .from('post_tags')
        .select('tags(name)')
        .eq('post_id', id);
      
      postTags.push(...(existingTags?.map(pt => pt.tags?.name).filter(Boolean) || []));
    }

    // Get user info for response
    const userInfo = getUserInfo(req.user);

    res.json({
      success: true,
      message: 'Post updated successfully',
      data: formatPost({ ...updatedPost, tags: postTags }, userInfo)
    });
  } catch (error) {
    console.error('Update post error:', error);
    res.status(500).json({ error: 'Failed to update post' });
  }
});

// Delete post
app.delete('/api/posts/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user owns the post and get image URL
    const { data: post, error: checkError } = await supabase
      .from('posts')
      .select('user_id, image_url')
      .eq('id', id)
      .single();

    if (checkError || !post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (post.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Delete from database (CASCADE will handle post_tags, likes, comments)
    const { error: deleteError } = await supabase
      .from('posts')
      .delete()
      .eq('id', id);

    if (deleteError) throw deleteError;

    // Try to delete from Cloudinary
    try {
      const publicId = post.image_url.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`posts/${publicId}`);
    } catch (cloudinaryError) {
      console.error('Cloudinary deletion failed:', cloudinaryError);
      // Continue even if Cloudinary deletion fails
    }

    res.json({
      success: true,
      message: 'Post deleted successfully'
    });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// Search posts
app.get('/api/posts/search', async (req, res) => {
  try {
    const { q, limit = 10, offset = 0 } = req.query;

    if (!q) {
      return res.status(400).json({ error: 'Search query is required' });
    }

    const { data, error, count } = await supabase
      .from('posts')
      .select(`
        *,
        post_tags (
          tags (name)
        )
      `, { count: 'exact' })
      .or(`caption.ilike.%${q}%,location.ilike.%${q}%`)
      .order('created_at', { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    if (error) throw error;

    // Get user info for each post
    const postsWithUserInfo = await Promise.all(
      data.map(async (post) => {
        try {
          const { data: userData } = await supabase.auth.admin.getUserById(post.user_id);
          const userInfo = userData?.user ? getUserInfo(userData.user) : null;
          const tags = post.post_tags?.map(pt => pt.tags?.name).filter(Boolean) || [];
          return formatPost({ ...post, tags }, userInfo);
        } catch (err) {
          return formatPost({ ...post, tags: [] });
        }
      })
    );

    res.json({
      success: true,
      data: {
        posts: postsWithUserInfo,
        total: count,
        limit: parseInt(limit),
        offset: parseInt(offset),
        query: q
      }
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Failed to search posts' });
  }
});

// Get posts by tag
app.get('/api/posts/tag/:tagName', async (req, res) => {
  try {
    const { tagName } = req.params;
    const { limit = 10, offset = 0 } = req.query;

    const { data, error, count } = await supabase
      .from('posts')
      .select(`
        *,
        post_tags!inner (
          tags!inner (name)
        )
      `, { count: 'exact' })
      .eq('post_tags.tags.name', tagName.toLowerCase())
      .order('created_at', { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    if (error) throw error;

    // Get user info for each post
    const postsWithUserInfo = await Promise.all(
      data.map(async (post) => {
        try {
          const { data: userData } = await supabase.auth.admin.getUserById(post.user_id);
          const userInfo = userData?.user ? getUserInfo(userData.user) : null;
          const tags = post.post_tags?.map(pt => pt.tags?.name).filter(Boolean) || [];
          return formatPost({ ...post, tags }, userInfo);
        } catch (err) {
          return formatPost({ ...post, tags: [] });
        }
      })
    );

    res.json({
      success: true,
      data: {
        posts: postsWithUserInfo,
        total: count,
        limit: parseInt(limit),
        offset: parseInt(offset),
        tag: tagName
      }
    });
  } catch (error) {
    console.error('Get posts by tag error:', error);
    res.status(500).json({ error: 'Failed to fetch posts by tag' });
  }
});

// Get popular tags
app.get('/api/tags', async (req, res) => {
  try {
    const { limit = 20 } = req.query;

    const { data, error } = await supabase
      .rpc('get_popular_tags', { tag_limit: parseInt(limit) });

    if (error) {
      // Fallback if RPC doesn't exist
      const { data: fallbackData, error: fallbackError } = await supabase
        .from('tags')
        .select(`
          name,
          post_tags(count)
        `)
        .limit(parseInt(limit));

      if (fallbackError) throw fallbackError;

      const tags = fallbackData.map(tag => ({
        name: tag.name,
        count: tag.post_tags?.length || 0
      })).sort((a, b) => b.count - a.count);

      return res.json({
        success: true,
        data: tags
      });
    }

    res.json({
      success: true,
      data: data || []
    });
  } catch (error) {
    console.error('Get tags error:', error);
    res.status(500).json({ error: 'Failed to fetch tags' });
  }
});

// Like/Unlike post
app.post('/api/posts/:id/like', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;

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

      if (error) throw error;

      res.json({
        success: true,
        message: 'Post liked',
        liked: true
      });
    }
  } catch (error) {
    console.error('Like/unlike error:', error);
    res.status(500).json({ error: 'Failed to like/unlike post' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Global error:', error);

  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
  }

  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Post Manager API running on port ${PORT}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;