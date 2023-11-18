// Chat API Implementation
const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const fetch = require('node-fetch');
const apn = require('apn');





// Socket.io Import
const http = require('http');
const socketIo = require('socket.io');




const app = express();
app.use(express.json());

// Create a connection pool
const pool = mysql.createPool({
        host: '',
        user: '',
        password: '',
        database: '',
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
});

pool.on('error', (err) => {
        console.error('Unexpected error on idle client', err);
        process.exit(-1);
});

const apiKey = '';

// Create HTTP Server
const server = http.createServer(app);

// Initialize Socket.io
const io = socketIo(server);


// Middleware to check for API key
app.use((req, res, next) => {
        const requestApiKey = req.headers['x-api-key'];
        console.log('Received API key:', requestApiKey);
        if (requestApiKey && requestApiKey === apiKey) {
                next();
        } else {
                res.status(403).json({ message: 'Forbidden' });
        }
});

// Authenthicate Device Token
app.post('/register-token', (req, res) => {
        const { userId, token } = req.body;
    
        // Insert or update the token in your database
        const query = 'INSERT INTO device_tokens (user_id, token) VALUES (?, ?) ON DUPLICATE KEY UPDATE token = ?';
        pool.query(query, [userId, token, token], (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Server error' });
            }
            res.json({ success: true, message: 'Token registered successfully' });
        });
    });
    

// Retrieve users
app.get('/users', (req, res) => {
        pool.query('SELECT id, email, created_at FROM users', (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json(results);
        });
});

// Authenticate users
app.post('/login', async (req, res) => {
        try {
                const { email, password } = req.body;

                if (!email || !password) {
                        return res.status(400).json({ message: 'Both email and password are required' });
                }

                const query = 'SELECT * FROM users WHERE email = ?';
                pool.query(query, [email], async (err, results) => {
                        if (err) {
                                console.error(err);
                                return res.status(500).json({ message: 'Server error' });
                        }

                        if (results.length === 0) {
                                return res.status(400).json({ message: 'Invalid email or password' });
                        }

                        const user = results[0];
                        const passwordMatch = await bcrypt.compare(password, user.password);

                        if (!passwordMatch) {
                                return res.status(400).json({ message: 'Invalid email or password' });
                        }
                        // Check for a profile
                        const profileQuery = 'SELECT * FROM profiles WHERE user_id = ?';
                        pool.query(profileQuery, [user.id], (profileErr, profileResults) => {
                                if (profileErr) {
                                        console.error(profileErr);
                                        return res.status(500).json({ message: 'Server error' });
                                }

                                const hasProfile = profileResults.length > 0;

                                // Generate JWT token
                                const token = jwt.sign({ id: user.id }, 'your-secret-key', { expiresIn: '1h' });

                                // Send JWT token and profile existence info to client
                                res.json({ success: true, userId: user.id, token, hasProfile });
                        });
                });
        } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'An error occurred while processing your request' });
        }
});


// Register users
app.post('/users', async (req, res) => {
        try {
                const { email, password } = req.body;

                if (!email || !password) {
                        return res.status(400).json({ message: 'Email and password are required' });
                }

                const query = 'SELECT * FROM users WHERE email = ?';
                pool.query(query, [email], async (err, results) => {
                        if (err) {
                                console.error(err);
                                return res.status(500).json({ message: 'Server error' });
                        }

                        if (results.length > 0) {
                                return res.status(400).json({ message: 'Email already exists' });
                        }

                        const hashedPassword = await bcrypt.hash(password, 10);
                        const insertQuery = 'INSERT INTO users (email, password) VALUES (?, ?)';
                        pool.query(insertQuery, [email, hashedPassword], (insertErr, insertResults) => {
                                if (insertErr) {
                                        console.error(insertErr);
                                        return res.status(500).json({ message: 'Server error' });
                                }

                                res.json({ success: true, userId: insertResults.insertId });
                        });
                });
        } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Internal Server Error' });
        }
});

// Create uploads directory if it doesn't exist
const uploadsDirectory = '/Users/g/Desktop/UserImages';

if (!fs.existsSync(uploadsDirectory)) {
        fs.mkdirSync(uploadsDirectory, { recursive: true });
}

console.log("Uploads Directory:", uploadsDirectory);

app.use('/UserImages', express.static(uploadsDirectory));

const storage = multer.diskStorage({
        destination: function (req, file, cb) {
                cb(null, uploadsDirectory);
        },
        filename: function (req, file, cb) {
                cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
        }
});

const upload = multer({ storage: storage });

// Retrieve Profile
app.get('/profiles/:userId', (req, res) => {
        const userId = req.params.userId;
        pool.query(
                'SELECT id, user_id, username, first_name, last_name, date_of_birth, profile_photo, description FROM profiles WHERE user_id = ?',
                [userId],
                (err, results) => {
                        if (err) {
                                console.error(err);
                                return res.status(500).json({ message: 'Server error' });
                        }

                        // Check if the results array is not empty
                        if (results.length > 0) {
                                console.log("Profile Photo URL:", results[0].profile_photo);
                                res.json(results[0]);  // Assuming user_id is unique and only one result will be returned
                        } else {
                                // If no profile found, return a 404 status code with an error message
                                res.status(404).json({ message: 'Profile not found' });
                        }
                }
        );
});

// Create Profile
app.post('/profiles', upload.single('profile_photo'), (req, res) => {
        console.log('Received user_id:', req.body.id);
        try {
                const { id: user_id, username, first_name, last_name, date_of_birth, description } = req.body;
                const profile_photo = req.file ? `${req.protocol}://${req.get('host')}/UserImages/${req.file.filename}` : null;

                if (!user_id || !username || !first_name || !last_name || !date_of_birth || !description) {
                        return res.status(400).json({ message: 'All fields are required except profile photo' });
                }

                // Validate user_id
                pool.query('SELECT id FROM users WHERE id = ?', [user_id], (err, results) => {
                        if (err || results.length === 0) {
                                return res.status(400).json({ message: 'Invalid user ID' });
                        }

                        // User ID is valid, proceed with inserting the profile
                        const insertQuery = 'INSERT INTO profiles (user_id, username, first_name, last_name, date_of_birth, profile_photo, description) VALUES (?, ?, ?, ?, ?, ?, ?)';
                        pool.query(insertQuery, [user_id, username, first_name, last_name, date_of_birth, profile_photo, description], (err, results) => {
                                if (err) {
                                        console.error(err);
                                        return res.status(500).json({ message: 'Server error', error: err.message });
                                }
                                res.json({ success: true, profileId: results.insertId });
                        });
                });

        } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Internal Server Error', error: error.message });
        }
});

// Update Profile
app.put('/updateProfile', upload.single('profile_photo'), (req, res) => {
        try {
                const { id: user_id, username, first_name, last_name, date_of_birth, description } = req.body;
                const profile_photo = req.file ? `${req.protocol}://${req.get('host')}/UserImages/${req.file.filename}` : null;

                // Log the values received
                console.log("Received user_id:", user_id);
                console.log("Received username:", username);
                console.log("Received first_name:", first_name);
                console.log("Received last_name:", last_name);
                console.log("Received date_of_birth:", date_of_birth);
                console.log("Received description:", description);
                console.log("Generated profile_photo URL:", profile_photo);

                if (!user_id) {
                        return res.status(400).json({ message: 'User ID is required' });
                }

                // Check if the profile for this user ID exists
                pool.query('SELECT id FROM profiles WHERE user_id = ?', [user_id], (err, results) => {
                        if (err) {
                                console.error(err);
                                return res.status(500).json({ message: 'Server error' });
                        }

                        if (results.length === 0) {
                                return res.status(404).json({ message: 'Profile not found for this user ID' });
                        }

                        // Profile exists, so update it
                        const updateQuery = `
                   UPDATE profiles
                   SET username = ?, first_name = ?, last_name = ?, date_of_birth = ?, profile_photo = ?, description = ?
                   WHERE user_id = ?
                   `;
                        pool.query(updateQuery, [username, first_name, last_name, date_of_birth, profile_photo, description, user_id], (updateErr, updateResults) => {
                                if (updateErr) {
                                        console.error(updateErr);
                                        return res.status(500).json({ message: 'Server error during profile update', error: updateErr.message });
                                }

                                // Send success response
                                res.json({ success: true, message: 'Profile updated successfully' });
                        });
                });
        } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Internal Server Error', error: error.message });
        }
});

// Delete Profile
app.delete('/deleteProfile', (req, res) => {
        const { id: user_id } = req.body;

        if (!user_id) {
                return res.status(400).json({ message: 'User ID is required' });
        }

        // Check if the profile for this user ID exists
        pool.query('SELECT id FROM profiles WHERE user_id = ?', [user_id], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }

                if (results.length === 0) {
                        return res.status(404).json({ message: 'Profile not found for this user ID' });
                }

                // Profile exists, so delete it
                const deleteQuery = 'DELETE FROM profiles WHERE user_id = ?';
                pool.query(deleteQuery, [user_id], (deleteErr, deleteResults) => {
                        if (deleteErr) {
                                console.error(deleteErr);
                                return res.status(500).json({ message: 'Server error during profile deletion', error: deleteErr.message });
                        }

                        // Send success response
                        res.json({ success: true, message: 'Profile deleted successfully' });
                });
        });
});

// Endpoints for Group Management

// Retrieve Chat History
app.get('/chats/:roomId', async (req, res) => {
        const roomId = req.params.roomId;
        const [user1, user2] = roomId.split('-').map(id => parseInt(id, 10));

        try {
                const query = `
        SELECT * FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp DESC
        `;
                pool.query(query, [user1, user2, user2, user1], (err, results) => {
                        if (err) {
                                console.error(err);
                                return res.status(500).json({ message: 'Server error while fetching chat history' });
                        }

                        // Send the fetched messages as a response
                        res.json(results);
                });
        } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Internal Server Error' });
        }
});


// Retrieve Chat History for a specific conversation
app.get('/conversations/:conversationId/history', async (req, res) => {
        const conversationId = req.params.conversationId;

        try {
                const chatHistoryQuery = `
                SELECT m.*, p.first_name as sender_name
                FROM messages m
                JOIN profiles p ON m.sender_id = p.user_id
                WHERE m.conversation_id = ?
                ORDER BY m.timestamp DESC
            `;

                pool.query(chatHistoryQuery, [conversationId], (err, results) => {
                        if (err) {
                                console.error(err);
                                return res.status(500).json({ message: 'Server error while fetching chat history' });
                        }

                        // Send the fetched messages as a response
                        res.json(results);
                });

        } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Internal Server Error' });
        }
});

// Get Conversations for User
app.get('/users/:userId/conversations', (req, res) => {
        const userId = req.params.userId;
        const query = `
        SELECT
        conversations.id AS conversation_id,
        other_profiles.user_id AS other_user_id,
        other_profiles.first_name AS other_user_first_name,
        other_profiles.last_name AS other_user_last_name,
        latest_messages.latest_message_timestamp,
        latest_message_text.message_text AS last_message
        FROM
        conversations
        JOIN
        conversation_members ON conversations.id = conversation_members.conversation_id
        JOIN
        conversation_members AS other_members ON conversations.id = other_members.conversation_id AND other_members.user_id != conversation_members.user_id
        JOIN
        profiles AS other_profiles ON other_members.user_id = other_profiles.user_id
        LEFT JOIN
        (SELECT
         conversation_id,
         MAX(timestamp) AS latest_message_timestamp
         FROM messages
         GROUP BY conversation_id) AS latest_messages ON conversations.id = latest_messages.conversation_id
        LEFT JOIN
        messages AS latest_message_text ON latest_messages.conversation_id = latest_message_text.conversation_id AND latest_messages.latest_message_timestamp = latest_message_text.timestamp
        WHERE
        conversation_members.user_id = ?
        ORDER BY
        latest_message_timestamp DESC;





        `;
        pool.query(query, [userId], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json(results);
        });
});

// Get Messages in Conversation
app.get('/conversations/:conversationId/messages', (req, res) => {
        const conversationId = req.params.conversationId;
        const query = `
        SELECT m.*, p.username, p.first_name, p.last_name, p.profile_photo
        FROM messages m
        JOIN profiles p ON m.sender_id = p.user_id
        WHERE m.conversation_id = ?
        ORDER BY m.timestamp ASC
        `;
        pool.query(query, [conversationId], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json(results);
        });
});





// Send Message in Conversation
app.post('/conversations/:conversationId/messages', (req, res) => {
    const conversationId = req.params.conversationId;
    const { sender_id, receiver_id, message_text } = req.body;

    // Insert the new message into the database
    const insertQuery = `
    INSERT INTO messages (sender_id, receiver_id, conversation_id, message_text, timestamp)
    VALUES (?, ?, ?, ?, NOW())
    `;

    pool.query(insertQuery, [sender_id, receiver_id, conversationId, message_text], async (err, insertResults) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Server error' });
        }

        const messageId = insertResults.insertId;

        // Code to send a push notification
        let notification = new apn.Notification({
          alert: "You have a new message",
          // ... other notification properties ...
        });

        // Fetch the recipient's device token from your database
        // For demonstration, assuming you have a function to get it
        const recipientDeviceToken = await getDeviceToken(receiver_id);

        apnProvider.send(notification, recipientDeviceToken).then((response) => {
          // Handle response
          console.log(response);
        });

        // Emit a socket event to notify other clients
        io.emit('newMessage', { conversationId, messageId, message: message_text });
    });
});

    




// Get Groups for User
app.get('/users/:userId/groups', (req, res) => {
        const userId = req.params.userId;
        const query = `
        SELECT g.id, g.name, p.user_id, p.username, p.first_name, p.last_name, p.profile_photo, m.message_text, m.timestamp
        FROM groups g
        JOIN user_groups ug ON g.id = ug.group_id
        JOIN profiles p ON ug.user_id = p.user_id
        JOIN messages m ON g.id = m.group_id
        WHERE ug.user_id = ?
        ORDER BY m.timestamp DESC
        `;
        pool.query(query, [userId], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json(results);
        });
});

// Get Messages in Group
app.get('/groups/:groupId/messages', (req, res) => {
        const groupId = req.params.groupId;
        const query = `
        SELECT m.*, p.username, p.first_name, p.last_name, p.profile_photo
        FROM messages m
        JOIN profiles p ON m.sender_id = p.user_id
        WHERE m.group_id = ?
        ORDER BY m.timestamp ASC
        `;
        pool.query(query, [groupId], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json(results);
        });
});

// Send Message in Group
app.post('/groups/:groupId/messages', (req, res) => {
        const groupId = req.params.groupId;
        const { sender_id, message_text } = req.body;
        const query = `
         INSERT INTO messages (sender_id, group_id, message_text, timestamp)
         VALUES (?, ?, ?, NOW())
         `;
        pool.query(query, [sender_id, groupId, message_text], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json({ success: true, messageId: results.insertId });
        });
});

// Create Group
app.post('/groups', (req, res) => {
        const { name, user_ids } = req.body;  // Assume user_ids is an array of user IDs

        // Start a transaction since we're making multiple related changes
        pool.getConnection((err, connection) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }

                connection.beginTransaction(err => {
                        if (err) {
                                console.error(err);
                                connection.release();
                                return res.status(500).json({ message: 'Server error' });
                        }

                        const insertGroupQuery = 'INSERT INTO groups (name) VALUES (?)';

                        connection.query(insertGroupQuery, [name], (err, results) => {
                                if (err) {
                                        console.error(err);
                                        return connection.rollback(() => {
                                                connection.release();
                                                res.status(500).json({ message: 'Server error' });
                                        });
                                }

                                const groupId = results.insertId;
                                const insertUserGroupQuery = 'INSERT INTO user_groups (user_id, group_id) VALUES ?';
                                const userGroupValues = user_ids.map(user_id => [user_id, groupId]);

                                connection.query(insertUserGroupQuery, [userGroupValues], (err, results) => {
                                        if (err) {
                                                console.error(err);
                                                return connection.rollback(() => {
                                                        connection.release();
                                                        res.status(500).json({ message: 'Server error' });
                                                });
                                        }

                                        connection.commit(err => {
                                                if (err) {
                                                        console.error(err);
                                                        return connection.rollback(() => {
                                                                connection.release();
                                                                res.status(500).json({ message: 'Server error' });
                                                        });
                                                }

                                                connection.release();
                                                res.json({ success: true, groupId });
                                        });
                                });
                        });
                });
        });
});


// Add/Remove Member in Group
app.post('/groups/:groupId/members', (req, res) => {
        const groupId = req.params.groupId;
        const { user_id } = req.body;
        const query = 'INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)';
        pool.query(query, [user_id, groupId], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json({ success: true });
        });
});

app.delete('/groups/:groupId/members/:memberId', (req, res) => {
        const { groupId, memberId } = req.params;
        const query = 'DELETE FROM user_groups WHERE user_id = ? AND group_id = ?';
        pool.query(query, [memberId, groupId], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json({ success: true });
        });
});

// Update Read Status
app.patch('/messages/:messageId/read', (req, res) => {
        const messageId = req.params.messageId;
        const query = 'UPDATE messages SET read = TRUE WHERE id = ?';
        pool.query(query, [messageId], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error' });
                }
                res.json({ success: true });
        });
});

// Search for User by username or other attribute
app.get('/users/search', (req, res) => {
        const searchTerm = req.query.term; // Get the search term from query parameters

        // Define the SQL query to search for users
        // The LIKE operator is used for partial matching
        // The '%' signs are wildcards that represent any sequence of characters
        const searchQuery = `
            SELECT user_id, username, first_name, last_name, profile_photo
            FROM profiles
            WHERE username LIKE ? OR first_name LIKE ? OR last_name LIKE ?
            ORDER BY username
        `;

        // The searchTerm is surrounded by '%' to match any users that contain the searchTerm within their username, first name, or last name
        const likeTerm = `%${searchTerm}%`;

        // Execute the query with the likeTerm in place of the '?' placeholders
        pool.query(searchQuery, [likeTerm, likeTerm, likeTerm], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error during user search' });
                }
                // If no error, send the search results back to the client
                res.json(results);
        });
});


// Create New Direct Message Conversation
app.post('/conversations/direct', (req, res) => {
        const { user1_id, user2_id } = req.body; // IDs of the two users

        // Avoid duplicate conversations by checking if one already exists
        const checkConversationQuery = `
         SELECT id FROM conversations
         WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
         `;

        pool.query(checkConversationQuery, [user1_id, user2_id, user2_id, user1_id], (err, results) => {
                if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Server error while checking for existing conversation' });
                }

                // If a conversation already exists, return its ID
                if (results.length > 0) {
                        return res.json({ conversationId: results[0].id, existing: true });
                }

                // If no conversation exists, create a new one
                pool.getConnection((err, connection) => {
                        if (err) {
                                console.error(err);
                                return res.status(500).json({ message: 'Server error' });
                        }

                        connection.beginTransaction(err => {
                                if (err) {
                                        console.error(err);
                                        connection.release();
                                        return res.status(500).json({ message: 'Server error' });
                                }

                                const insertConversationQuery = `
                                                                   INSERT INTO conversations (user1_id, user2_id, last_message_timestamp) VALUES (?, ?, NULL)
                                                                   `;

                                connection.query(insertConversationQuery, [user1_id, user2_id], (err, conversationResults) => {
                                        if (err) {
                                                console.error(err);
                                                return connection.rollback(() => {
                                                        connection.release();
                                                        res.status(500).json({ message: 'Server error during conversation creation' });
                                                });
                                        }

                                        const conversationId = conversationResults.insertId;
                                        const insertMembersQuery = `
                                                                                    INSERT INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, NOW()), (?, ?, NOW())
                                                                                    `;

                                        connection.query(insertMembersQuery, [conversationId, user1_id, conversationId, user2_id], (err, memberResults) => {
                                                if (err) {
                                                        console.error(err);
                                                        return connection.rollback(() => {
                                                                connection.release();
                                                                res.status(500).json({ message: 'Server error during conversation members creation' });
                                                        });
                                                }

                                                connection.commit(err => {
                                                        if (err) {
                                                                console.error(err);
                                                                return connection.rollback(() => {
                                                                        connection.release();
                                                                        res.status(500).json({ message: 'Server error' });
                                                                });
                                                        }

                                                        connection.release();
                                                        res.json({ success: true, conversationId });
                                                });
                                        });
                                });
                        });
                });
        });
});


    

// Start the server
server.listen(3001, () => {
        console.log('Server is running on port 3001');
});
