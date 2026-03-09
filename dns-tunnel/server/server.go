// Existing content before modification

// Other code...

// Modifying cleanupLoop function around line 345
func cleanupLoop() {
    // ... other code
    sess.closed = true // Prevent race condition
    sess.conn.Close() // This is your current line of code
}

// Existing content after modification