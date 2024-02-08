
// Function to toggle dark mode
function toggleDarkMode() {
    const body = document.body;
    // Toggle the 'light-mode' class on the body element to switch between dark and light mode
    body.classList.toggle('light-mode');
}

// Event listener for the login form submission
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault(); // Prevent the default form submission behavior

    // Retrieve username and password from the form inputs
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        // Determine the protocol (http or https) and server IP from the window location
        const protocol = window.location.protocol;
        const serverIP = window.location.hostname;
        // Send a POST request to the login endpoint with the username and password
        const response = await fetch(`${protocol}//${serverIP}:8080/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password }) // Convert the credentials to JSON
        });

        // Check for a successful response from the server
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const data = await response.json(); // Parse the JSON response

        // Handle the response for successful or unsuccessful login
        if (data.success) {
            // On successful login, hide the login form
            var userToken = data.token; // Retrieve the token from the response
            var targetURL = "/filepage.html"; // Define the URL to redirect after login
            // Store the token in a cookie and redirect to the target URL
            document.cookie = "token=" + encodeURIComponent(userToken) + "; path=/";
            window.location.href = targetURL;
        } else {
            alert('Incorrect user name or password.'); // Alert if login credentials are incorrect
        }
    } catch (error) {
        console.error('Error during fetch:', error); // Log fetch errors
        console.error('Server response:', error.response); // Log additional server response error
    }
});
