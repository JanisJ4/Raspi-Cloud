// Constants for protocol, server IP, and port
const protocol = window.location.protocol;
const serverIP = window.location.hostname;
const serverPort = '8080';

// Event listener for when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
    var versionNumber = 'v2.5.3'; 
    var versionTag = document.createElement('div');
    versionTag.className = 'version-tag';
    versionTag.textContent = versionNumber;

    document.body.appendChild(versionTag);
    // Regular token check, e.g. every 5 minutes
    setInterval(checkAuthToken, 300000);
});

// Function to toggle dark mode
function toggleDarkMode() {
    const body = document.body;
    // Toggle the 'light-mode' class on the body element to switch between dark and light mode
    body.classList.toggle('light-mode');
}

// Function to open the menu
function openMenu() {
    var menu = document.getElementById("menu");
    var overlay = document.getElementById("overlay");

    // Display the menu and overlay
    menu.style.display = "block";
    overlay.style.display = "block";

    // Animate the menu appearance
    setTimeout(function () {
        menu.style.right = "0"; // Slide the menu into view
        overlay.addEventListener("click", closeMenu); // Add listener to overlay for closing the menu
    }, 1); // Timeout to ensure the CSS transition takes effect
}

// Function to close the menu
function closeMenu() {
    var menu = document.getElementById('menu');
    var overlay = document.getElementById("overlay");

    menu.style.right = '-100%'; // Slide the menu out of view

    // Animate and hide the menu and overlay
    setTimeout(function () {
        overlay.style.display = 'none';
        menu.style.display = 'none';
    }, 300); // Duration of the transition in milliseconds

    // Remove the event listener for closing the menu
    overlay.removeEventListener("click", closeMenu);
}

// Function to read a cookie value
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function logout() {
    // Handle logout action, such as redirecting to the login page
    localStorage.setItem('dateipfad', ''); // Clear the file path in local storage
    var targetURL = "/index.html"; // Define the URL to redirect after logout
    window.location.href = targetURL; // Redirect to the login page
}

function isTokenExpired(token) {
    // Decode the token to extract the expiration date
    const payloadBase64 = token.split('.')[1];
    const decodedPayload = JSON.parse(window.atob(payloadBase64));
    const exp = decodedPayload.exp;
    const now = Math.floor(Date.now() / 1000); // Current time in seconds since Epoch

    // Check whether the token has expired
    return exp < now;
}

function checkForTokenExpiration(response) {
    if (response.status == 401) {
        logout();
    } else if (!response.ok) {
        // Wenn der Status nicht ok ist, werfen Sie einen Fehler mit dem StatusText
        throw new Error(`HTTP error! status: ${response.statusText}`);
    }
}

function checkAuthToken() {
    // Get token from the cookie
    const token = getCookie('token');

    if (token && isTokenExpired(token)) {
        // Token has expired
        console.log('Token expired. Log out user.');
        logout();
    } else {
        // Token is valid or not available
        console.log('Token is valid or not available.');
    }
}


// Function that is called when the page is loaded
function checkAndDisplayLogMenu() {
    const token = getCookie('token'); // Assumption that you have the getCookie function available
    const username = getCookie('username');

    // Direct call to check the user rights
    return fetch(`${protocol}//${serverIP}:${serverPort}/user_rights`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            username: username
        })
    })
    .then(response => response.json())
    .then(userRights => {
        // Check whether the user has the 'owner' right
        const hasOwnerRight = userRights.some(userRight => userRight.right.toLowerCase() === 'owner');
        if (hasOwnerRight) {
            // If the user has the right 'owner', display the menu item
            document.getElementById('logMenuLink').style.display = 'block';
        }
    })
    .catch(error => console.error('Error checking user rights:', error));
}

// Event listener for logout action
document.querySelector('.menu a.logout').addEventListener('click', async (e) => {
    e.preventDefault();

    try {
        logout();
    } catch (error) {
        console.error('Error during fetch:', error); // Log any errors to the console
    }
});