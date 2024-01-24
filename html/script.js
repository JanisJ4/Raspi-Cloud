// Constants for protocol, server IP, and port
const protocol = window.location.protocol;
const serverIP = window.location.hostname;
const serverPort = '8080';

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

// Event listener for logout action
document.querySelector('.menu a.logout').addEventListener('click', async (e) => {
    e.preventDefault();

    try {
        // Handle logout action, such as redirecting to the login page
        localStorage.setItem('dateipfad', ''); // Clear the file path in local storage
        var targetURL = "/index.html"; // Define the URL to redirect after logout
        window.location.href = targetURL; // Redirect to the login page
    } catch (error) {
        console.error('Error during fetch:', error); // Log any errors to the console
    }
});
