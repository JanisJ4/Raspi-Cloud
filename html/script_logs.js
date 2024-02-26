// Event listener for when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
    // Add event listeners to all elements with class 'close' to close modals
    document.querySelectorAll('.close').forEach(closeButton => {
        closeButton.addEventListener('click', closeModal);
    });

    // Call the function to perform the check when loading the page
    fetchAndDisplayLogData();
});

// Function to close a modal
function closeModal(modalId) {
    // Hide the modal with the given ID
    document.getElementById(modalId).style.display = 'none';
}

// Function to toggle the visibility of the mini menu
function toggleMiniMenu() {
    var menu = document.getElementById('moreMenu');
    var overlay = document.getElementById("overlay");
    var lastAdded = document.querySelector('.last-added');

    // Reset positioning for mobile devices
    moreMenu.style.position = '';
    moreMenu.style.top = '';
    moreMenu.style.left = '';
    moreMenu.style.bottom = '';

    // Create Upload Button
    const uploadButton = document.createElement('button');
    uploadButton.textContent = 'Upload';
    uploadButton.classList.add('menuButton');
    uploadButton.onclick = function () { uploadFile(); };

    // Create New Folder Button
    const newFolderButton = document.createElement('button');
    newFolderButton.textContent = 'New folder';
    newFolderButton.classList.add('menuButton');
    newFolderButton.onclick = function () { createFolder(); };

    // Create a horizontal rule
    const hr1 = document.createElement('hr');

    // Append buttons to the menu
    menu.appendChild(newFolderButton);
    menu.appendChild(hr1);
    menu.appendChild(uploadButton);

    // Append the menu to the body
    document.body.appendChild(menu);

    // CSS breakpoint for mobile devices
    var mobileBreakpoint = 768;
    overlay.style.display = 'block';
    menu.style.display = 'block';
    // Check if the current view is wider than the breakpoint
    if (window.innerWidth > mobileBreakpoint) {
        // Calculate the position of .last-added
        var rect = lastAdded.getBoundingClientRect();

        moreMenu.style.position = 'absolute';
        moreMenu.style.top = `${rect.bottom + window.scrollY}px`; // Bottom of .last-added plus current scroll position
        moreMenu.style.left = `${rect.left + window.scrollX}px`; // Left of .last-added plus current scroll position
    } else {
        setTimeout(function () {
            menu.style.bottom = '0';
        }, 100); // Duration of the transition in milliseconds
    }

    // Event listener to close the menu
    overlay.addEventListener("click", closeMiniMenu);
}

// Function to close the mini menu
function closeMiniMenu() {
    var menu = document.getElementById('moreMenu');
    var overlay = document.getElementById("overlay");

    // CSS breakpoint for mobile devices
    var mobileBreakpoint = 768;
    if (window.innerWidth > mobileBreakpoint) {
        moreMenu.style.display = 'none';
    } else {
        setTimeout(function () {
            menu.style.bottom = '-100%';
        }, 100); // Duration of the transition in milliseconds
    }

    setTimeout(function () {
        menu.style.display = 'none';
        overlay.style.display = 'none';

        // Remove all buttons in the menu
        while (menu.firstChild) {
            menu.removeChild(menu.firstChild);
        }

        // Remove the event listener for closing the menu
        overlay.removeEventListener("click", closeMiniMenu);
    }, 300);
}

// Function to fetch the log data from the server and display it in the browser
function fetchAndDisplayLogData() {
    const token = getCookie('token'); // Assumption that you have the getCookie function available

    fetch(`${protocol}//${serverIP}:${serverPort}/get_log`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.text(); // Assumption that the server returns the content of the log file as text
    })
    .then(text => {
        // Split the text into lines, reverse the order and merge them again
        const reversedText = text.split('\n').reverse().join('\n');
        // Display the reversed content of the log file in the designated <pre> element
        document.getElementById('logContent').textContent = reversedText;
        // Make the display container visible
        document.querySelector('.log-display').style.display = 'block';
    })
    .catch(error => {
        console.error('Error fetching log data:', error);
    });
}