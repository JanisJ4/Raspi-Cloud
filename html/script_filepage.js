// Event listener for when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
    // Call function to load user groups on page load
    loadUserGroups();

    // Add event listeners to all elements with class 'close' to close modals
    document.querySelectorAll('.close').forEach(closeButton => {
        closeButton.addEventListener('click', closeModal);
    });
});

// Function to close a modal
function closeModal(modalId) {
    // Hide the modal with the given ID
    document.getElementById(modalId).style.display = 'none';
}

// Function to navigate to a specific directory
function goToDirectory(path) {
    // Store the path in local storage and load files of that group
    localStorage.setItem('filepath', path);
    loadGroupFiles();
    // Update directory buttons (commented out)
}

// Function to navigate to the home directory
function goHome() {
    // Set the path in local storage to the root and load group files
    localStorage.setItem('filepath', '');
    loadGroupFiles();
    // Update directory buttons (commented out)
}

// Function to start the file upload process
function uploadFile() {
    // Open file selection dialog
    openFileSelection();
    // Add event listener for changes in the file input field
    document.getElementById('fileInput').addEventListener('change', handleFileUpload);
}

// Function to create a new folder
function createFolder() {
    // Retrieve authentication token from cookies
    const token = getCookie('token');
    var newFolderForm = document.getElementById("newFolderForm");

    // Define the action on form submission
    newFolderForm.onsubmit = function (event) {
        // Prevent the default form submission
        event.preventDefault();
        // Get the folder name from the input field
        const folder_name = document.getElementById('newFolderName').value;
        // Retrieve or initialize the directory path
        var directory = localStorage.getItem('filepath');
        if (directory === null) {
            localStorage.setItem('filepath', '');
            directory = '';
        }

        // Attempt to send a request to the server to create a folder
        try {
            fetch(`${protocol}//${serverIP}:${serverPort}/create_folder`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    folder_name: folder_name,
                    directory: directory,
                    group_id: localStorage.getItem('group')
                })
            })
                .then(response => response.json())
                .then(data => {
                    // Reload group files on success or display an error message
                    if (data.success) {
                        loadGroupFiles()
                    } else {
                        alert(data.message); // Show error message
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                });
        } catch (error) {
            console.error('Error during fetch:', error);
        }
    };

    // Display the modal for creating a new folder
    document.getElementById("newFolderModal").style.display = 'block';
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
    newFolderButton.textContent = 'New Folder';
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

    setTimeout(function () {
        menu.style.bottom = '-100%';
        menu.style.display = 'none';
        overlay.style.display = 'none';
    }, 100);

    // Remove all buttons in the menu
    while (menu.firstChild) {
        menu.removeChild(menu.firstChild);
    }

    // Remove the event listener for closing the menu
    overlay.removeEventListener("click", closeMiniMenu);
}

// Function to update the directory buttons
function updateDirectoryButtons() {
    const linkContainer = document.getElementById("directoryButtons");
    const currentPath = localStorage.getItem('filepath');
    linkContainer.innerHTML = ""; // Clear existing buttons

    // Split the current path into directories
    const directories = currentPath.split("/").filter(Boolean);

    // Create a back button if not in 'onlyGroup' mode
    if (!localStorage.getItem('onlyGroup')) {
        const backButton = document.createElement("a");
        backButton.href = 'javascript:void(0)';
        backButton.textContent = 'Gruppen';
        backButton.classList.add('backButton');
        backButton.onclick = () => {
            loadUserGroups();
            linkContainer.innerHTML = ""; // Clear existing buttons
        };
        linkContainer.appendChild(backButton);
    }

    // Create a home link
    const homelink = document.createElement("a");
    homelink.href = 'javascript:void(0)';
    homelink.textContent = 'Home';
    homelink.style.fontSize = 'var(--normal-text-size)';
    homelink.addEventListener("click", () => {
        goHome(localStorage.getItem('onlyGroup'));
    });
    linkContainer.appendChild(homelink);

    // Create buttons for each directory in the path
    for (let i = 0; i < directories.length - 1; i++) {
        const link = document.createElement("a");
        link.href = 'javascript:void(0)';
        link.textContent = directories[i];
        link.style.fontSize = 'var(--normal-text-size)';
        link.addEventListener("click", () => {
            // Update the path when a button is clicked
            const newPath = directories.slice(0, i + 1).join("/");
            goToDirectory(newPath);
        });
        linkContainer.appendChild(link);
    }

    // Create a button to add new items
    const addLink = document.createElement("a");
    addLink.href = 'javascript:void(0)';
    addLink.textContent = '+';
    addLink.classList.add('last-added');
    addLink.addEventListener("click", () => {
        toggleMiniMenu();
    });
    linkContainer.appendChild(addLink);
}

// Function to load uploaded files
async function loadGroupFiles() {
    try {
        // Read the token cookie
        const token = getCookie('token');

        var folder = localStorage.getItem('filepath');
        if (folder === null) {
            localStorage.setItem('filepath', '');
            folder = '';
        }

        // Prepare the request to fetch files
        const url = `${protocol}//${serverIP}:${serverPort}/files`;
        console.info('folder:', folder, '; group: ', localStorage.getItem('group'));
        const jsonBody = JSON.stringify({
            folder: folder,
            group: localStorage.getItem('group')
        });

        const formData = new FormData();
        formData.append('json', jsonBody);  // Attach JSON data as a string

        // Send the fetch request
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
            body: formData  // Send the JSON body directly without using Blob and FormData
        });
        const data = await response.json();
        if ('message' in data) {
            const fileList = document.getElementById('fileList');
            fileList.innerHTML = 'No files available.';
        } else if (data.files_and_folders) {
            showGroupFiles(data.files_and_folders);
        }
        // Update directory buttons after loading files
        updateDirectoryButtons();
    } catch (error) {
        console.error('Error during fetch:', error);
    }
}

// Function to load user groups from the server
async function loadUserGroups() {
    const token = getCookie('token'); // Retrieve the authentication token

    try {
        const groupList = document.getElementById('fileList'); // Get the element to display groups
        groupList.innerHTML = ''; // Clear existing group list

        // Construct the URL for the API request
        const url = `${protocol}//${serverIP}:${serverPort}/my_groups`;
        // Make a GET request to the server to retrieve user groups
        const response = await fetch(url, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }, // Include the authentication token in the request headers
        });

        // Check if the response from the server is successful
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const responseData = await response.json(); // Parse the JSON response
        // Check if the response indicates success
        if (!responseData.success) {
            throw new Error(responseData.message || 'Failed to load groups');
        }

        const groups = responseData.groups; // Extract the groups data from the response

        // Handle both single and multiple groups scenarios
        if (Array.isArray(groups)) {
            // Single group scenario: auto-select the group and load its files
            if (groups.length === 1) {
                localStorage.setItem('group', groups[0].group_id); // Store group ID in local storage
                localStorage.setItem('onlyGroup', true); // Set flag indicating only one group
                loadGroupFiles(); // Load files for the selected group
            } else {
                // Multiple groups scenario: display all groups as clickable list items
                groups.forEach(group => {
                    const groupItem = document.createElement('li');
                    groupItem.textContent = group.group_name; // Set the group name as text
                    groupItem.classList.add('groupItem'); // Add CSS class for styling
                    groupItem.onclick = () => { // Set click event handler for each group
                        localStorage.setItem('group', group.group_id); // Store selected group ID
                        localStorage.setItem('onlyGroup', false); // Set flag for multiple groups
                        loadGroupFiles(); // Load files for the selected group
                    };
                    groupList.appendChild(groupItem); // Append the group item to the list
                });
            }
        } else {
            console.error('Expected an array of groups, but got:', groups);
        }
    } catch (error) {
        console.error('Error during fetch:', error); // Log errors to the console
    }
}

// Helper function to format file size into a readable format
function formatFileSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']; // Size units
    if (bytes == 0) return '0 Byte'; // Handle zero bytes
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024))); // Determine the size unit
    return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i]; // Format and return the file size
}

// Function to display files and folders in the user interface
function showGroupFiles(filesAndFolders) {
    const fileList = document.getElementById('fileList'); // Get the element to display files and folders
    // Create and set header for the file list
    fileList.innerHTML = '<li class="fileListHeader"> <div class="fileInfo">Name</div> <div class="fileInfo">Created on</div> <div class="fileInfo">User</div> <div class="fileInfo">Size</div> <div class="fileButton"></div> <!-- Empty divs as placeholders for buttons --> <div class="fileButton"></div> </li>';

    filesAndFolders.forEach(item => {
        // Create list item for each file/folder

        const listItem = document.createElement('li');
        listItem.classList.add('fileListItem'); // Add CSS class for styling

        // Create and set elements for file information: name, creation date, user, and size
        const fileInfoName = document.createElement('div');
        fileInfoName.classList.add('fileInfo');
        fileInfoName.textContent = item.name;

        const fileInfoCreated = document.createElement('div');
        fileInfoCreated.classList.add('fileInfo');
        fileInfoCreated.textContent = `${item.created_at}`;

        const fileInfoUser = document.createElement('div');
        fileInfoUser.classList.add('fileInfo');
        fileInfoUser.textContent = `${item.last_modified_by}`;

        const fileInfoSize = document.createElement('div');
        fileInfoSize.classList.add('fileInfo');
        fileInfoSize.textContent = formatFileSize(item.size);

        // Create buttons for actions (delete, open/download)
        const deleteButton = document.createElement('div');
        deleteButton.classList.add('fileButton', 'deleteButton');
        deleteButton.innerHTML = '<i class="fa fa-trash"></i>'; // Use Font Awesome icon
        deleteButton.addEventListener('click', () => deleteFile(item.name)); // Set event handler for deleting

        let actionButton = document.createElement('div');
        actionButton.classList.add('fileButton', 'actionButton');
        // Determine the action button based on whether the item is a folder or file
        if (item.is_folder) {
            actionButton.innerHTML = '<i class="fa fa-folder"></i>'; // Icon for folder
            actionButton.addEventListener('click', () => openFolder(item.name)); // Event handler to open folder
        } else {
            actionButton.innerHTML = '<i class="fa fa-download"></i>'; // Icon for download
            actionButton.addEventListener('click', () => downloadFile(item.name)); // Event handler to download file
        }

        const moreButton = document.createElement('div');
        moreButton.classList.add('fileButton', 'moreButton');
        moreButton.innerHTML = '<i class="fa fa-ellipsis-v"></i>'; // Icon for more options
        moreButton.addEventListener('click', () => showMoreMenu(item)); // Event handler to show more options

        // Append elements to the list item and then to the file list
        listItem.appendChild(fileInfoName);
        listItem.appendChild(fileInfoCreated);
        listItem.appendChild(fileInfoUser);
        listItem.appendChild(fileInfoSize);
        listItem.appendChild(deleteButton);
        listItem.appendChild(actionButton);
        listItem.appendChild(moreButton);
        fileList.appendChild(listItem);
    });
}

// Function to show a detailed menu for an item
function showMoreMenu(item) {
    // Activate the overlay
    var overlay = document.getElementById("overlay");
    overlay.style.display = 'block';

    // Create the menu container
    const menu = document.getElementById("moreMenu");
    menu.style.display = 'block';
    // Make the menu appear from the bottom
    menu.style.bottom = '0';

    // Create a details button with item information
    const detailsButton = document.createElement('button');
    detailsButton.innerHTML = `Created on ${item.created_at}<br>by: ${item.last_modified_by}<br>size: ${formatFileSize(item.size)}`;
    detailsButton.classList.add('menuButton');

    // Create a download button
    const downloadButton = document.createElement('button');
    downloadButton.textContent = 'Download';
    downloadButton.classList.add('menuButton');
    downloadButton.onclick = function () { downloadFile(item.name); };

    // Create a delete button
    const deleteButton = document.createElement('button');
    deleteButton.textContent = 'Delete';
    deleteButton.classList.add('menuButton');
    deleteButton.onclick = function () { deleteFile(item.name); };

    // Create horizontal rules as dividers
    const hr1 = document.createElement('hr');
    const hr2 = document.createElement('hr');

    // Append the buttons and dividers to the menu
    menu.appendChild(detailsButton);
    menu.appendChild(hr1);
    menu.appendChild(downloadButton);
    menu.appendChild(hr2);
    menu.appendChild(deleteButton);

    // Add the menu to the body of the document
    document.body.appendChild(menu);

    // Set up the overlay click to close the menu
    overlay.addEventListener("click", closeMoreMenu);
}

// Function to close the detailed menu
function closeMoreMenu() {
    var overlay = document.getElementById("overlay");
    var menu = document.getElementById("moreMenu");
    // Hide the menu and move it downward
    menu.style.display = 'none';
    menu.style.bottom = '-100%';
    // Remove all buttons from the menu
    while (menu.firstChild) {
        menu.removeChild(menu.firstChild);
    }

    // Hide the overlay and remove the event listener for closing the menu
    overlay.style.display = 'none';
    overlay.removeEventListener("click", closeMoreMenu);
}

// Function to open a folder
async function openFolder(folder) {
    try {
        // Update the file path in localStorage
        if (localStorage.getItem('filepath') == '') {
            localStorage.setItem('filepath', localStorage.getItem('filepath') + `${folder}`);
        } else {
            localStorage.setItem('filepath', localStorage.getItem('filepath') + `/${folder}`);
        }
        // Reload the group files after updating the path
        loadGroupFiles();
    } catch (error) {
        console.error('Error during folder opening:', error); // Log any errors
    }
}

// Function to delete a file
async function deleteFile(filename) {
    // Retrieve the authentication token
    const token = getCookie('token');
    const folder = localStorage.getItem('filepath');

    // Construct the URL for the delete request
    const url = `${protocol}//${serverIP}:${serverPort}/delete_file`;

    // Prepare the request body with the filename, folder, and group
    const requestBody = {
        filename: filename,
        folder: folder,
        group: localStorage.getItem('group')
    };

    try {
        // Send a POST request to the server to delete the file
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify(requestBody),
        });

        // Check for successful response
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        const data = await response.json();

        // Handle the response after deletion
        if (data.success) {
            loadGroupFiles(); // Reload the files list
        } else {
            alert('Error while deleting'); // Show error message
            console.error(data.message);
        }
    } catch (error) {
        console.error('Error during fetch:', error); // Log any fetch errors
    }
}

// Function to download a file
async function downloadFile(filename) {
    // Retrieve the authentication token
    const token = getCookie('token');
    const folder = localStorage.getItem('filepath'); // Get the current folder from local storage

    const url = `${protocol}//${serverIP}:${serverPort}/download_file`; // Construct the URL for the download request

    const requestBody = {
        filename: filename,
        folder: folder,
        group: localStorage.getItem('group') // Get the current group ID from local storage
    };

    try {
        // Send a POST request to the server to initiate file download
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`, // Include the token in the request headers
            },
            body: JSON.stringify(requestBody),
        });

        // Check for a successful server response
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const blob = await response.blob(); // Get the blob data from the response
        let correctedFilename = filename;
        // Ensure the file has the correct extension (for example, '.jpg')
        if (!correctedFilename.endsWith('.jpg')) {
            correctedFilename += '.jpg';
        }

        // Create a temporary link element for downloading the file
        const downloadLink = document.createElement('a');
        downloadLink.href = window.URL.createObjectURL(blob); // Create a URL for the blob
        downloadLink.download = correctedFilename; // Set the download attribute with the filename
        document.body.appendChild(downloadLink);
        downloadLink.click(); // Programmatically click the link to start the download
        window.URL.revokeObjectURL(downloadLink.href); // Revoke the created URL to free resources

        // Remove the link element from the document
        document.body.removeChild(downloadLink);
    } catch (error) {
        console.error('Error during fetch:', error); // Log any errors to the console
    }
}

// Function to open the file selection dialog
function openFileSelection() {
    const fileInput = document.getElementById('fileInput'); // Get the file input element
    fileInput.click(); // Programmatically click the file input to open the file dialog
}

// Function to handle the file upload process
async function handleFileUpload() {
    // Retrieve the authentication token
    const token = getCookie('token');
    const folder = localStorage.getItem('filepath'); // Get the current folder from local storage
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0]; // Get the selected file

    // Check if a file is selected
    if (!file) {
        alert('Please choose a file'); // Alert if no file is selected
        return;
    }

    const url = `${protocol}//${serverIP}:${serverPort}/upload_file`; // Construct the URL for the upload request

    // Prepare the JSON body and append it to the FormData object
    const jsonBody = JSON.stringify({
        folder: folder,
        group: localStorage.getItem('group') // Get the current group ID from local storage
    });

    const formData = new FormData();
    formData.append('file', file); // Append the file to the FormData object
    formData.append('json', jsonBody); // Append the JSON data as a string

    try {
        // Send a POST request to the server to upload the file
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`, // Include the token in the request headers
            },
            body: formData, // Send the FormData object containing the file and JSON data
        });

        // Check for a successful server response
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const data = await response.json(); // Parse the JSON response

        // Check the response data for success or failure
        if (data.success) {
            loadGroupFiles(); // Reload the group files to reflect the uploaded file
        } else {
            alert('Error while uploading'); // Alert if the upload fails
            console.error(data.message); // Log the error message
        }
    } catch (error) {
        console.error('Error during fetch:', error); // Log any errors to the console
    }

    // Optionally reset the file input field to allow re-selection of the same file
    fileInput.value = null;
}