// Wait for the DOM to be fully loaded before executing the code
document.addEventListener('DOMContentLoaded', () => {
    // Load all users and groups when the page is loaded
    loadAllUsers();
    loadAllGroups();

    // Add click event listeners to all elements with the class 'close'
    document.querySelectorAll('.close').forEach(closeButton => {
        closeButton.addEventListener('click', closeModal);
    });

    // Set the initial header title to 'Users' and configure UI elements
    const header = document.getElementById('header-titel');
    header.innerHTML = `Users`;
    var back = document.getElementById('back-button');
    var toggle = document.getElementById('view-toggle');
    back.style.display = 'none';
    toggle.style.display = 'block';

    // Set initial values in the local storage for view and group_id
    localStorage.setItem('view', 'user');
    localStorage.setItem('group_id', null);
});

// Function to close a modal by setting its display property to 'none'
function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

// Function to toggle between 'User' and 'Group' views
function toggleView() {
    var userList = document.getElementById('userList');
    var groupList = document.getElementById('groupList');
    var groupMemberList = document.getElementById('groupMemberList');
    var addLink = document.querySelector('.last-added'); // Select the last-added link

    // Check the current view and toggle between 'User' and 'Group' views
    if (userList.style.display === 'none') {
        userList.style.display = 'block';
        groupList.style.display = 'none';
        groupMemberList.style.display = 'none';

        // Change event listeners for the addLink
        addLink.removeEventListener("click", newGroup);
        addLink.addEventListener("click", newUser);

        // Update the view in local storage and header title
        localStorage.setItem('view', 'user');
        const header = document.getElementById('header-titel')
        header.innerHTML = `Users`;
    } else {
        userList.style.display = 'none';
        groupList.style.display = 'block';
        groupMemberList.style.display = 'none';

        // Change event listeners for the addLink
        addLink.removeEventListener("click", newUser);
        addLink.addEventListener("click", newGroup);

        // Update the view in local storage and header title
        localStorage.setItem('view', 'group');
        const header = document.getElementById('header-titel')
        header.innerHTML = `Groups`;
    }
}

// Function to navigate back to the previous page
function goBack() {
    // Get references to DOM elements
    var userList = document.getElementById('userList');
    var groupList = document.getElementById('groupList');
    var groupMemberList = document.getElementById('groupMemberList');

    // Hide user list, show group list, and update UI elements
    userList.style.display = 'none';
    groupList.style.display = 'block';
    groupMemberList.style.display = 'none';

    var back = document.getElementById('back-button');
    var toggle = document.getElementById('view-toggle');
    
    back.style.display = 'none'; // Hide back button
    toggle.style.display = 'block'; // Show view toggle button

    const header = document.getElementById('header-titel');
    header.innerHTML = `Groups`; // Update header title

    // Clear the stored group_id in local storage
    localStorage.setItem('group_id', null);
}

// Function to create a new user
function newUser() {
    const token = getCookie('token');
    var newUserModal = document.getElementById("newUserModal");

    newUserModal.onsubmit = function (event) {
        event.preventDefault();
        const username = document.getElementById('newUsername').value;
        const password = document.getElementById('newPassword').value;

        try {
            // Send a POST request to create a new user
            fetch(`${protocol}//${serverIP}:${serverPort}/create_user`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Reload the user list upon success
                        loadAllUsers();
                    } else {
                        alert(data.message); // Display a message whether successful or not
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                });
        } catch (error) {
            console.error('Error during fetch:', error);
            console.error('Server response:', error.response); // Log server response for debugging
        }
    };

    newUserModal.style.display = 'block'; // Display the modal for creating a new user
}

// Function to create a new group
function newGroup() {
    const token = getCookie('token');
    var newGroupName = document.getElementById("newGroupModal");

    newGroupName.onsubmit = function (event) {
        event.preventDefault();
        const group_name = document.getElementById('newGroupName').value;

        try {
            // Send a POST request to create a new group
            fetch(`${protocol}//${serverIP}:${serverPort}/create_group`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    group_name: group_name
                })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Reload the group list upon success
                        loadAllGroups();
                    } else {
                        alert(data.message); // Display a message whether successful or not
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                });
        } catch (error) {
            console.error('Error during fetch:', error);
            console.error('Server response:', error.response); // Log server response for debugging
        }
    };

    newGroupName.style.display = 'block'; // Display the modal for creating a new group
}

// Function to load and display all users from the server
function loadAllUsers() {
    // URL of the Python server that provides user data
    const url = `${protocol}//${serverIP}:${serverPort}/users`;

    // Reference to the container element for user list
    const userList = document.getElementById('userList');
    userList.innerHTML = ''; // Clear the previous content

    // Fetch request to the server to retrieve user data
    fetch(url)
        .then(response => response.json()) // Parse the response as JSON
        .then(users => {
            // Process each user in the received data
            users.forEach(user => {
                // Create a new div element for each user
                const userDiv = document.createElement('div');
                userDiv.className = 'user'; // Assign a CSS class to the user div
                userDiv.textContent = user.username; // Display the username (use 'username' instead of 'name')

                // Add a click event listener to each user div
                userDiv.addEventListener('click', function () {
                    // Check if the user menu is already loaded
                    if (!userDiv.querySelector('.user-menu')) {
                        // Load and append the user menu when clicked
                        const userMenu = createUserMenu(user);
                        userDiv.appendChild(userMenu); // Add the menu to the user div
                    }
                    toggleUserMenu(userDiv, user); // Toggle the user menu
                });

                userList.appendChild(userDiv); // Add the user div to the container
            });

            // Create a link to add a new user and append it to the user list
            const addLink = document.createElement("a");
            addLink.href = 'javascript:void(0)';
            addLink.textContent = '+';
            addLink.classList.add('last-added');
            addLink.addEventListener("click", () => {
                newUser(); // Call the newUser function when the link is clicked
            });
            userList.appendChild(addLink); // Add the link to the user list
        })
        .catch(error => {
            console.error('Error loading users:', error);
        });
}

// Function to fetch and process user rights
function fetchUserRights(username) {
    // Default rights that should always be displayed
    const standardRights = ['admin', 'owner'];
    return fetch(`${protocol}//${serverIP}:${serverPort}/user_rights/${username}`)
        .then(response => response.json())
        .then(userRights => {
            // Create an object to store the status of each right
            const rightsStatus = standardRights.reduce((acc, right) => {
                // Check if the right is present in the userRights array and set it accordingly in the checkbox
                acc[right] = userRights.some(userRight => userRight.right.toLowerCase() === right.toLowerCase());
                return acc;
            }, {});
            return rightsStatus;
        });
}

// Function to fetch and process group-specific user rights
function fetchGroupUserRights(username) {
    // Group-specific rights to be checked
    const groupSpecificRights = ['read', 'write', 'local_admin'];

    // Construct the URL for the request
    const url = `${protocol}//${serverIP}:${serverPort}/user_group_rights`;

    return fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: username,
            group_id: localStorage.getItem('group_id')
        })
    })
        .then(response => response.json())
        .then(userGroupRights => {
            // Create an object to store the status of each group right
            const rightsStatus = groupSpecificRights.reduce((acc, right) => {
                // Check if the right is present in the userGroupRights array and set it accordingly in the checkbox
                acc[right] = userGroupRights.some(userRight => userRight.right.toLowerCase() === right.toLowerCase());
                return acc;
            }, {});
            return rightsStatus;
        });
}

// Function to fetch user groups
function fetchUserGroups(username) {
    return fetch(`${protocol}//${serverIP}:${serverPort}/user_groups/${username}`)
        .then(response => response.json())
        .then(data => data.groups);
}

// Function to fetch available groups
function fetchGroups() {
    return fetch(`${protocol}//${serverIP}:${serverPort}/groups`)
        .then(response => response.json());
}

// Function to change user rights
function changeUserRights(username, newRights) {
    // Get the user's authentication token from a cookie
    const token = getCookie('token');

    // Send a POST request to the server to change user rights
    fetch(`${protocol}//${serverIP}:${serverPort}/change_user_rights`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            username: username,
            new_rights: newRights
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // If the operation was successful, reload user rights to reflect changes
                fetchUserRights(username);
            } else {
                alert(data.message); // Display a message whether the operation was successful or not
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
}

// Function to change group-specific user rights
function changeGroupUserRights(username, group, newRights) {
    // Get the user's authentication token from a cookie
    const token = getCookie('token');

    // Send a POST request to the server to change group-specific user rights
    fetch(`${protocol}//${serverIP}:${serverPort}/change_group_rights`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            username: username,
            group_id: group,
            new_rights: newRights
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // If the operation was successful, reload the user menu to reflect changes
                createUserMenu(username);
            } else {
                if (data.message) {
                    alert(data.message); // Display a message whether the operation was successful or not
                } else {
                    alert("An unexpected error occurred. Please try logging in again.");
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
}

// Function to change user groups
function changeUserGroups(username, newGroups) {
    // Get the user's authentication token from a cookie
    const token = getCookie('token');

    // Send a POST request to the server to change user groups
    fetch(`${protocol}//${serverIP}:${serverPort}/change_user_groups`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            username: username,
            new_groups: newGroups
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // If the operation was successful, reload the user menu to reflect changes
                createUserMenu(username);
            } else {
                alert(data.message); // Display a message whether the operation was successful or not
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
}


// Function to change the username for a user
function changeUsername(oldUsername) {
    // Get the user's authentication token from a cookie
    const token = getCookie('token');

    // Prompt the user to enter a new username
    const newUsername = prompt('Enter the new username:', oldUsername);

    // Send a POST request to the server to change the username
    fetch(`${protocol}//${serverIP}:${serverPort}/change_username`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            username: oldUsername,
            new_username: newUsername
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // If the operation was successful, reload either user list or group members based on the view
                if (localStorage.getItem('view') == 'user') {
                    loadAllUsers();
                } else {
                    loadGroupMembers(localStorage.getItem('view'));
                }
            } else {
                alert(data.message); // Display a message whether the operation was successful or not
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
}

// Function to change the password for a user
function changePassword(username) {
    // Get the user's authentication token from a cookie
    const token = getCookie('token');

    // Prompt the user to enter a new password
    const newPassword = prompt('Enter the new password:', '');

    // Send a POST request to the server to change the password
    fetch(`${protocol}//${serverIP}:${serverPort}/change_password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            username: username,
            new_password: newPassword
        })
    })
        .then(response => response.json())
        .then(data => {
            alert(data.message); // Display a message whether the operation was successful or not
        })
        .catch(error => {
            console.error('Error:', error);
        });
}


// Function to create a user menu for a given user
function createUserMenu(user) {
    // Create a new div element for the user menu
    const userMenu = document.createElement('div');
    userMenu.className = 'user-menu';

    // Define the structure of the user menu using HTML
    userMenu.innerHTML = `
        <div class="menu-section rights">
            <strong>Rights:</strong>
        </div>
        <div class="menu-section groups"><strong>Groups:</strong></div>
        <div class="menu-section properties">
            <button id="changePassword">Change password</button>
            <button id="changeName">Change name</button>
        </div>
    `;

    // Fetch and display user rights in the user menu
    fetchUserRights(user.username).then(rightsStatus => {
        const rightsContainer = userMenu.querySelector('.rights');
        // Remove existing user rights to avoid duplicates
        removeRights(rightsContainer, 'user');

        // Iterate through user rights and create checkboxes
        Object.keys(rightsStatus).forEach(right => {
            const isChecked = rightsStatus[right] ? 'checked' : '';
            rightsContainer.innerHTML += `<label><input type="checkbox" data-type="user" value="${right}" ${isChecked}> ${right}</label>`;
        });
    });

    // Get the group ID from local storage
    const groupId = localStorage.getItem('group_id');

    // Fetch and display group-specific user rights if a group is selected
    if (groupId && groupId !== "null" && groupId !== "") {
        fetchGroupUserRights(user.username).then(rightsStatus => {
            const rightsContainer = userMenu.querySelector('.rights');
            // Remove existing group rights to avoid duplicates
            removeRights(rightsContainer, 'group');

            // Iterate through group rights and create checkboxes
            Object.keys(rightsStatus).forEach(right => {
                const isChecked = rightsStatus[right] ? 'checked' : '';
                rightsContainer.innerHTML += `<label><input type="checkbox" data-type="group" value="${right}" ${isChecked}> ${right}</label>`;
            });
        });
    }

    // Function to add change event listeners to checkboxes
    function addCheckboxListeners(container, username, groupId = null) {
        container.addEventListener('change', event => {
            if (event.target.type === 'checkbox') {
                const rightType = event.target.dataset.type;
                const newRights = Array.from(container.querySelectorAll(`input[type="checkbox"][data-type="${rightType}"]:checked`)).map(box => box.value);

                if (rightType === 'group') {
                    // Change group-specific user rights when checkboxes are changed
                    changeGroupUserRights(username, groupId, newRights);
                } else {
                    // Change user rights when checkboxes are changed
                    changeUserRights(username, newRights);
                }
            }
        });
    }

    // Function to remove existing rights checkboxes
    function removeRights(container, type) {
        Array.from(container.querySelectorAll(`input[data-type="${type}"]`)).forEach(element => {
            element.parentElement.remove();
        });
    }

    // Add change event listeners to rights checkboxes
    const rightsContainer = userMenu.querySelector('.rights');
    addCheckboxListeners(rightsContainer, user.username, localStorage.getItem('group_id'));

    // Fetch and display user groups in the user menu
    fetchGroups().then(allGroups => {
        fetchUserGroups(user.username).then(userGroups => {
            const groupsContainer = userMenu.querySelector('.groups');
            allGroups.forEach(group => {
                const isChecked = userGroups.some(userGroup => userGroup.group_id === group.group_id);
                groupsContainer.innerHTML += `<label><input type="checkbox" data-group-id="${group.group_id}" ${isChecked ? 'checked' : ''}> ${group.group_name}</label>`;
            });

            // Add change event listener to group checkboxes
            const groupCheckboxes = document.querySelectorAll('.groups input[type="checkbox"]');
            groupCheckboxes.forEach((checkbox) => {
                checkbox.addEventListener('change', () => {
                    const newGroups = [];
                    document.querySelectorAll('.groups input[type="checkbox"]:checked').forEach((box) => {
                        newGroups.push(box.getAttribute('data-group-id'));
                    });

                    // Change user groups when group checkboxes are changed
                    changeUserGroups(user.username, newGroups);
                });
            });
        });
    });

    // Prevent clicks inside the user menu from closing the menu
    userMenu.addEventListener('click', function (event) {
        event.stopPropagation();
    });

    // Add click event listeners to change username and change password buttons
    const changeNameButton = userMenu.querySelector('#changeName');
    changeNameButton.addEventListener('click', () => changeUsername(user.username));

    const changePasswordButton = userMenu.querySelector('#changePassword');
    changePasswordButton.addEventListener('click', () => changePassword(user.username));

    // Return the created user menu
    return userMenu;
}


// Function to load and display members of a specific group
function loadGroupMembers(group_name) {
    // Construct the URL of the Python server that provides group member data
    const url = `${protocol}//${serverIP}:${serverPort}/group_members`;

    // Get the header element for displaying the group name
    const header = document.getElementById('header-titel');
    header.innerHTML = `${group_name}`;

    // Reference to the container element for displaying group members
    const userList = document.getElementById('groupMemberList');
    userList.innerHTML = '';

    // Send a POST request to the server to fetch group members
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${getCookie('token')}` // Ensure the correct way to retrieve the token
        },
        body: JSON.stringify({
            group_name: group_name
        })
    })
        .then(response => response.json()) // Parse the response as JSON
        .then(users => {
            // Process each group member
            users.forEach(user => {
                const userDiv = document.createElement('div');
                userDiv.className = 'user';
                userDiv.textContent = user.username; // Use 'username' instead of 'name'

                userDiv.addEventListener('click', function () {
                    // Check if the menu is already loaded
                    if (!userDiv.querySelector('.user-menu')) {
                        // Load and add the menu when a user is clicked
                        const userMenu = createUserMenu(user);
                        userDiv.appendChild(userMenu); // Add the menu to the user's div
                    }
                    toggleUserMenu(userDiv, user);
                });

                userList.appendChild(userDiv); // Add the user's div to the container
            });
        })
        .catch(error => {
            console.error('Error loading group members:', error);
        });
}

// Function to load and display all groups
function loadAllGroups() {
    // Construct the URL of the Python server that provides group data
    const url = `${protocol}//${serverIP}:${serverPort}/groups`;

    // Reference to the container element for displaying groups
    const groupList = document.getElementById('groupList');
    groupList.innerHTML = '';

    // Send a GET request to the server to fetch groups
    fetch(url)
        .then(response => response.json()) // Parse the response as JSON
        .then(groups => {
            // Process each group
            groups.forEach(group => {
                const groupDiv = document.createElement('div');
                groupDiv.className = 'group';
                groupDiv.textContent = group.group_name;

                groupDiv.addEventListener('click', function () {
                    // Check if the menu is already loaded
                    var userList = document.getElementById('userList');
                    var groupList = document.getElementById('groupList');
                    var groupMemberList = document.getElementById('groupMemberList');
                    userList.style.display = 'none';
                    groupList.style.display = 'none';
                    groupMemberList.style.display = 'block';

                    var back = document.getElementById('back-button');
                    var toggle = document.getElementById('view-toggle');
                    back.style.display = 'block';
                    toggle.style.display = 'none';
                    localStorage.setItem('group_id', group.group_id);
                    localStorage.setItem('view', group.group_name);
                    loadGroupMembers(group.group_name);
                });

                groupList.appendChild(groupDiv); // Add the group div to the container
            });

            // Create a link to add a new group
            const addLink = document.createElement("a");
            addLink.href = 'javascript:void(0)';
            addLink.textContent = '+';
            addLink.classList.add('last-added');
            addLink.addEventListener("click", () => {
                newGroup();
            });
            groupList.appendChild(addLink);
        })
        .catch(error => {
            console.error('Error loading groups:', error);
        });
}

// Function to toggle the visibility of user menus
function toggleUserMenu(userDiv, user) {
    const userMenu = userDiv.querySelector('.user-menu');
    const isVisible = userMenu.style.display === 'grid';
    
    // Hide all open menus
    document.querySelectorAll('.user .user-menu').forEach(menu => {
        menu.style.display = 'none';
    });
    
    // Show the menu of the clicked user if it was not visible previously
    userMenu.style.display = isVisible ? 'none' : 'grid';
}
