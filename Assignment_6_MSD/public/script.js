document.getElementById("register").addEventListener("submit", async (e) => {
    e.preventDefault();
    
    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;
    
    try {
        const response = await fetch("http://localhost:3000/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) throw new Error('Network response was not ok');

        const data = await response.json();
        alert(data.message);
    } catch (error) {
        console.error('Error:', error);
        alert(`An error occurred: ${error.message}`);
    }
});

document.getElementById("login").addEventListener("submit", async (e) => {
    e.preventDefault();
    
    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;
    
    try {
        const response = await fetch("http://localhost:3000/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) throw new Error('Network response was not ok');

        const data = await response.json();
        alert(data.message);
    } catch (error) {
        console.error('Error:', error);
        alert(`An error occurred: ${error.message}`);
    }
});

// New functionality for the Dashboard button
document.getElementById("dashboard-btn").addEventListener("click", async () => {
    try {
        const response = await fetch("http://localhost:3000/users");
        
        if (!response.ok) throw new Error('Network response was not ok');

        const users = await response.json();
        const userList = document.getElementById("userList");
        userList.innerHTML = ''; // Clear previous data

        // Display users in the modal
        users.forEach(user => {
            const listItem = document.createElement("li");
            listItem.textContent = `Username: ${user.username}`;
            userList.appendChild(listItem);
        });

        showCredentials(); // Show the modal with user credentials
    } catch (error) {
        console.error('Error fetching users:', error);
        alert(`An error occurred: ${error.message}`);
    }
});
