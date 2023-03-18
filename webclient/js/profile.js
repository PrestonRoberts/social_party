const userNameElement = document.getElementById('username');
const changeNameForm = document.getElementById('change-name-form');
const newNameInput = document.getElementById('new-name');

async function fetchUserProfile() {
    try {
        const response = await fetch('http://localhost:3000/user_profile', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + localStorage.getItem('userToken')
            }
        });

        if (!response.ok) {
            throw new Error('Error fetching user profile');
        }
        const data = await response.json();
        document.getElementById('username').textContent = data.username;
    } catch (error) {
        console.error('Error:', error);
    }
}

async function changeName() {
    // get form data
    const newUsername = document.getElementById("new-username").value.trim();

    console.log(newUsername);

    fetch('http://localhost:3000/change_username', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
            'userToken': localStorage.getItem('userToken'),
            'newUsername': newUsername
        }),
    }).then(response => {
        return response.json();
    }).then(data => {

        if(!data.success) {
            alert('Error updating username');
            return;
        }

        document.getElementById('username').textContent = newUsername;
        alert('Username updated successfully');
    })
}

fetchUserProfile();