async function fetchAdminUsers() {
    try {
        const response = await fetch('/admin/users/data');
        if (!response.ok) {
            throw new Error('Failed to refresh user list');
        }
        const payload = await response.json();
        const tbody = document.querySelector('#admin-user-table tbody');
        if (!tbody) return;
        tbody.innerHTML = '';
        payload.users.forEach(user => {
            const roleBadge = user.role === 'Admin'
                ? '<span style="background:linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color:#fff; padding:5px 12px; border-radius:8px; font-size:12px; font-weight:700;"><i class="fa-solid fa-user-shield"></i> Admin</span>'
                : '<span style="background:rgba(255,255,255,0.08); color:#94a3b8; padding:5px 12px; border-radius:8px; font-size:12px; font-weight:600; border:1px solid rgba(255,255,255,0.1);"><i class="fa-solid fa-user"></i> Standard User</span>';

            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${user.user_id}</td>
                <td>
                    <button onclick="viewUserScans(${user.user_id}, '${user.username}')" style="background:none; border:none; color:#0284c7; font-weight:700; cursor:pointer; text-decoration:underline; font-size:15px; font-family:inherit; padding:0;">
                        <i class="fa-solid fa-folder-open"></i> ${user.username}
                    </button>
                </td>
                <td>${user.email}</td>
                <td>${user.created_at}</td>
                <td>${user.scan_count}</td>
                <td>${roleBadge}</td>
            `;
            tbody.appendChild(row);
        });
    } catch (err) {
        console.error(err);
    }
}

const refreshButton = document.getElementById('refresh-users-btn');
if (refreshButton) {
    refreshButton.addEventListener('click', fetchAdminUsers);
}

setInterval(fetchAdminUsers, 15000);
window.addEventListener('load', fetchAdminUsers);
