const credentials = document.getElementById('credentials');
const privatePanel = document.getElementById('private');
const message = document.getElementById('message');
const localOnly = ['localhost','127.0.0.1'].includes(location.hostname);
async function loadProtected() {
    const profile = await apiRequest('/user/me');
    const favorites = await apiRequest('/favorites');
    document.getElementById('identity').textContent = `Signed in as ${profile.email || profile.user?.email || 'your account'}`;
    document.getElementById('records').textContent = `${(favorites.favorites || []).length} records returned for this user. Another user’s records are excluded by the API.`;
    credentials.hidden = true; privatePanel.hidden = false;
}
credentials.onsubmit = async event => {
    event.preventDefault();
    if (!localOnly) return;
    const buttons = [...credentials.querySelectorAll('button')]; buttons.forEach(b=>b.disabled=true);
    try {
        const fields = new FormData(credentials);
        const email = fields.get('email'); const password = fields.get('password');
        if (event.submitter?.value === 'register') {
            await register(email,password);
            message.textContent = 'Account created. In local development, verification instructions appear in the API terminal. You can now log in.';
        } else { await login(email,password,'Integration example'); await loadProtected(); message.textContent = 'Protected data loaded from the API.'; }
    } catch(error) { message.textContent = error.message; }
    finally { buttons.forEach(b=>b.disabled=false); }
};
document.getElementById('logout').onclick = async () => {
    try { await apiRequest('/auth/logout',{method:'POST',body:JSON.stringify({refreshToken:sessionStorage.getItem('refreshToken')})}); clearAuth(); privatePanel.hidden=true; credentials.hidden=false; message.textContent='Session revoked. You are logged out.'; }
    catch(error) { message.textContent=`Logout could not be confirmed: ${error.message}. Retry before leaving this device.`; }
};
if (!localOnly) { credentials.hidden=true; message.textContent='Run this integration locally. This public preview does not connect to an authentication service.'; }
else if (getAccessToken()) loadProtected().catch(()=>{clearAuth();message.textContent='Session expired. Log in again.';});
