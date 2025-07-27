(async function() {
    try {
        const response = await fetch('/api/user', { credentials: 'include' });
        if (response.ok) {
            const user = await response.json();
            document.documentElement.className = 'theme-' + user.theme;
        } else {
            document.documentElement.className = 'theme-dark';
        }
    } catch (error) {
        console.error('Failed to load theme:', error);
        document.documentElement.className = 'theme-dark';
    }
})();
