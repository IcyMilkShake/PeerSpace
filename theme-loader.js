(function() {
    // 1. Immediately apply theme from localStorage if it exists
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.className = 'theme-' + savedTheme;
    } else {
        // Fallback theme if nothing is in localStorage
        document.documentElement.className = 'theme-dark';
    }

    // 2. Asynchronously fetch the user's theme from the server to ensure it's up-to-date
    // This will correct the theme if it was changed on another device.
    document.addEventListener('DOMContentLoaded', () => {
        fetch('/api/user', { credentials: 'include' })
            .then(response => {
                if (response.ok) {
                    return response.json();
                }
                // Don't throw an error, just use the default if the user is not logged in.
                return null; 
            })
            .then(user => {
                const serverTheme = user ? user.theme : 'dark';
                // Apply the theme from the server
                document.documentElement.className = 'theme-' + serverTheme;
                
                // Update localStorage if it's different
                if (serverTheme !== savedTheme) {
                    localStorage.setItem('theme', serverTheme);
                }
            })
            .catch(error => {
                console.error('Failed to fetch updated theme:', error);
                // The page already has a theme, so we just log the error.
            });
    });
})();
