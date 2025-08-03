(function() {
    // Immediately sets the theme from the user's local storage to prevent flashing.
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.className = 'theme-' + savedTheme;
    } else {
        // Sets a default theme if no theme is saved in local storage.
        document.documentElement.className = 'theme-dark';
    }

    // After the page loads, it checks the server for the user's most recent theme settings.
    document.addEventListener('DOMContentLoaded', () => {
        fetch('/api/user', { credentials: 'include' })
            .then(response => {
                if (response.ok) {
                    return response.json();
                }
                return null; 
            })
            .then(user => {
                const serverTheme = user ? user.theme : 'dark';
                // Applies the theme from the server to keep it consistent across devices.
                document.documentElement.className = 'theme-' + serverTheme;
                
                // Updates the local storage if the server has a different theme.
                if (serverTheme !== savedTheme) {
                    localStorage.setItem('theme', serverTheme);
                }
            })
            .catch(error => {
                console.error('Failed to fetch updated theme:', error);
            });
    });
})();
