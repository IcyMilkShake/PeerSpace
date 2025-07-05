function applyThemePreference() {
    const preferredTheme = localStorage.getItem('forumTheme') || 'dark'; // Default to dark
    document.documentElement.className = 'theme-' + preferredTheme;
}

applyThemePreference();
