// Helper function to award credibility points
async function awardCredibility(user, points, comment = null) {
    const threeDaysAgo = new Date();
    threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);

    if (user.createdAt > threeDaysAgo || !user.emailVerified) {
        return false; // Conditions not met
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const lastUpdated = new Date(user.dailyCredibility.lastUpdated);
    lastUpdated.setHours(0, 0, 0, 0);

    if (lastUpdated < today) {
        user.dailyCredibility.value = 0;
    }

    if (user.dailyCredibility.value >= 50) {
        return false; // Daily limit reached
    }

    const potentialGain = points;
    const gain = Math.min(potentialGain, 50 - user.dailyCredibility.value);

    if (gain > 0) {
        user.credibility += gain;
        user.dailyCredibility.value += gain;
        user.dailyCredibility.lastUpdated = new Date();

        if (comment && points === 1) { // Only for the 1-point like award
            comment.credibilityAwardedForLikes = true;
            await comment.save();
        }
        await user.save();
        return true; // Points awarded
    }
    return false; // No points awarded
}

// Helper function to revoke credibility points
async function revokeCredibility(user, points, comment = null) {
    user.credibility = Math.max(0, user.credibility - points);

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const lastUpdated = new Date(user.dailyCredibility.lastUpdated);
    lastUpdated.setHours(0, 0, 0, 0);

    if (lastUpdated.getTime() === today.getTime()) {
        user.dailyCredibility.value = Math.max(0, user.dailyCredibility.value - points);
    }

    if (comment && points === 1) {
        comment.credibilityAwardedForLikes = false;
        await comment.save();
    }
    await user.save();
}

module.exports = {
    awardCredibility,
    revokeCredibility,
};