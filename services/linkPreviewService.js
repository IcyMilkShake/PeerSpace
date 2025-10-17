const axios = require('axios');
const cheerio = require('cheerio');

// Generates a preview for the first link found in a piece of text.
async function generateLinkPreview(content) {
  const urlRegex = /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])|(\bwww\.[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
  const urls = content.match(urlRegex);

  if (urls && urls.length > 0) {
    try {
      let url = urls[0];
      if (!url.match(/^[a-zA-Z]+:\/\//)) {
        url = 'http://' + url;
      }

      const { data } = await axios.get(url, {
        timeout: 5000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
      });
      const $ = cheerio.load(data);

      const getMetaTag = (name) => {
        return (
          $(`meta[property="og:${name}"]`).attr('content') ||
          $(`meta[name="twitter:${name}"]`).attr('content') ||
          $(`meta[name="${name}"]`).attr('content')
        );
      };

      const title = getMetaTag('title') || $('title').first().text();
      const description = getMetaTag('description') || $('p').first().text();
      let image = getMetaTag('image');

      if (image && image.trim() && !image.startsWith('http')) {
        try {
            const urlObject = new URL(url);
            image = new URL(image, urlObject.origin).href;
        } catch (e) {
            console.error(`Invalid image URL found for ${url}: ${image}`);
            image = null;
        }
      }

      if (title || description) {
          return {
            url: url,
            title: title ? title.trim() : '',
            description: description ? description.trim().substring(0, 200) : '',
            image: image,
          };
      }
    } catch (previewError) {
      console.error(`Error generating link preview for ${url}:`, previewError.message);
    }
  }
  return null;
}

module.exports = {
    generateLinkPreview,
};