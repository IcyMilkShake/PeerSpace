from playwright.sync_api import sync_playwright, expect

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    try:
        page.goto("http://localhost:8082")

        # Wait for the posts to load
        page.wait_for_selector("#posts-container .rounded-lg.shadow-md.p-6.hover-lift.fade-in.cursor-pointer", timeout=10000)

        # Expect at least one post to be visible
        expect(page.locator("#posts-container .rounded-lg.shadow-md.p-6.hover-lift.fade-in.cursor-pointer").first).to_be_visible()

        page.screenshot(path="jules-scratch/verification/verification.png")

    except Exception as e:
        print(f"An error occurred: {e}")
        page.screenshot(path="jules-scratch/verification/error.png")

    finally:
        browser.close()

with sync_playwright() as playwright:
    run(playwright)