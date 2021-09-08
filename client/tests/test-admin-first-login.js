describe("admin login", function() {
  it("should login as admin", async function() {
    await browser.gl.utils.login_admin();
  });

  it("should be retrieve the account recovery key", async function() {
    await element(by.id("PreferencesLink")).click();
    await browser.gl.utils.waitForUrl("/admin/preferences");
    await element(by.cssContainingText("button", "Account recovery key")).click();
    await element(by.cssContainingText("button", "Close")).click();
  });
});
